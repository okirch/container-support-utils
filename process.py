#!/usr/bin/python2
#
#  Copyright (C) 2020 Olaf Kirch <okir@suse.de>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

import os

##################################################################
# The fd based access method for files in /proc/<pid> is
# designed to handle exiting processes more gracefully.
# However, currently we're on python2 (because python3-Twisted
# was still a bit flakey), so we cannot use these methods.
##################################################################
class ProcEntry(object):
	def __init__(self, path, fd = None):
		self.path = path
		self.fd = fd

	def __del__(self):
		self.close()

	def okayToOpenAt(self):
		if self.fd is None:
			return False

		# Detect if we're running on python3 and say yes in that case
		return False
		
	def _open(self):
		if self.fd is None:
			try:	self.fd = os.open(self.path, 0)
			except:	return False
		return True

	def close(self):
		if self.fd is not None:
			os.close(self.fd)
			self.fd = None

	def open(self, name, flags = os.O_RDONLY):
		if self.okayToOpenAt():
			# python3 only
			return os.open(name, flags, dir_fd = self.fd)

		return os.open(self.path + "/" + name, flags)

	def stat(self, name):
		if self.okayToOpenAt():
			# python3 only
			return os.stat(name, dir_fd = self.fd)

		return os.stat(self.path + "/" + name)

	def readlink(self, name):
		if self.okayToOpenAt():
			# python3 only
			return os.readlink(name, dir_fd = self.fd)

		return os.readlink(self.path + "/" + name)

	def rootInfo(self):
		try:
			st = self.stat("root")
		except:
			return ()
		return (st.st_dev, st.st_ino)

	def rootDir(self):
		return self.path + "/root/"

	def mntNS(self):
		for thread in os.listdir(self.path + "/task"):
			ns = self.readlink("task/%s/ns/mnt" % thread)
			if ns:
				return ns
		return None

	def executable(self):
		try:
			return self.readlink("exe")
		except:
			return None

	def commandline(self):
		raw = open(self.path + "/cmdline", "r").read()
		return raw.strip("\0").split("\0")

	def json(self):
		result = {
			'pid':		self.pid,
			'executable':	self.executable(),
			'cmdline':	self.commandline(),
		}
		return result

class ProcSelf(ProcEntry):
	def __init__(self):
		super(ProcSelf, self).__init__("/proc/self")

class Process(ProcEntry):
	def __init__(self, pid, fd = None):
		super(Process, self).__init__("/proc/%d" % pid, fd)
		self.pid = pid

class Container:
	def __init__(self, proc):
		self.processes = [proc]
		self.pid = proc.pid

		path = "%s/root/etc/HOSTNAME" % proc.path 

		try:
			self.hostname = str(open(path, "r").read()).strip()
		except:
			self.hostname = None

	def root(self):
		return proc.path + "/root/"

	def addProcess(self, p):
		self.processes.append(p)

	def executable(self):
		for p in self.processes:
			r = p.executable()
			if r is not None:
				return r
		return None

	def rootDir(self):
		for p in self.processes:
			if p.rootInfo():
				return p.rootDir()
		return None

class ProcFS:
	def processes(self):
		result = []
		for name in os.listdir("/proc"):
			try:
				pid = int(name)
			except:
				continue

			proc = Process(pid)
			result.append(proc)

		return result

	def containers(self, excludingSelf = False):
		selfProc = ProcSelf()
		myRoot = selfProc.rootInfo()

		# rtkit-daemon does a chroot("/proc").
		# Note that this is probably only ever a problem when
		# we run this code on the host side (eg for testing).
		st = os.stat("/proc")
		procInfo = (st.st_dev, st.st_ino)

		containers = []
		containerDict = dict()
		for proc in self.processes():
			if not proc.executable():
				# print "pid %d has no executable" % proc.pid
				continue

			# Chromium is doing some weird stuff with its root.
			rootInfo = proc.rootInfo()
			nsInfo = proc.mntNS()

			# Catch rtkit-daemon and pretend it uses the same root as
			# we do.
			if rootInfo == procInfo:
				rootInfo = myRoot

			con = containerDict.get(rootInfo)
			if con is None:
				con = containerDict.get(nsInfo)

			if con is None:
				con = Container(proc)
				containerDict[rootInfo] = con
				containerDict[nsInfo] = con
				if not excludingSelf or rootInfo != myRoot:
					containers.append(con)
			else:
				con.addProcess(proc)

			if rootInfo == myRoot:
				myContainer = con

		return containers

if __name__ == '__main__':
	procFS = ProcFS()
	print("%5s %-30s %s" % ("PID", "EXECUTABLE", "HOSTNAME"))
	for con in procFS.containers(excludingSelf = True):
		print("%5u %-30s %s" % (con.pid, con.executable(), con.hostname))
		print("%36s root=%s" % ("", con.rootDir()))
		for p in con.processes:
			print("%36s %5d %s" % ("", p.pid, p.executable()))

