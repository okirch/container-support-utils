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

import rpm
import json
import datetime

class RpmPackage:
	def __init__(self, fd):
		self.fd = fd

	def header(self):
		self.fd.seek(0)

		ts = rpm.TransactionSet()
		return ts.hdrFromFdno(self.fd)

class RpmDB:
	def __init__(self, rootdir = "/"):
		self._root = rootdir

	@staticmethod
	def headerToJson(h):
		# f = lambda s : str(s, 'utf-8')
		f = lambda s : unicode(s)
		jh = {
			'name':		f(h.N),
			'version':	f(h.V),
			'release':	f(h.R),
		}
		if h.E:
			jh['epoch'] = f(h.E)

		when = h.installtime
		if when:
			dt = datetime.datetime.utcfromtimestamp(when)
			dt = dt.replace(microsecond = 0)
			jh['installdate'] = dt.isoformat()

		return jh

	def query(self):
		ts = rpm.TransactionSet(self._root, 0)
		ts.openDB()

		result = []
		for h in ts.dbMatch():
			jh = RpmDB.headerToJson(h)
			result.append(jh)

		return result

	@staticmethod
	def runCallback(reason, amount, total, key, client_data):
		print "runCallback(%s, %s, %s, %s, %s)" % (reason, amount, total, key, client_data)
		if reason == rpm.RPMCALLBACK_INST_OPEN_FILE:
			pkg = key
			pkg.fd.seek(0)
			return pkg.fd.fileno()

		if reason == rpm.RPMCALLBACK_INST_CLOSE_FILE:
			# NOP
			return

	def transactionStatus(self, status, hdr):
		return {
			'status'	: status,
			'package'	: RpmDB.headerToJson(hdr)
		}

	def install(self, fd):
		ts = rpm.TransactionSet(self._root, rpm._RPMVSF_NOSIGNATURES)
		ts.openDB()

		pkg = RpmPackage(fd)
		h = pkg.header()

		action = 'i'
		for found in ts.dbMatch('name', h.name):
			if found.NEVR == h.NEVR:
				return self.transactionStatus('already-installed', found)
			action = 'u'

		ts.addInstall(h, pkg, action)

		# The check() method rarely provides useful information
		# Print the result for logging reasons, though
		print "check: ", ts.check()

		problems = ts.run(RpmDB.runCallback, "nothing")
		print "problems: ", problems

		if problems is None:
			if action == 'i':
				status = 'installed'
			else:
				status = 'updated'

			for found in ts.dbMatch('name', h.name):
				if found.NEVR == h.NEVR:
					h = found
			return self.transactionStatus(status, h)

		return {
			'status'	: 'failed',
			'problems'	: problems
		}

	def uninstall(self, name):
		ts = rpm.TransactionSet(self._root, 0)
		ts.openDB()

		found = ts.dbMatch('name', name)
		if not found:
			return self.transactionStatus('not-installed')
		for h in found:
			ts.addErase(h)

		# The check() method rarely provides useful information
		# Print the result for logging reasons, though
		print "check: ", ts.check()

		problems = ts.run(RpmDB.runCallback, "nothing")
		print "problems: ", problems

		if problems is None:
			return self.transactionStatus('erased', h)

		return {
			'status'	: 'failed',
			'problems'	: problems
		}

