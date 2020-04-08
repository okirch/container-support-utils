#!/usr/bin/python2

import sys

from zope.interface import implementer

from twisted.python import log
from twisted.internet import reactor
from twisted.web import server, resource, guard, http
from twisted.web.resource import NoResource
from twisted.cred.portal import IRealm, Portal
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse

from suse_sidecar.rpms import RpmDB
from suse_sidecar.process import ProcFS

##################################################################
# This is a resource base class
# Its main purpose in life is providing a utility function
# for sending json responses
##################################################################
class JsonResource(resource.Resource):
	def jsonResponse(self, request, reply):
		import json

		request.responseHeaders.addRawHeader(b"content-type", b"application/json")
		return json.dumps(reply) + "\n"

	def errorPage(self, request, code, msg, detail):
		return resource.ErrorPage(code, msg, detail or msg).render(request)

	def errorBadRequest(self, request, msg, detail = None):
		return self.errorPage(request, http.BAD_REQUEST, msg, detail)

	def errorNotImplemented(self, request, msg, detail = None):
		return self.errorPage(request, http.NOT_IMPLEMENTED, msg, detail)

##################################################################
# /rpms
#  GET	returns the list of installed packages
#  PUT	install/update a package. The binary package needs to
#	be supplied as content to the request.
##################################################################
class RpmDbResource(JsonResource):
	def __init__(self, root = "/"):
		JsonResource.__init__(self)
		self.db = RpmDB(root)

		# Setting isLead to True causes a "DELETE /rpms/blubber" to
		# invoke our render_DELETE() method with a postpath of
		# "blubber"
		self.isLeaf = True

	def render_GET(self, request):
		if len(request.postpath) != 0:
			return self.errorBadRequest(request, "Bad path", "Extra path component after rpms/")
		return self.jsonResponse(request, self.db.query())

	def render_PUT(self, request):
		if len(request.postpath) != 0:
			return self.errorBadRequest(request, "Bad path", "Extra path component after rpms/")
		return self.jsonResponse(request, self.db.install(request.content))

	def render_DELETE(self, request):
		if len(request.postpath) != 1:
			return self.errorBadRequest(request, "Bad path", "The path must contain exactly one package name")

		pkgName = request.postpath[0]

		return self.jsonResponse(request, self.db.uninstall(pkgName))

##################################################################
# Service encapsulating a container's process listing
##################################################################
class ContainerProcessListService(JsonResource):
	def __init__(self, container):
		JsonResource.__init__(self)
		self.container = container

		self.isLeaf = True

	def render_GET(self, request):
		listing = []
		for p in self.container.processes:
			listing.append(p.json())
		return self.jsonResponse(request, listing)

	def render_DELETE(self, request):
		if len(request.postpath) != 1:
			return self.errorBadRequest(request, "Bad path", "The path must contain exactly one pid")

		pid = request.postpath[0]
		try:
			pid = int(pid)
		except:
			return self.errorBadRequest(request, "Not a valid pid")

		return self.errorNotImplemented(request, "Process kill not yet implemented")
		return self.jsonResponse(request, self.container.kill(pid))

##################################################################
# Service encapsulating a container
##################################################################
class ContainerService(JsonResource):
	def __init__(self, container):
		JsonResource.__init__(self)
		self.container = container

		print("container %s root %s" % (container.hostname, container.rootDir()))
		self.putChild("rpms", RpmDbResource(container.rootDir()))
		self.putChild("processes", ContainerProcessListService(container))

	def render_GET(self, request):
		return self.jsonResponse(request, ("rpms", "processes"))

##################################################################
# The / of the support sidecar http server
##################################################################
class SupportService(JsonResource):
	def __init__(self):
		JsonResource.__init__(self)
		self.procFS = ProcFS()

	def containers(self, excludingSelf = True):
		return self.procFS.containers(excludingSelf)

	def getChild(self, path, request):
		print("getChild(%s)" % path)
		if path == "":
			return self

		for con in self.containers():
			if con.hostname == path:
				return ContainerService(con)

		return resource.NoResource("Not a valid container hostname")

	def render(self, request):
		result = []
		for con in self.containers():
			result.append(con.hostname)
		return self.jsonResponse(request, result)

##################################################################
# AdministrativeRealm - linked to a set of credentials
# using the Portal class
##################################################################
@implementer(IRealm)
class AdministrativeRealm(object):
	def requestAvatar(self, avatarId, mind, *interfaces):
		if resource.IResource in interfaces:
			return resource.IResource, SupportService(), lambda: None
		raise NotImplementedError()



def main():
	log.startLogging(sys.stdout)

	# TBD: get the admin password from an environment variable

	credCheckers = [InMemoryUsernamePasswordDatabaseDontUse(admin='secret')]

	wrapper = guard.HTTPAuthSessionWrapper(
		Portal(AdministrativeRealm(), credCheckers),
		[guard.DigestCredentialFactory('md5', 'suse.com')])

	reactor.listenTCP(8889, server.Site(resource = wrapper))
	reactor.run()

if __name__ == '__main__':
	main()
