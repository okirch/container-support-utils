#!/usr/bin/python2

import sys

from zope.interface import implementer

from twisted.python import log
from twisted.internet import reactor
from twisted.web import server, resource, guard
from twisted.web.resource import NoResource
from twisted.cred.portal import IRealm, Portal
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse

import rpms

##################################################################
# /rpms
#  GET	returns the list of installed packages
#  PUT	install/update a package. The binary package needs to
#	be supplied as content to the request.
##################################################################
class RpmDbResource(resource.Resource):
	def __init__(self):
		resource.Resource.__init__(self)
		self.db = rpms.RpmDB()

		# Setting isLead to True causes a "DELETE /rpms/blubber" to
		# invoke our render_DELETE() method with a postpath of
		# "blubber"
		self.isLeaf = True

	def jsonResponse(self, request, reply):
		import json

		request.responseHeaders.addRawHeader(b"content-type", b"application/json")
		return json.dumps(reply) + "\n"

	def render_GET(self, request):
		if len(request.postpath) != 0:
			raise ValueError("Bad path")
		return self.jsonResponse(request, self.db.query())

	def render_PUT(self, request):
		if len(request.postpath) != 0:
			raise ValueError("Bad path")
		return self.jsonResponse(request, self.db.install(request.content))

	def render_DELETE(self, request):
		if len(request.postpath) != 1:
			# I'm sure there's a cleaner way to do this
			raise ValueError("Bad path")
		pkgName = request.postpath[0]

		return self.jsonResponse(request, self.db.uninstall(pkgName))

##################################################################
# The / of the support sidecar http server
##################################################################
class SupportService(resource.Resource):
	def __init__(self):
		resource.Resource.__init__(self)
		self.putChild("rpms", RpmDbResource())

	def getChild(self, path, request):
		return self

	def render(self, request):
		return "General information should go here"

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
