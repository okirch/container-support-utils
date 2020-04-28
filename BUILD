#!/bin/bash

RUNTIME_REQS="
	python2-Twisted
	python2-service_identity
	python2-rpm
"
INSTALL_REQS="
	tar
"

set -x
set -e

TARBALL=installed.tar
IMAGE=sidecar.tar

mkdir -p instroot
make DESTDIR=$PWD/instroot install
tar -C instroot -cf $TARBALL .
rm -rf instroot

id=$(buildah from opensuse/leap)

buildah run $id -- zypper in --no-confirm $RUNTIME_REQS $INSTALL_REQS
buildah copy $id $TARBALL /tmp/$TARBALL
buildah run $id tar -C / -xvf /tmp/$TARBALL
buildah run $id rm -f /tmp/$TARBALL
buildah config --entrypoint /usr/bin/suse-sidecar $id
buildah config --port 8889 $id

buildah commit $id opensuse/sidecar
buildah push opensuse/sidecar oci-archive:$IMAGE

rm -f $TARBALL
