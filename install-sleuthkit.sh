#!/bin/sh
set -ex
if test ${TRAVIS_OS_NAME} = "linux"; then
	sudo apt-get -qq update
	sudo apt-get -y install libafflib-dev libewf-dev libpq-dev libsqlite3-dev testdisk ant libcppunit-dev	
fi
./bootstrap && ./configure --prefix=/usr && make
if test ${TRAVIS_REPO_SLUG} = "sleuthkit/autopsy"; then
	cd bindings/java/dist
	ln -s sleuthkit-4.6.0.jar sleuthkit-postgresql-4.6.0.jar
fi
 
