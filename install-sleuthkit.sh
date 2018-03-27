#!/bin/sh
set -ex
if test ${TRAVIS_OS_NAME} = "linux"; then
	sudo apt-get -qq update
	sudo apt-get -y install libafflib-dev libewf-dev libpq-dev postgresql-9.5 libvhdi-dev libvmdk-dev libsqlite3-dev testdisk ant libcppunit-dev	
fi
#if test ${TRAVIS_REPO_SLUG} = "sleuthkit/autopsy"; then
#	git clone https://github.com/sleuthkit/sleuthkit
#	cd sleuthkit
#fi
./bootstrap && ./configure --prefix=/usr && make
#cd /usr/share/java && sudo ln -s sleuthkit-4.6.0.jar sleuthkit-postgresql-4.6.0.jar
 
