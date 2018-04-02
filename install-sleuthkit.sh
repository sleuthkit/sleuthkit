#!/bin/sh
set -ex
if test ${TRAVIS_OS_NAME} = "linux"; then
	sudo apt-get -qq update
	sudo apt-get -y install libafflib-dev libewf-dev libpq-dev libsqlite3-dev ant libcppunit-dev	
fi
./bootstrap && ./configure --prefix=/usr && make
cd bindings/java/ && ant dist-PostgreSQL
