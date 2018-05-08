#!/bin/sh
set -ex
if test ${TRAVIS_OS_NAME} = "linux"; then
	sudo apt-get -qq update
	sudo apt-get -y install libafflib-dev libewf-dev libpq-dev libsqlite3-dev ant libcppunit-dev
elif test ${TRAVIS_OS_NAME} = "osx"; then
	brew install ant	
fi
./bootstrap && ./configure --prefix=/usr && make > /dev/null
cd bindings/java/ && ant dist-PostgreSQL
