#!/bin/sh
set -ex
installLib() {
	git clone https://github.com/libyal/$1
	cd $1
	./synclibs.sh
	./autogen.sh
	./configure && make > /dev/null && sudo make install > /dev/null
	cd ..
}

if test ${TRAVIS_OS_NAME} = "linux"; then
	sudo apt-get -qq update
	sudo apt-get -y install libafflib-dev libewf-dev libpq-dev autopoint libsqlite3-dev ant libcppunit-dev
elif test ${TRAVIS_OS_NAME} = "osx"; then
	export PATH=${PATH}:/usr/local/opt/gettext/bin
	brew install ant libewf gettext
fi
installLib libvhdi
installLib libvmdk
./bootstrap && ./configure --prefix=/usr && make > /dev/null
cd bindings/java/ && ant dist-PostgreSQL
