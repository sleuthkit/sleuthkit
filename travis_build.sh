#!/bin/sh
set -ex
installLib() {
	wget https://github.com/libyal/$1/releases/download/$2/$1-alpha-$2.tar.gz
	tar -xzf $1-alpha-$2.tar.gz
	cd $1-$2
	if test ${TRAVIS_OS_NAME} = "linux"; then
		./configure -prefix=/usr > /dev/null
	else
		./configure > /dev/null
	fi
	make > /dev/null && sudo make install > /dev/null
	cd ..
}

if test ${TRAVIS_OS_NAME} = "linux"; then
	sudo apt-get -qq update
	sudo apt-get -y install libafflib-dev libewf-dev libpq-dev autopoint libsqlite3-dev ant libcppunit-dev wget
elif test ${TRAVIS_OS_NAME} = "osx"; then
	export PATH=${PATH}:/usr/local/opt/gettext/bin
	brew install ant libewf gettext cppunit afflib
fi
installLib libvhdi 20181125
installLib libvmdk 20181124
./bootstrap && ./configure --prefix=/usr && make > /dev/null
cd bindings/java/ && ant -q dist-PostgreSQL
