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

installLib libvhdi 20201204
installLib libvmdk 20200926

