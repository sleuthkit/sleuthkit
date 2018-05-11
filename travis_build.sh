#!/bin/sh
set -ex
installLib() {
	git clone https://github.com/sleuthkit/$1
	if [ "$1" == "libvmdk_64bit" ];then
		cd $1/libvmdk
	else
		cd $1
	fi
	# use prefix=/usr in linux to prevent clang shared libraries not found error
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
	sudo apt-get -y install libafflib-dev libewf-dev libpq-dev autopoint libsqlite3-dev ant libcppunit-dev
elif test ${TRAVIS_OS_NAME} = "osx"; then
	export PATH=${PATH}:/usr/local/opt/gettext/bin
	brew install ant libewf gettext
fi
installLib libvhdi_64bit
installLib libvmdk_64bit
./bootstrap && ./configure --prefix=/usr && make > /dev/null
cd bindings/java/ && ant -q dist-PostgreSQL
