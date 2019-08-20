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
#	sudo apt-get -qq update
#	sudo apt-get -y install libafflib-dev libewf-dev libpq-dev autopoint libsqlite3-dev ant libcppunit-dev wget

#	sudo apt-get -y install openjdk-8-jdk openjfx=8u161-b12-1ubuntu2 libopenjfx-java=8u161-b12-1ubuntu2 libopenjfx-jni=8u161-b12-1ubuntu2

#	sudo update-alternatives --set java /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java
#	sudo update-alternatives --set javac /usr/lib/jvm/java-8-openjdk-amd64/bin/javac
#	export PATH=/usr/bin:$PATH
#	unset JAVA_HOME

elif test ${TRAVIS_OS_NAME} = "osx"; then
	export PATH=${PATH}:/usr/local/opt/gettext/bin
	brew install ant libewf gettext cppunit afflib
fi

# Step 1: Install and build libvhdi
installLib libvhdi 20181227
# Step 2: Install and build libvmdk
installLib libvmdk 20181227

java -version
javac -version

# Step 3: Build TSK
./bootstrap && ./configure --prefix=/usr && make

# Step 4: Build the Java bindings
cd bindings/java/ && ant -q dist-PostgreSQL

# Step 5: Test the release script on Linux.
if test ${TRAVIS_OS_NAME} = "linux"; then
	cd ../../release; ./release-unix.pl ci;
fi
