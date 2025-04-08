.ONESHELL:
build_deb:
	export USER=ubuntu
	export EMAIL=info@sleuthkit.org
	cd ..
	/bin/rm configure
	echo First pass on bootstrap so we can distclean
	bash bootstrap
	./configure --enable-java
	make distclean
	rm -rf autom4te.cache config.log config.status 
	echo Second pass on bootstrap so we can build
	bash bootstrap
	./configure --enable-java
	make -j4
	debuild -us -uc 

