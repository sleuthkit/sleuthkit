.ONESHELL:
build_deb:
	export USER=ubuntu
	export EMAIL=info@sleuthkit.org
	cd ..
	/bin/rm configure
	bash bootstrap
	./configure --enable-java
	make distclean
	rm -rf autom4te.cache config.log config.status debian/
	bash bootstrap
	./configure --enable-java
	make -j4
	debuild -us -uc 

