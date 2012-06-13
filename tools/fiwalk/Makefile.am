SUBDIRS = src plugins

RELEASE_USER = simsong@
RELEASE_HOST = www.afflib.org
RELEASE_DIR  = afflib.org/

RELEASE_LOC  = $(RELEASE_DIR)/downloads/
CHANGES_LOC  = $(RELEASE_DIR)/ChangeLog.txt
RELEASE_FN   = @FIWALK_PACKAGE@_version.txt
RELEASE_PATH = $(RELEASE_LOC)/$(RELEASE_FN)
RELEASE_SSH  = $(RELEASE_USER)$(RELEASE_HOST):$(RELEASE_LOC)
RELEASE	     = @FIWALK_PACKAGE@-@FIWALK_VERSION@

AM_CFLAGS = -Wall
AM_CXXFLAGS = -Wall

ACLOCAL_AMFLAGS = -I m4

#renew:
#	aclocal
#	autoheader -f
#	touch NEWS README AUTHORS ChangeLog
#	touch stamp-h
#	aclocal
#	automake -a -c
#	autoconf -f
#
#release:
#	make prerelease
#	make distcheck
#	make therelease
#
#prerelease:
#	@echo Building and uploading the release...
#	@echo Making release $(RELEASE)
#	@echo
#	echo
#	wget http://$(RELEASE_HOST)/downloads/$(RELEASE_FN)
#	@echo Version `cat $(RELEASE_FN)` is on the server.
#	python checkversion.py $(RELEASE_FN) $(RELEASE)
#	/bin/rm $(RELEASE_FN)
#
#therelease:
#	gpg --detach-sign $(RELEASE).tar.gz
#	scp $(RELEASE).tar.gz{,.sig} $(RELEASE_SSH)
#	ssh $(RELEASE_HOST) 'echo $(RELEASE).tar.gz > $(RELEASE_PATH)'
#	ssh $(RELEASE_HOST) 'cd $(RELEASE_LOC);/bin/rm $(PACKAGE).tar.gz;ln -s $(RELEASE).tar.gz $(PACKAGE).tar.gz'
#	@echo Release $(RELEASE) uploaded to server

