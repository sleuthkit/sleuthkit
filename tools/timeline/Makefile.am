bin_SCRIPTS = mactime
CLEANFILES = $(bin_SCRIPTS)
EXTRA_DIST = mactime.base .perltidyrc

mactime: mactime.base Makefile
	@echo "#!$(PERL) -w" > mactime
	@echo "my \$$VER=\"$(VERSION)\";" >> mactime 
	@cat $(srcdir)/mactime.base >> mactime
	@chmod +x mactime 

indent:
	perltidy -b mactime.base
