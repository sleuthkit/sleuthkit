bin_SCRIPTS = sorter
CLEANFILES = $(bin_SCRIPTS)
EXTRA_DIST = sorter.base .perltidyrc

sorter: sorter.base Makefile
	@echo "#!$(PERL) -w" > sorter
	@echo "my \$$BIN_DIR=\"$(bindir)\";" >> sorter
	@echo "my \$$DATA_DIR=\"$(datadir)\";" >> sorter
	@echo "my \$$VER=\"$(VERSION)\";" >> sorter
	@cat $(srcdir)/sorter.base >> sorter
	@chmod +x sorter

indent:
	perltidy -b sorter.base
