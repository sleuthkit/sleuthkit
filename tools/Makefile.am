SUBDIRS = timeline fiwalk

bin_SCRIPTS = sorter/sorter
CLEANFILES = $(bin_SCRIPTS)
EXTRA_DIST = sorter/sorter.base sorter/.perltidyrc

sorter/sorter: sorter/sorter.base Makefile
	@echo "#!$(PERL) -w" > sorter/sorter
	@echo "my \$$BIN_DIR=\"$(bindir)\";" >> sorter/sorter
	@echo "my \$$DATA_DIR=\"$(datadir)\";" >> sorter/sorter
	@echo "my \$$VER=\"$(VERSION)\";" >> sorter/sorter
	@cat $(srcdir)/sorter/sorter.base >> sorter/sorter
	@chmod +x sorter/sorter

indent:
	cd sorter ; perltidy -b sorter.base
