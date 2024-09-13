SUBDIRS = fiwalk

bin_SCRIPTS = sorter/sorter timeline/mactime
CLEANFILES = $(bin_SCRIPTS)
EXTRA_DIST = \
	sorter/sorter.base \
	sorter/.perltidyrc \
	timeline/mactime.base \
	timeline/.perltidyrc

# TODO: use $@ for target file name

timeline/mactime: timeline/mactime.base Makefile
	@echo "#!$(PERL) -w" > timeline/mactime
	@echo "my \$$VER=\"$(VERSION)\";" >> timeline/mactime
	@cat $(srcdir)/timeline/mactime.base >> timeline/mactime
	@chmod +x timeline/mactime

sorter/sorter: sorter/sorter.base Makefile
	@echo "#!$(PERL) -w" > sorter/sorter
	@echo "my \$$BIN_DIR=\"$(bindir)\";" >> sorter/sorter
	@echo "my \$$DATA_DIR=\"$(datadir)\";" >> sorter/sorter
	@echo "my \$$VER=\"$(VERSION)\";" >> sorter/sorter
	@cat $(srcdir)/sorter/sorter.base >> sorter/sorter
	@chmod +x sorter/sorter

indent:
	pushd sorter ; perltidy -b sorter.base ; popd
	pushd timeline ; perltidy -b mactime.base ; popd
