ACLOCAL_AMFLAGS = -I m4
AM_CXXFLAGS = $(FW_INCLUDE) $(TSK_INCLUDE) -Wall
LDFLAGS="-lmagic"

# this will be true if libmagic was found by configure. 
# We don't have configure fail at runtime because then no modules
# can be compiled. 
if HAS_LIBMAGIC

lib_LTLIBRARIES = libtskFileTypeSigModule.la
libtskFileTypeSigModule_la_SOURCES = FileTypeModule.cpp
libtskFileTypeSigModule_la_LIBADD = $(FW_LIBS)

nobase_dist_data_DATA = tsk/FileTypeSigModule/magic.mgc

.PHONY: maybe_copy_configs setup_data
bin_PROGRAMS = maybe_copy_configs setup_data

setup_data_SOURCES = 
setup_data:
	-mkdir -p tsk/FileTypeSigModule
	(cd tsk/FileTypeSigModule; ln -sf ../../file-5.08/magic/magic.mgc .)

MODULE_CONFIG_DIR = $(RUNTIME_MODULES_CONFIG_DIR)/tskFileTypeSigModule

maybe_copy_configs_SOURCES =
maybe_copy_configs:
	if test "$(FW_LIBS)" != ""; then \
		mkdir -p $(MODULE_CONFIG_DIR); \
		(cd $(MODULE_CONFIG_DIR); ln -sf $(MODULES_ROOT_DIR)/c_FileTypeSigModule/file-5.08/magic/magic.mgc .); \
	fi

else

bin_PROGRAMS = no_libmagic
no_libmagic_SOURCES = 
no_libmagic:
	@echo "Nothing to do for FileTypeSigModule, libmagic not found."

endif
