AM_CXXFLAGS = $(AM_CXXFLAGS_MOD)

lib_LTLIBRARIES = libtskInterestingFilesModule.la
libtskInterestingFilesModule_la_SOURCES = InterestingFilesModule.cpp
libtskInterestingFilesModule_la_LIBADD = $(AM_LIBADD_MOD)

nobase_dist_data_DATA = tsk/InterestingFilesModule/interesting_files.xml

.PHONY: maybe_copy_configs setup_data
bin_PROGRAMS = maybe_copy_configs setup_data

setup_data_SOURCES = 
setup_data:
	-mkdir -p tsk/InterestingFilesModule
	(cd tsk/InterestingFilesModule; ln -sf ../../interesting_files.xml .)

MODULE_CONFIG_DIR = $(RUNTIME_MODULES_CONFIG_DIR)/tskInterestingFilesModule

maybe_copy_configs_SOURCES =
maybe_copy_configs:
		mkdir -p $(MODULE_CONFIG_DIR); \
		(cd $(MODULE_CONFIG_DIR); ln -sf $(MODULES_ROOT_DIR)/c_InterestingFilesModule/tsk/InterestingFilesModule/interesting_files.xml .); 
