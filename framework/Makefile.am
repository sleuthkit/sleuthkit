ACLOCAL_AMFLAGS = -I m4
SUBDIRS = tsk/framework tools modules

nobase_include_HEADERS = \
    tsk/framework/framework.h \
    tsk/framework/framework_i.h \
    tsk/framework/TskVersionInfo.h \
    tsk/framework/extraction/CarveExtract.h \
    tsk/framework/extraction/CarvePrep.h \
    tsk/framework/extraction/TskAutoImpl.h \
    tsk/framework/extraction/TskCarveExtractScalpel.h \
    tsk/framework/extraction/TskCarvePrepSectorConcat.h \
    tsk/framework/extraction/TskImageFile.h \
    tsk/framework/extraction/TskImageFileTsk.h \
    tsk/framework/file/TskFile.h \
    tsk/framework/file/TskFileManager.h \
    tsk/framework/file/TskFileManagerImpl.h \
    tsk/framework/file/TskFileTsk.h \
    tsk/framework/pipeline/TskExecutableModule.h \
    tsk/framework/pipeline/TskFileAnalysisPipeline.h \
    tsk/framework/pipeline/TskFileAnalysisPluginModule.h \
    tsk/framework/pipeline/TskModule.h \
    tsk/framework/pipeline/TskPipeline.h \
    tsk/framework/pipeline/TskPipelineManager.h \
    tsk/framework/pipeline/TskPluginModule.h \
    tsk/framework/pipeline/TskReportPipeline.h \
    tsk/framework/pipeline/TskReportPluginModule.h \
    tsk/framework/services/Log.h \
    tsk/framework/services/Scheduler.h \
    tsk/framework/services/TskBlackboardArtifact.h \
    tsk/framework/services/TskBlackboardAttribute.h \
    tsk/framework/services/TskBlackboard.h \
    tsk/framework/services/TskDBBlackboard.h \
    tsk/framework/services/TskImgDB.h \
    tsk/framework/services/TskImgDBSqlite.h \
    tsk/framework/services/TskSchedulerQueue.h \
    tsk/framework/services/TskServices.h \
    tsk/framework/services/TskSystemProperties.h \
    tsk/framework/services/TskSystemPropertiesImpl.h \
    tsk/framework/utilities/SectorRuns.h \
    tsk/framework/utilities/TskException.h \
    tsk/framework/utilities/TskModuleDev.h \
    tsk/framework/utilities/TskUtilities.h \
    tsk/framework/utilities/UnallocRun.h


if DARWIN
  PLATFORM=mac
  LIBEXT=dylib
else
  PLATFORM=linux
  LIBEXT=so
endif

.PHONY: copy_libs copy_configs
# Copy the modules libraries into the Modules directory
bin_PROGRAMS = copy_libs copy_configs

runtime/modules:
	-mkdir -p $@

copy_libs_SOURCES = 
copy_libs: runtime/modules
	(cd $<; ln -sf ../../modules/c_*/.libs/libtsk*Module.* .)
	(cd $<; ln -sf ../../tsk/framework/.libs/libtskframework.* .)
	(cd $<; ln -sf ../../../tsk/.libs/libtsk.* .)

copy_configs_SOURCES = 
copy_configs:
	-mkdir -p runtime
	cp SampleConfig/framework_config_unixdev.xml runtime/framework_config.xml
	if ! test -d SampleConfig/to_install; then \
		mkdir SampleConfig/to_install; \
	else \
        rm -f SampleConfig/to_install/framework_config.xml; \
	fi

installdir = ${datadir}/tsk
dist_install_DATA = SampleConfig/to_install/framework_config.xml SampleConfig/pipeline_config.xml

# Creates a framework_config file that has the paths for where things will be installed.
SampleConfig/to_install/framework_config.xml:
	sed \
		-e 's?#CONFIGDIRPATH#?$(DESTDIR)/usr/local/share/tsk?' \
		-e 's?#MODULEDIRPATH#?$(DESTDIR)/usr/local/lib?' \
		-e 's?#MODULECONFIGDIRPATH#?$(DESTDIR)/usr/local/share/tsk?' \
		SampleConfig/framework_config_template.xml \
	 > $@
