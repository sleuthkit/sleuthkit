BUILDLOG = BuildLog.txt
RM	= rm -f
MORE	= cat
MSBUILD	= msbuild.exe

TSK_SOLN = "$(TSK_HOME)\win32\tsk-win.sln"
EWF_SOLN = "$(LIBEWF_HOME)\msvscpp\libewf.sln"
FRMWK_SOLN = "$(TSK_HOME)\framework\msvcpp\framework\framework.sln"
POCO_SOLN = "$(POCO_HOME)\Foundation\Foundation_vs100.sln"
POCO_UTIL_SOLN = "$(POCO_HOME)\Util\Util_vs100.sln"
POCO_XML_SOLN = "$(POCO_HOME)\XML\XML_vs100.sln"
POCO_NET_SOLN = "$(POCO_HOME)\Net\Net_vs100.sln"
POCO_ZIP_SOLN = "$(POCO_HOME)\Zip\Zip_vs100.sln"

RELEASE_FLAGS = "/property:Configuration=Release"
DEBUG_FLAGS = "/property:Configuration=Debug"
POCO_RELEASE_FLAGS = "/property:Configuration=release_shared"
POCO_DEBUG_FLAGS = "/property:Configuration=debug_shared"

LOGFILE_FLAGS = "/fileloggerparameters:logfile=$(BUILDLOG);Append;Verbosity=detailed"

all:	debug

usage:
    @echo Usage: nmake [poco ^| libewf ^| all_deps ^| debug ^| release ^| clean ^| spotless]
    @echo "   poco: Builds debug and release versions of Poco libraries"
    @echo "   libewf: Builds release version of libewf_dll and zlib"
    @echo "   all_deps: Builds all dependencies (i.e. Poco, libewf and zlib)"
    @echo "   release: Builds release versions of libtsk and libtskframework"
    @echo "   debug: Builds debug versions of libtsk and libtskframework"
    @echo "   clean: Cleans debug and release versions of libtsk and libtskframework"
    @echo "   spotless: Cleans libtsk, libtskframework, libewf, zlib and Poco."

poco:
	$(MSBUILD)  $(POCO_SOLN) /target:Foundation $(POCO_DEBUG_FLAGS) $(LOGFILE_FLAGS)
	$(MSBUILD)  $(POCO_XML_SOLN) /target:XML $(POCO_DEBUG_FLAGS) $(LOGFILE_FLAGS)
	$(MSBUILD)  $(POCO_NET_SOLN) /target:Net $(POCO_DEBUG_FLAGS) $(LOGFILE_FLAGS)
	$(MSBUILD)  $(POCO_ZIP_SOLN) /target:Zip $(POCO_DEBUG_FLAGS) $(LOGFILE_FLAGS)
	$(MSBUILD)  $(POCO_UTIL_SOLN) /target:Util $(POCO_DEBUG_FLAGS) $(LOGFILE_FLAGS)
	$(MSBUILD)  $(POCO_SOLN) /target:Foundation $(POCO_RELEASE_FLAGS) $(LOGFILE_FLAGS)
	$(MSBUILD)  $(POCO_XML_SOLN) /target:XML $(POCO_RELEASE_FLAGS) $(LOGFILE_FLAGS)
	$(MSBUILD)  $(POCO_NET_SOLN) /target:Net $(POCO_RELEASE_FLAGS) $(LOGFILE_FLAGS)
	$(MSBUILD)  $(POCO_ZIP_SOLN) /target:Zip $(POCO_RELEASE_FLAGS) $(LOGFILE_FLAGS)
	$(MSBUILD)  $(POCO_UTIL_SOLN) /target:Util $(POCO_RELEASE_FLAGS) $(LOGFILE_FLAGS)

libewf:
	$(MSBUILD)  $(EWF_SOLN) /target:libewf_dll $(RELEASE_FLAGS) $(LOGFILE_FLAGS)
    
all_deps: poco libewf

release: all_deps
	$(MSBUILD)  $(TSK_SOLN) /target:libtsk $(RELEASE_FLAGS) $(LOGFILE_FLAGS)
	$(MSBUILD)  $(FRMWK_SOLN) $(RELEASE_FLAGS) $(LOGFILE_FLAGS)

debug: all_deps
	$(MSBUILD)  $(TSK_SOLN) /target:libtsk $(DEBUG_FLAGS) $(LOGFILE_FLAGS)
	$(MSBUILD)  $(FRMWK_SOLN) $(DEBUG_FLAGS) $(LOGFILE_FLAGS)

clean:
    $(RM) $(BUILDLOG)
	$(MSBUILD) $(TSK_SOLN) /target:Clean $(DEBUG_FLAGS)
	$(MSBUILD) $(FRMWK_SOLN) /target:Clean $(DEBUG_FLAGS)
	$(MSBUILD) $(TSK_SOLN) /target:Clean $(RELEASE_FLAGS)
	$(MSBUILD) $(FRMWK_SOLN) /target:Clean $(RELEASE_FLAGS)

spotless: clean
	$(MSBUILD) $(EWF_SOLN) /target:Clean $(RELEASE_FLAGS)
	$(MSBUILD) $(POCO_SOLN) /target:Clean $(POCO_DEBUG_FLAGS)
	$(MSBUILD) $(POCO_XML_SOLN) /target:Clean $(POCO_DEBUG_FLAGS)
	$(MSBUILD) $(POCO_NET_SOLN) /target:Clean $(POCO_DEBUG_FLAGS)
	$(MSBUILD) $(POCO_ZIP_SOLN) /target:Clean $(POCO_DEBUG_FLAGS)
	$(MSBUILD) $(POCO_UTIL_SOLN) /target:Clean $(POCO_DEBUG_FLAGS)
	$(MSBUILD) $(POCO_SOLN) /target:Clean $(POCO_RELEASE_FLAGS)
	$(MSBUILD) $(POCO_XML_SOLN) /target:Clean $(POCO_RELEASE_FLAGS)
	$(MSBUILD) $(POCO_NET_SOLN) /target:Clean $(POCO_RELEASE_FLAGS)
	$(MSBUILD) $(POCO_ZIP_SOLN) /target:Clean $(POCO_RELEASE_FLAGS)
	$(MSBUILD) $(POCO_UTIL_SOLN) /target:Clean $(POCO_RELEASE_FLAGS)
