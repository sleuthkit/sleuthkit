#!/usr/bin/perl

# Builds the dependent libraries
# run this from cygwin (that's what I do at least).

# This assumes that:
# - libewf has already been converted to 2010
# - msbuild is on the path (requires .Net in the path)

sub build_libewf() {
	print "Building libewf\n";

	chdir "$ENV{'LIBEWF_HOME'}" or die "error changing into libewf folder";
	chdir "msvscpp/" or die "error changing into libewf msvscpp folder";

	die "Project needs to be upgraded to 2010" unless (-e "libewf_dll/libewf_dll.vcxproj");
        `rm -f Release/*`;

        `rm -f libewf_dll/Release/*`;
        `rm -f BuildErrors.txt`;
        # 2010 version
        `msbuild.exe libewf.sln /p:Configuration=Release /clp:ErrorsOnly /nologo > BuildErrors.txt`;
        die "Build errors -- check libewf/msvscpp/BuildErrors.txt" if (-s "BuildErrors.txt");
}

sub build_poco() {
	print "Building Poco\n";

	chdir "$ENV{'POCO_HOME'}" or die "error changing into POCO folder";
	`rm -f bin/*`;
	`rm -f lib/*`;

	chdir "Foundation" or die "error changing into poco foundation folder";
        `rm -f BuildErrors.txt`;
        # 2010 version
        `msbuild.exe Foundation_vs100.vcxproj /p:Configuration=release_shared /clp:ErrorsOnly /nologo > BuildErrors.txt`;
        die "Build errors -- check poco/foundation/BuildErrors.txt" if (-s "BuildErrors.txt");

        `rm -f BuildErrors.txt`;
        # 2010 version
        `msbuild.exe Foundation_vs100.vcxproj /p:Configuration=debug_shared /clp:ErrorsOnly /nologo > BuildErrors.txt`;
        die "Build errors -- check poco/foundation/BuildErrors.txt" if (-s "BuildErrors.txt");
	chdir "..";

	chdir "Net" or die "error changing into poco Net folder";
        `rm -f BuildErrors.txt`;
        # 2010 version
        `msbuild.exe Net_vs100.vcxproj /p:Configuration=release_shared /clp:ErrorsOnly /nologo > BuildErrors.txt`;
        die "Build errors -- check poco/Net/BuildErrors.txt" if (-s "BuildErrors.txt");
        `rm -f BuildErrors.txt`;
        # 2010 version
        `msbuild.exe Net_vs100.vcxproj /p:Configuration=debug_shared /clp:ErrorsOnly /nologo > BuildErrors.txt`;
        die "Build errors -- check poco/Net/BuildErrors.txt" if (-s "BuildErrors.txt");
	chdir "..";

	chdir "XML" or die "error changing into poco XML folder";
        `rm -f BuildErrors.txt`;
        # 2010 version
        `msbuild.exe XML_vs100.vcxproj /p:Configuration=release_shared /clp:ErrorsOnly /nologo > BuildErrors.txt`;
        die "Build errors -- check poco/xml/BuildErrors.txt" if (-s "BuildErrors.txt");
        `rm -f BuildErrors.txt`;
        # 2010 version
        `msbuild.exe XML_vs100.vcxproj /p:Configuration=debug_shared /clp:ErrorsOnly /nologo > BuildErrors.txt`;
        die "Build errors -- check poco/xml/BuildErrors.txt" if (-s "BuildErrors.txt");
	chdir "..";

	chdir "Util" or die "error changing into poco Util folder";
        `rm -f BuildErrors.txt`;
        # 2010 version
        `msbuild.exe Util_vs100.vcxproj /p:Configuration=release_shared /clp:ErrorsOnly /nologo > BuildErrors.txt`;
        die "Build errors -- check poco/Util/BuildErrors.txt" if (-s "BuildErrors.txt");
        `rm -f BuildErrors.txt`;
        # 2010 version
        `msbuild.exe Util_vs100.vcxproj /p:Configuration=debug_shared /clp:ErrorsOnly /nologo > BuildErrors.txt`;
        die "Build errors -- check poco/Util/BuildErrors.txt" if (-s "BuildErrors.txt");
	chdir "..";

	chdir "Zip" or die "error changing into poco Zip folder";
        `rm -f BuildErrors.txt`;
        # 2010 version
        `msbuild.exe Zip_vs100.vcxproj /p:Configuration=release_shared /clp:ErrorsOnly /nologo > BuildErrors.txt`;
        die "Build errors -- check poco/Zip/BuildErrors.txt" if (-s "BuildErrors.txt");
        `rm -f BuildErrors.txt`;
        # 2010 version
        `msbuild.exe Zip_vs100.vcxproj /p:Configuration=debug_shared /clp:ErrorsOnly /nologo > BuildErrors.txt`;
        die "Build errors -- check poco/Zip/BuildErrors.txt" if (-s "BuildErrors.txt");
	chdir "..";


}

build_libewf();
build_poco();
