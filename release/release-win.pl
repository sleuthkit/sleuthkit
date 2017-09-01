#!/usr/bin/perl

# Release script for Windows Executables.  Note that this is run
# after release-unix.pl, which will create the needed tag directories
# and update the version variables accordingly.
#
# This only builds the 32-bit, release target  
#
# Assumes:
#- libewf, libvmdk, and libvhdi are configured and built
#- The correct msbuild is in the PATH
#-- VS2015 and VS2008 put this in different places.  If VS2008 is found first, you'll get errors
#   about not finding the 140_xp platform. 
#-- The easiest way to do this is to launch Cygwin using the appropriate batch file, which sets
#   the correct environment variables. 
#
# This requires Cygwin with:
# - git 
# - zip
#

use strict;

my $TESTING = 0;
print "TESTING MODE (no commits)\n" if ($TESTING);

unless (@ARGV == 1) {
	print stderr "Missing arguments: version\n";
	print stderr "    for example: release-win.pl 3.1.0\n";
	print stderr "    or to use current working code: release-win.pl no-tag\n";
	die "stopping";

}

my $RELDIR = `pwd`;	# The release directory
chomp $RELDIR;
my $TSKDIR = "$RELDIR/../";

my $TAGNAME = $ARGV[0];
unless ($TAGNAME eq "no-tag") {
	$TAGNAME = "sleuthkit-${TAGNAME}";
}
my $VER = "";


# VS 2008 code
#my $BUILD_LOC = `which vcbuild`;
#chomp $BUILD_LOC;
#die "Unsupported build system.  Verify redist location" 
#    unless ($BUILD_LOC =~ /Visual Studio 9\.0/);

#my $REDIST_LOC = $BUILD_LOC . "/../../redist/x86/Microsoft.VC90.CRT";
#die "Missing redist dir $REDIST_LOC" unless (-d "$REDIST_LOC");


# Verify LIBX libraries exist / built
die "LIBEWF missing" unless (-d "$ENV{'LIBEWF_HOME'}");
die "libewf dll missing" 
	unless (-e "$ENV{'LIBEWF_HOME'}/msvscpp/Release/libewf.dll" ); 

die "libvhdi dll missing" 
	unless (-e "$ENV{'LIBVHDI_HOME'}/msvscpp/Release/libvhdi.dll" ); 

die "libvhdi dll missing" 
	unless (-e "$ENV{'LIBVMDK_HOME'}/msvscpp/Release/libvmdk.dll" ); 

	
#######################

# Function to execute a command and send output to pipe
# returns handle
# exec_pipe(HANDLE, CMD);
sub exec_pipe {
    my $handle = shift(@_);
    my $cmd    = shift(@_);

    die "Can't open pipe for exec_pipe"
      unless defined(my $pid = open($handle, '-|'));

    if ($pid) {
        return $handle;
    }
    else {
        $| = 1;
        exec("$cmd") or die "Can't exec program: $!";
    }
}



# Read a line of text from an open exec_pipe handle
sub read_pipe_line {
    my $handle = shift(@_);
    my $out;

    for (my $i = 0; $i < 100; $i++) {
        $out = <$handle>;
        return $out if (defined $out);
    }
    return $out;
}



############## CODE SPECIFIC STUFF ##########

# Checkout a specific tag 
# Starts and ends in sleuthkit
sub update_code {

	my $no_tag = 0;
	$no_tag = 1 if ($TAGNAME eq "no-tag");


	if ($no_tag == 0) {
		#`git submodule update`;
		# Make sure we have no changes in the current tree
		exec_pipe(*OUT, "git status -s | grep \"^ M\"");
		my $foo = read_pipe_line(*OUT);
		if ($foo ne "") {
		    print "Changes stil exist in current repository -- commit them\n";
		    die "stopping";
		}

		# Make sure src dir is up to date
		print "Updating source directory\n";
		`git pull`;
		#`git submodule init`;
		#`git submodule update`;
		#`git submodule foreach git checkout master`;

		# Verify the tag exists
		exec_pipe(*OUT, "git tag | grep \"^${TAGNAME}\"");
		my $foo = read_pipe_line(*OUT);
		if ($foo eq "") {
		    print "Tag ${TAGNAME} doesn't exist\n";
		    die "stopping";
		}
		close(OUT);

		`git checkout -q ${TAGNAME}`;
	}


	# Parse the config file to get the version number
	open (IN, "<configure.ac") or die "error opening configure.ac to get version";
	$VER = "";
	while (<IN>) {
		if (/^AC_INIT\(sleuthkit, ([\d\w\.]+)\)/) {
			$VER = $1;
			last;
		}
	}
	die "Error finding version in configure.ac" if ($VER eq "");
	print "Version found in configure.ac: $VER\n";

	if ($no_tag == 0) {
		die "tag name and configure.ac have different versions ($TAGNAME vs sleuthkit-$VER)" 
			if ("sleuthkit-".$VER != $TAGNAME);
	}

}



# Compile Core TSK
# Starts and ends in sleuthkit
sub build_core {
	print "Building TSK source\n";
	chdir "win32" or die "error changing directory into win32";
	# Get rid of everything in the release dir (since we'll be doing * copy)
	`rm -rf Release`;
	`rm -f BuildErrors.txt`;
	# This was not required with VS2008, but is with 2010. Otherwise, 
	# it won't build with the tagged version
	`rm -rf */Release`;

	die "Release folder not deleted" if (-x "Release/fls.exe");

	# 2008 version
	# `vcbuild /errfile:BuildErrors.txt tsk-win.sln "Release|Win32"`; 
	# 2010/2015 version
	`msbuild.exe tsk-win.sln /m /p:Configuration=Release /clp:ErrorsOnly /nologo > BuildErrors.txt`;
	die "Build errors -- check win32/BuildErrors.txt" if (-s "BuildErrors.txt");

	# Do a basic check on some of the executables
	die "mmls missing" unless (-x "Release/mmls.exe");
	die "fls missing" unless (-x "Release/fls.exe");
	die "hfind missing" unless (-x "Release/hfind.exe");
	chdir "..";
}


#######################
# Package the execs

# Runs in root sleuthkit dir
sub package_core {
	# Verify that the directory does not already exist
	my $rfile = "sleuthkit-${VER}-win32";
	my $rdir = $RELDIR . "/" . $rfile;
	die "Release directory already exists: $rdir" if (-d "$rdir");

	# We already checked that it didn't exist
	print "Creating file in ${rdir}\n";

	mkdir ("$rdir") or die "error making release directory: $rdir";
	mkdir ("${rdir}/bin") or die "error making bin release directory: $rdir";
	mkdir ("${rdir}/lib") or die "error making lib release directory: $rdir";
	mkdir ("${rdir}/licenses") or die "error making licenses release directory: $rdir";


	`cp win32/Release/*.exe \"${rdir}/bin\"`;
	`cp win32/Release/*.dll \"${rdir}/bin\"`;
	`cp win32/Release/*.lib \"${rdir}/lib\"`;

	# basic cleanup
	`rm \"${rdir}/bin/callback-sample.exe\"`;
	`rm \"${rdir}/bin/callback-cpp-sample.exe\"`;
	`rm \"${rdir}/bin/posix-sample.exe\"`;
	`rm \"${rdir}/bin/posix-cpp-sample.exe\"`;


	# mactime
	`echo 'my \$VER=\"$VER\";' > \"${rdir}/bin/mactime.pl\"`;
	`cat tools/timeline/mactime.base >> \"${rdir}/bin/mactime.pl\"`;


	# Copy standard files
	`cp README.md \"${rdir}/README.txt\"`;
	`unix2dos \"${rdir}/README.txt\" 2> /dev/null`;
	`cp win32/docs/README-win32.txt \"${rdir}\"`;
	`cp NEWS.txt \"${rdir}\"`;
	`unix2dos \"${rdir}/NEWS.txt\" 2> /dev/null`;
	`cp licenses/cpl1.0.txt \"${rdir}/licenses\"`;
	`unix2dos \"${rdir}/licenses/cpl1.0.txt\" 2> /dev/null`;
	`cp licenses/IBM-LICENSE \"${rdir}/licenses\"`;
	`unix2dos \"${rdir}/licenses/IBM-LICENSE\" 2> /dev/null`;

	# MS Redist dlls and manifest
	# 2008 version 
	#`cp \"${REDIST_LOC}\"/* \"${rdir}/bin\"`;
	#print "******* Using Updated Manifest File *******\n";
	#`cp \"${RELDIR}/Microsoft.VC90.CRT.manifest\" \"${rdir}/bin\"`;

	# 2010 version
	# copy_runtime_2010("${rdir}/bin");
	
	# 2015 - nothing is needed anymore because they were all setup in the Release folder

	# Zip up the files - move there to make the path in the zip short
	chdir ("$RELDIR") or die "Error changing directories to $RELDIR";
	`zip -r ${rfile}.zip ${rfile}`;

	die "ZIP file not created" unless (-e "${rfile}.zip");

	print "TSK core file saved as ${rfile}.zip in release\n";
	chdir ("..") or die "Error changing to root dir";
}


##############################

# Starts and ends in root sleuthkit dir
sub build_framework {
	print "Building TSK framework\n";

	chdir "framework/msvcpp/framework" or die "error changing directory into framework/msvcpp";
	# Get rid of everything in the release dir (since we'll be doing * copy)
	`rm -rf Release`;
	`rm -f BuildErrors.txt`;
	# This was not needed for VS2008, but is for VS2010
	`rm -rf ../../modules/*/win32/Release`;

	# 2008 version
	#`vcbuild /errfile:BuildErrors.txt framework.sln "Release|Win32"`; 
	# 2010/2015 version
	`msbuild.exe framework.sln /m /p:Configuration=Release /clp:ErrorsOnly /nologo > BuildErrors.txt`;
	die "Build errors -- check framework/msvcpp/framework/BuildErrors.txt" if (-e "BuildErrors.txt" && -s "BuildErrors.txt");

	chdir "../..";

	chdir "runtime";
	# Do a basic check on some of the executables
	die "libtskframework.dll missing" unless (-x "libtskframework.dll");
	die "tsk_analyzeimg missing" unless (-x "tsk_analyzeimg.exe");
	die "tskHashCalcModule.dll missing" unless (-x "tskHashCalcModule.dll");
	chdir "../..";

}

sub package_framework {
	# Verify that the directory does not already exist
	my $rfile = "sleuthkit-${VER}-framework-win32";
	my $rdir = $RELDIR . "/" . $rfile;
	die "Release directory already exists: $rdir" if (-d "$rdir");

	# We already checked that it didn't exist
	print "Creating file in ${rdir}\n";

	# Make the directory structure
	mkdir ("$rdir") or die "error making release directory: $rdir";
	mkdir ("${rdir}/bin") or die "error making bin release directory: $rdir";
	mkdir ("${rdir}/modules") or die "error making module release directory: $rdir";
	mkdir ("${rdir}/licenses") or die "error making licenses release directory: $rdir";
	mkdir ("${rdir}/docs") or die "error making docs release directory: $rdir";


	# Copy the files
	chdir "framework/runtime" or die "Error changing directory into runtime";
	`cp *.exe \"${rdir}/bin\"`;
	`cp libtsk*.dll \"${rdir}/bin\"`;
	`cp Poco*.dll \"${rdir}/bin\"`;
	`cp libewf*.dll \"${rdir}/bin\"`;
	`cp zlib.dll \"${rdir}/bin\"`;

	
	# Copy the modules and config dirs
	opendir(DIR, ".") or die "Error opening framework runtime folder";
	while(my $f = readdir(DIR)) {
        # Skip it unless it ends in Module.dll
		next unless ($f =~ /Module\.dll$/);
		`cp \"$f\" \"${rdir}/modules\"`;
		my $base = $1 if ($f =~ /^(.*)\.dll$/);
		# copy the config dir if it has one
		if (-d "$base") {
			`cp -r \"$base\" \"${rdir}/modules\"`;
		}
	}
	closedir(DIR);


	# Special case libs
	# libmagic
    die unless (-e "libmagic-1.dll");
	`cp libmagic-1.dll \"${rdir}/modules\"`;
    die unless (-e "libgnurx-0.dll");
	`cp libgnurx-0.dll \"${rdir}/modules\"`;

	chdir "..";

	`cp SampleConfig/framework_config_bindist.xml \"${rdir}/bin/framework_config.xml\"`;
	`unix2dos \"${rdir}/bin/framework_config.xml\" 2> /dev/null`;


	`cp SampleConfig/pipeline_config.xml \"${rdir}/bin/pipeline_config.xml\"`;
	`unix2dos \"${rdir}/bin/pipeline_config.xml\" 2> /dev/null`;


	# Copy the readme files for each module
	opendir(my $modDir, "./modules") or die "Error opening modules folder";
	while(my $f = readdir($modDir)) {
		next unless ($f =~ /^c_\w+/);
		if (-f "modules/$f/README.txt") {
			`cp modules/$f/README.txt \"${rdir}/docs/README_${f}.txt\"`;
			`unix2dos \"${rdir}/docs/README_${f}.txt\" 2> /dev/null`;
			`cp modules/$f/NEWS.txt \"${rdir}/docs/NEWS_${f}.txt\"`;
			`unix2dos \"${rdir}/docs/NEWS_${f}.txt\" 2> /dev/null`;
		}
		else {
			print "Didn't find readme in $f\n";
		}
	}
	closedir($modDir);

	# Copy the man pages into docs
	`cp man/*.html \"${rdir}/docs\"`;

	# Copy standard files
	`cp README_bindist.txt \"${rdir}/README.txt\"`;
	`unix2dos \"${rdir}/README.txt\"`;

	# Licences
	`cp ../licenses/cpl1.0.txt \"${rdir}/licenses\"`;
	`unix2dos \"${rdir}/licenses/cpl1.0.txt\" 2> /dev/null`;
	`cp ../licenses/IBM-LICENSE \"${rdir}/licenses\"`;
	`unix2dos \"${rdir}/licenses/IBM-LICENSE\" 2> /dev/null`;
	#`cp \"${ENV{'LIBEWF_HOME'}}/COPYING\" \"${rdir}/licenses\LGPL-COPYING\"`;
	#`unix2dos \"${rdir}/licenses/LGPL-COPYING\"`;

	# MS Redist dlls and manifest

	# 2008 version 
	#`cp \"${REDIST_LOC}\"/* \"${rdir}/bin\"`;
	#print "******* Using Updated Manifest File *******\n";
	#`cp \"${RELDIR}/Microsoft.VC90.CRT.manifest\" \"${rdir}/bin\"`;

	# 2010 version
	copy_runtime_2010("${rdir}/bin");

	# Zip up the files - move there to make the path in the zip short
	chdir ("$RELDIR") or die "Error changing directories to $RELDIR";
	`zip -r ${rfile}.zip ${rfile}`;

	die "ZIP file not created" unless (-e "${rfile}.zip");

	print "File saved as ${rfile}.zip in release\n";
	chdir "..";
}

# Assumes path in /cygwin/style
sub copy_runtime_2010 { 
    my $dest = shift(@_);
    # Copy 32-bit version
    `cp /cygdrive/c/windows/sysWow64/msvcp100.dll \"$dest\"`;
    `cp /cygdrive/c/windows/sysWow64/msvcr100.dll \"$dest\"`;
}

chdir ("$TSKDIR") or die "Error changing to TSK dir $TSKDIR";

update_code();
build_core();
package_core();
# build_framework();
# package_framework();
