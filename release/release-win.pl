#!/usr/bin/perl

# Release script for Windows Executables.  Note that this is run
# after release-unix.pl, which will create the needed tag directories
# and update the version variables accordingly.  This assumes that 
# libewf has been compiled in LIBEWF_HOME
#
#
# This requires Cygwin with:
# - git 
# - zip
#
# It has been used with Visual Studio 9.0 Express.  It may work with other
# versions.
#

use strict;

my $TESTING = 0;
print "TESTING MODE (no commits)\n" if ($TESTING);



unless (@ARGV == 1) {
	print stderr "Missing arguments: tag_version\n";
	print stderr "    for example: release-win.pl sleuthkit-3.1.0\n";
	print stderr "    or to use current working code: release-win.pl no-tag\n";
	die "stopping";

}



my $RELDIR = `pwd`;	# The release directory
chomp $RELDIR;
my $SVNDIR = "$RELDIR/../";
my $TSKDIR = "${SVNDIR}";

my $TAGNAME = $ARGV[0];
my $VER = "";


my $BUILD_LOC = `which vcbuild`;
chomp $BUILD_LOC;
die "Unsupported build system.  Verify redist location" 
    unless ($BUILD_LOC =~ /Visual Studio 9\.0/);

my $REDIST_LOC = $BUILD_LOC . "/../../redist/x86/Microsoft.VC90.CRT";
die "Missing redist dir $REDIST_LOC" unless (-d "$REDIST_LOC");


# Verify LIBEWF is built
die "LIBEWF missing" unless (-d "$ENV{'LIBEWF_HOME'}");
die "libewf dll missing" 
	unless (-e "$ENV{'LIBEWF_HOME'}/msvscpp/release/libewf.dll" ); 


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
		`git submodule update`;
		`git submodule foreach git checkout master`;

		# Verify the tag exists
		exec_pipe(*OUT, "git tag | grep \"${TAGNAME}\"");
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
		die "tag name and configure.ac have different versions ($TAGNAME vs $VER)" 
			if ("sleuthkit-".$VER != $TAGNAME);
	}

}



# Compile Core TSK
# Starts and ends in sleuthkit
sub build_core {
	print "Building TSK source\n";
	chdir "win32" or die "error changing directory into win32";
	# Get rid of everything in the release dir (since we'll be doing * copy)
	`rm -f release/*`;
	`rm BuildErrors.txt`;
	`vcbuild /errfile:BuildErrors.txt tsk-win.sln "Release|Win32"`; 
	die "Build errors -- check win32/BuildErrors.txt" if (-s "BuildErrors.txt");

	# Do a basic check on some of the executables
	die "mmls missing" unless (-x "release/mmls.exe");
	die "fls missing" unless (-x "release/fls.exe");
	die "hfind missing" unless (-x "release/hfind.exe");
	chdir "..";
}


#######################
# Package the execs

# Runs in root sleuthkit dir
sub package_core {
	# Verify that the directory does not already exist
	my $rfile = "sleuthkit-win32-${VER}";
	my $rdir = $RELDIR . "/" . $rfile;
	die "Release directory already exists: $rdir" if (-d "$rdir");

	# We already checked that it didn't exist
	print "Creating file in ${rdir}\n";

	mkdir ("$rdir") or die "error making release directory: $rdir";
	mkdir ("${rdir}/bin") or die "error making bin release directory: $rdir";
	mkdir ("${rdir}/lib") or die "error making lib release directory: $rdir";
	mkdir ("${rdir}/licenses") or die "error making licenses release directory: $rdir";


	`cp win32/release/*.exe \"${rdir}/bin\"`;
	`cp win32/release/*.dll \"${rdir}/bin\"`;
	`cp win32/release/*.lib \"${rdir}/lib\"`;

	# basic cleanup
	`rm \"${rdir}/bin/callback-sample.exe\"`;
	`rm \"${rdir}/bin/posix-sample.exe\"`;


	# mactime
	`echo 'my \$VER=\"$VER\";' > \"${rdir}/bin/mactime.pl\"`;
	`cat tools/timeline/mactime.base >> \"${rdir}/bin/mactime.pl\"`;


	# Copy standard files
	`cp README.txt \"${rdir}\"`;
	`unix2dos \"${rdir}/README.txt\" 2> /dev/null`;
	`cp win32/docs/README-win32.txt \"${rdir}\"`;
	`cp NEWS.txt \"${rdir}\"`;
	`unix2dos \"${rdir}/NEWS.txt\" 2> /dev/null`;
	`cp licenses/cpl1.0.txt \"${rdir}/licenses\"`;
	`unix2dos \"${rdir}/licenses/cpl1.0.txt\" 2> /dev/null`;
	`cp licenses/IBM-LICENSE \"${rdir}/licenses\"`;
	`unix2dos \"${rdir}/licenses/IBM-LICENSE\" 2> /dev/null`;

	# MS Redist dlls and manifest
	`cp \"${REDIST_LOC}\"/* \"${rdir}/bin\"`;
	print "******* Using Updated Manifest File *******\n";
	`cp \"${RELDIR}/Microsoft.VC90.CRT.manifest\" \"${rdir}/bin\"`;

	# Zip up the files - move there to make the path in the zip short
	chdir ("$RELDIR") or die "Error changing directories to $RELDIR";
	`zip -r ${rfile}.zip ${rfile}`;

	die "ZIP file not created" unless (-e "${rfile}.zip");

	print "File saved as ${rfile}.zip in release\n";
	chdir ("..") or die "Error changing to root dir";
}


##############################

# Starts and ends in root sleuthkit dir
sub build_framework {
	print "Building TSK framework\n";

	chdir "framework/win32/framework" or die "error changing directory into framework/win32";
	# Get rid of everything in the release dir (since we'll be doing * copy)
	`rm -rf release/*`;
	`rm BuildErrors.txt`;
	`vcbuild /errfile:BuildErrors.txt framework.sln "Release|Win32"`; 
	die "Build errors -- check framework/win32/framework/BuildErrors.txt" if (-e "BuildErrors.txt" && -s "BuildErrors.txt");

	# Do a basic check on some of the executables
	die "libtskframework.dll missing" unless (-x "Release/libtskframework.dll");
	die "tsk_analyzeimg missing" unless (-x "Release/tsk_analyzeimg.exe");
	die "HashCalcModule.dll missing" unless (-x "Release/HashCalcModule.dll");

	chdir "../../..";
}

sub package_framework {
	# Verify that the directory does not already exist
	my $rfile = "sleuthkit-framework-win32-${VER}";
	my $rdir = $RELDIR . "/" . $rfile;
	die "Release directory already exists: $rdir" if (-d "$rdir");

	# We already checked that it didn't exist
	print "Creating file in ${rdir}\n";

	mkdir ("$rdir") or die "error making release directory: $rdir";
	mkdir ("${rdir}/bin") or die "error making bin release directory: $rdir";
	mkdir ("${rdir}/modules") or die "error making module release directory: $rdir";
	mkdir ("${rdir}/licenses") or die "error making licenses release directory: $rdir";
	mkdir ("${rdir}/docs") or die "error making docs release directory: $rdir";

	chdir "framework" or die "error changing directory into framework";

	chdir "win32/framework/release" or die "Error changing directory into release / framework";

	`cp *.exe \"${rdir}/bin\"`;
	`cp libtsk*.dll \"${rdir}/bin\"`;
	`cp Poco*.dll \"${rdir}/bin\"`;
	`cp libewf*.dll \"${rdir}/bin\"`;
	`cp zlib.dll \"${rdir}/bin\"`;

	
	# Copy the modules and config dirs
	opendir(DIR, ".") or die "Error opening framework release folder";
	while(my $f = readdir(DIR)) {
		next unless ($f =~ /Module\.dll$/);
		`cp \"$f\" \"${rdir}/modules\"`;
		my $base = $1 if ($f =~ /^(.*)\.dll$/);
		if (-d "$base") {
			`cp -r \"$base\" \"${rdir}/modules\"`;
		}
	}
	closedir(DIR);
	chdir "../../..";


	`cp SampleConfig/framework_config_bindist.xml \"${rdir}/bin/framework_config.xml\"`;
	`unix2dos \"${rdir}/bin/framework_config.xml\" 2> /dev/null`;


	`cp SampleConfig/pipeline_config.xml \"${rdir}/bin/pipeline_config.xml\"`;
	`unix2dos \"${rdir}/bin/pipeline_config.xml\" 2> /dev/null`;


	# Copy the readme files for each module
	opendir(my $modDir, "./TskModules") or die "Error opening TskModules folder";
	while(my $f = readdir($modDir)) {
		next unless ($f =~ /^c_\w+/);
		if (-f "TskModules/$f/README.txt") {
			`cp TskModules/$f/README.txt \"${rdir}/docs/README_${f}.txt\"`;
			`unix2dos \"${rdir}/docs/README_${f}.txt\" 2> /dev/null`;
			
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
	`cp \"${REDIST_LOC}\"/* \"${rdir}/bin\"`;
	print "******* Using Updated Manifest File *******\n";
	`cp \"${RELDIR}/Microsoft.VC90.CRT.manifest\" \"${rdir}/bin\"`;

	# Zip up the files - move there to make the path in the zip short
	chdir ("$RELDIR") or die "Error changing directories to $RELDIR";
	`zip -r ${rfile}.zip ${rfile}`;

	die "ZIP file not created" unless (-e "${rfile}.zip");

	print "File saved as ${rfile}.zip in release\n";
	chdir "..";
}

chdir ("$TSKDIR") or die "Error changing to TSK dir $TSKDIR";

update_code();
build_core();
package_core();
build_framework();
package_framework();
