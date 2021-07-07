#!/usr/bin/perl

# Release script for Windows Executables.  Note that this is run
# after release-unix.pl, which will create the needed tag directories
# and update the version variables accordingly.
#
# This only builds the 32-bit, release target  
#
# Assumes:
#- The correct msbuild is in the PATH
#-- VS2015 and VS2008 put this in different places.  If VS2008 is found first, you'll get errors
#   about not finding the 140_xp platform. 
#-- The easiest way to do this is to launch Cygwin using the appropriate batch file, which sets
#   the correct environment variables. 
#- Nuget exe commandline is installed and on path
#
# This requires Cygwin with:
# - git 
# - zip
#

use strict;

# Use 'no-tag' as the tag name to do basic testing

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


#my $REDIST_LOC = $BUILD_LOC . "/../../redist/x86/Microsoft.VC90.CRT";
#die "Missing redist dir $REDIST_LOC" unless (-d "$REDIST_LOC");


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


	# Get Dependencies
	`nuget restore tsk-win.sln`;

	# 2008 version
	# `vcbuild /errfile:BuildErrors.txt tsk-win.sln "Release|Win32"`; 
	# 2010/2015 version
	`msbuild.exe tsk-win.sln /m /p:Configuration=Release /p:platform=Win32 /clp:ErrorsOnly /nologo > BuildErrors.txt`;
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

	# Zip up the files - move there to make the path in the zip short
	chdir ("$RELDIR") or die "Error changing directories to $RELDIR";
	`zip -r ${rfile}.zip ${rfile}`;

	die "ZIP file not created" unless (-e "${rfile}.zip");

	print "TSK core file saved as ${rfile}.zip in release\n";
	chdir ("..") or die "Error changing to root dir";
}


##############################

chdir ("$TSKDIR") or die "Error changing to TSK dir $TSKDIR";

update_code();
build_core();
package_core();
