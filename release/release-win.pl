#!/usr/bin/perl

# Release script for Windows Executables.  Note that this is run
# after release-unix.pl, which will create the needed tag directories
# and update the version variables accordingly.  This assumes that you
# have been building TSK with libewf on your system in one of the trunk
# or branch directories and it will copy libewf from there. 
#
#
# This requires Cygwin with:
# - svn
# - zip
#
# It has been used with Visual Studio 9.0 Express.  It may work with other
# versions.
#

use strict;

unless (@ARGV == 2) {
	print stderr "Missing arguments: tag version and base directory\n";
	print stderr "    for example: release-win.pl 3.1.0 branches/sleuthkit-3.1\n";
	print stderr "    tag version: 3.1.0 if building from tags/sleuthkit-3.1.0\n";
	print stderr "    base directory: trunk or branches/sleuthkit-3.1 so that libewf and zlib can be copied from there (must exist on local system and be able to be built)\n";
	die "stopping";
}


my $RELDIR = `pwd`;	# The release directory
chomp $RELDIR;
my $SVNDIR = "$RELDIR/../";
my $TAGNAME = $ARGV[0];
my $TSKDIR = "${SVNDIR}/tags/sleuthkit-$TAGNAME";


my $COPYDIR = $ARGV[1];
die "Base dir missing $SVNDIR/$COPYDIR" unless (-d "$SVNDIR/$COPYDIR");


my $BUILD_LOC = `which vcbuild`;
chomp $BUILD_LOC;
die "Unsupported build system.  Verify redist location" 
    unless ($BUILD_LOC =~ /Visual Studio 9\.0/);

my $REDIST_LOC = $BUILD_LOC . "/../../redist/x86/Microsoft.VC90.CRT";
die "Missing redist dir $REDIST_LOC" unless (-d "$REDIST_LOC");


#######################
# Build the execs


# Make sure src dir is up to date
print "Updating source directory\n";
chdir ("$SVNDIR") or die "Error changing to SVN dir $SVNDIR";
`svn -q update`;

die "tag directory ${TSKDIR} not in SVN" unless (-d "${TSKDIR}");
chdir ("$TSKDIR") or die "Error changing directories to $TSKDIR";

# Parse the config file to get the version number
open (IN, "<configure.ac") or die "error opening configure.ac to get version";
my $VER = "";
while (<IN>) {
	if (/^AC_INIT\(sleuthkit, ([\d\w\.]+)\)/) {
		$VER = $1;
		last;
	}
}
die "Error finding version in configure.ac" if ($VER eq "");
print "Version found in configure.ac: $VER\n";
die "tag name and configure.ac have different versions ($TAGNAME vs $VER)" 
	if ($VER != $TAGNAME);


# Verify that the directory does not already exist
my $rfile = "sleuthkit-win32-${VER}";
my $rdir = $RELDIR . "/" . $rfile;
die "Release directory already exists: $rdir" if (-d "$rdir");



print "Copying libewf source from base directory\n";
die "Base dir missing libewf" unless (-d "$SVNDIR/$COPYDIR/win32/libewf");
`cp -r \"$SVNDIR/$COPYDIR/win32/libewf\" win32`;
die "Error copying libewf" unless (-d "win32/libewf");


print "Building libewf source\n";
chdir "win32/libewf/msvscpp" or die "Error changing directory into libewf";
`vcbuild libewf.sln "Release|Win32"`; 
die "libewf dll missing" 
	unless (-e "release/libewf.dll" ); 
chdir "../../../";


print "Building TSK source\n";
chdir "win32" or die "error changing directory into win32";
# Get rid of everything in the release dir (since we'll be doing * copy)
`rm -f release/*`;
`vcbuild tsk-win.sln "Release|Win32"`; 
chdir "..";

# Do a basic check on some of the executables
die "mmls missing" unless (-x "win32/release/mmls.exe");
die "fls missing" unless (-x "win32/release/fls.exe");
die "hfind missing" unless (-x "win32/release/hfind.exe");


#######################
# Package the execs

# We already checked that it didn't exist
print "Creating file in ${rdir}\n";

mkdir ("$rdir") or die "error making release directory: $rdir";
mkdir ("${rdir}/bin") or die "error making bin release directory: $rdir";
mkdir ("${rdir}/lib") or die "error making lib release directory: $rdir";
mkdir ("${rdir}/licenses") or die "error making licenses release directory: $rdir";


`cp win32/release/*.exe \"${rdir}/bin\"`;
`cp win32/release/*.lib \"${rdir}/lib\"`;
`cp win32/libewf/msvscpp/release/libewf.dll \"${rdir}/bin\"`;
`cp win32/libewf/msvscpp/zlib/zlib1.dll \"${rdir}/bin\"`;

# basic cleanup
`rm \"${rdir}/bin/callback-sample.exe\"`;
`rm \"${rdir}/bin/posix-sample.exe\"`;


# mactime
`echo 'my \$VER=\"$VER\";' > \"${rdir}/bin/mactime.pl\"`;
`cat tools/timeline/mactime.base >> \"${rdir}/bin/mactime.pl\"`;


# Copy standard files
`cp README.txt \"${rdir}\"`;
`unix2dos \"${rdir}/README.txt\"`;
`cp win32/docs/README-win32.txt \"${rdir}\"`;
`cp NEWS.txt \"${rdir}\"`;
`unix2dos \"${rdir}/NEWS.txt\"`;
`cp licenses/cpl1.0.txt \"${rdir}/licenses\"`;
`unix2dos \"${rdir}/licenses/cpl1.0.txt\"`;
`cp licenses/IBM-LICENSE \"${rdir}/licenses\"`;
`unix2dos \"${rdir}/licenses/IBM-LICENSE\"`;

# MS Redist dlls and manifest
`cp \"${REDIST_LOC}\"/* \"${rdir}/bin\"`;
print "******* Using Updated Manifest File *******\n";
`cp \"${RELDIR}/Microsoft.VC90.CRT.manifest\" \"${rdir}/bin\"`;

# Zip up the files - move there to make the path in the zip short
chdir ("$RELDIR") or die "Error changing directories to $RELDIR";
`zip -r ${rfile}.zip ${rfile}`;

die "ZIP file not created" unless (-e "${rfile}.zip");

print "File saved as ${rfile}.zip\n";

