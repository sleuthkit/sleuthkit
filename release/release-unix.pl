#!/usr/bin/perl

# Unix release script for TSK. This creates the SVN tag directory
# and then updates the needed version numbers. It also double checks
# that everything compiles. 
# 
# It must be run from a Unix-like system.  It is currently being used
# on OS X, but other systems should work. 
#

use strict;

# global variables
my $VER;
my $TSK_RELDIR;
my $RELDIR;
my $SVNDIR;
my $TARBALL;
my $BRANCH;

my $TESTING = 0;
print "TESTING MODE (no commits)" if ($TESTING);

######################################################
# Utility functions


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


# Prompt user for argument and return response
sub prompt_user {
    my $q = shift(@_);
    print "$q: ";
    $| = 1;
    $_ = <STDIN>;
    chomp;
    return $_;
}



#####################################################
# release functions

# Get rid of the extra files in current source directory
sub clean_src() {
    print "Cleaning source code\n";
    system ("make clean > /dev/null");
}

# Verify that all files in the current source directory
# are checked in.  dies if any are modified.
sub verify_precheckin {
    print "Verifying everything is checked in\n";
    exec_pipe(*OUT, "svn -q status | grep \"^M\"");

    my $foo = read_pipe_line(*OUT);
    if ($foo ne "") {
        print "Files not checked in\n";
        while ($foo ne "") {
            print "$foo";
            $foo = read_pipe_line(*OUT);
        }
        die "stopping";
    }
    close(OUT);
}

# Create a tag and jump into that directory
sub tag_dir {

    chdir "${SVNDIR}" or die "Error changing directories to ${SVNDIR}";

    print "Tagging release\n";
    system ("svn copy ${BRANCH} tags/${TSK_RELDIR}");
    die "Error creating tag" unless (-d "tags/${TSK_RELDIR}");
    system ("svn -q commit -m \"Release ${VER} from ${BRANCH}\" tags/${TSK_RELDIR}") unless ($TESTING);

    chdir ("tags/${TSK_RELDIR}") or die "Error changing into tag directory tags/${TSK_RELDIR}";
    print "Updating tag directory\n";
    system ("svn update") unless ($TESTING);
}

# Commit the updated version info in the current source directory
sub checkin_vers {
    print "Checking in version updates\n";
    system ("svn -q commit -m \"New version files for ${VER}\"")
	unless ($TESTING);
}

# update the version in configure.ac in current source directory
sub update_configver {

    print "Updating the version in configure.ac\n";
    
    open (CONF_IN, "<configure.ac") or die "Cannot open configure.ac";
    open (CONF_OUT, ">configure2.ac") or die "Cannot open configure2.ac";

    my $found = 0;
    while (<CONF_IN>) {
        if (/^AC_INIT\(sleuthkit/) {
            print CONF_OUT "AC_INIT(sleuthkit, $VER)\n";
            $found++;
        }
        else {
            print CONF_OUT $_;
        }
    }
    close (CONF_IN);
    close (CONF_OUT);

    if ($found != 1) {
        die "$found (instead of 1) occurances of AC_INIT found in configure.ac";
    }

    unlink ("configure.ac") or die "Error deleting configure.ac";
    rename ("configure2.ac", "configure.ac") or die "Error renaming tmp configure.ac file";
}

# Update the version in the .h file in current source directory
sub update_hver {

    print "Updating the version in tsk_base.h\n";
    
    open (CONF_IN, "<tsk3/base/tsk_base.h") or die "Cannot open tsk3/base/tsk_base.h";
    open (CONF_OUT, ">tsk3/base/tsk_base2.h") or die "Cannot open tsk3/base/tsk_base2.h";

    my $found = 0;
    while (<CONF_IN>) {
        if (/^#define\s+TSK_VERSION_NUM\s+0x/) {
            my $vstr = "0x";
            if ($VER =~ /^(\d+)\.(\d+)\.(\d+)/) {
                if (($1 > 99) || ($2 > 99) || ($3 > 99)) {
                    die "version has numbers larger than 99";
                }
                $vstr .= "0" if ($1 <= 9);
                $vstr .= $1;
                $vstr .= "0" if ($2 <= 9);
                $vstr .= $2;
                $vstr .= "0" if ($3 <= 9);
                $vstr .= $3;
                if ($VER =~ /b(\d+)$/) {
                    if ($1 > 99)  {
                        die "version has numbers larger than 99";
                    }
                    $vstr .= "0" if ($1 <= 9);
                    $vstr .= $1;
                }
                else {
                    $vstr .= "ff";
                }
            }
            else {
                die "Error parsing version number $VER";
            }

            print CONF_OUT "#define TSK_VERSION_NUM $vstr\n";
            $found++;
        }
        elsif (/^#define\s+TSK_VERSION_STR\s+\"\d/) {
            print CONF_OUT "#define TSK_VERSION_STR \"$VER\"\n";
            $found++;
        }
        else {
            print CONF_OUT $_;
        }
    }
    close (CONF_IN);
    close (CONF_OUT);

    if ($found != 2) {
        die "$found (instead of 2) occurances of VERSION in tsk_base.h";
    }

    unlink ("tsk3/base/tsk_base.h") or die "Error deleting tsk3/base/tsk_base.h";
    rename ("tsk3/base/tsk_base2.h", "tsk3/base/tsk_base.h") or die "Error renaming tmp tsk3/base/tsk_base.h file";
}

# update the version in libaux vs files in current source directory
sub update_vsver {

    print "Updating the version in libauxtools\n";
    
    my $IFILE = "win32/libauxtools/libauxtools.vcproj";
    my $OFILE = "win32/libauxtools/libauxtools.vcproj2";

    open (CONF_IN, "<${IFILE}") or 
        die "Cannot open $IFILE";
    open (CONF_OUT, ">${OFILE}") or 
        die "Cannot open $OFILE";

    my $found = 0;
    while (<CONF_IN>) {
        if (/^(\s+PreprocessorDefinitions.*?PACKAGE_VERSION=\\&quot;).*(\\&quot;.*?)$/) {
            print CONF_OUT "$1${VER}$2\n";
            $found++;
        }
        else {
            print CONF_OUT $_;
        }
    }
    close (CONF_IN);
    close (CONF_OUT);

    if ($found != 3) {
        die "Error: Found $found (instead of 3) occurances of PACKAGE_VERSION in libauxtools visual studio files";
    }

    unlink ($IFILE) or die "Error deleting $IFILE";
    rename ($OFILE, $IFILE) or die "Error renaming $OFILE";
}

# update the version in the package files in current source directory
sub update_pkgver {

    print "Updating the version in RPM spec file\n";
    
    my $IFILE = "packages/sleuthkit.spec";
    my $OFILE = "packages/sleuthkit.spec2";

    open (CONF_IN, "<${IFILE}") or 
        die "Cannot open $IFILE";
    open (CONF_OUT, ">${OFILE}") or 
        die "Cannot open $OFILE";

    my $found = 0;
    while (<CONF_IN>) {
        if (/^(Version:\s+)[\d\.]+\s*/) {
            print CONF_OUT "$1${VER}\n";
            $found++;
        }
        else {
            print CONF_OUT $_;
        }
    }
    close (CONF_IN);
    close (CONF_OUT);

    if ($found != 1) {
        die "Error: Found $found (instead of 1) occurances of Version: in RPM spec file";
    }

    unlink ($IFILE) or die "Error deleting $IFILE";
    rename ($OFILE, $IFILE) or die "Error renaming $OFILE";
}

# Update the version in the library in current source directory
# note that this version is independent from the
# release version.
sub update_libver {
    print "Updating library version\n";

    my $a;
    while (1) {
        $a = prompt_user("Update the library version (no if this is a restart) [y/n]");
        last if (($a eq "n") || ($a eq  "y"));
        print "Invalid response: $a\n";
    }
    return if ($a eq "n");

    my $cur;
    my $rev;
    my $age;
    while (1) {
        $a = prompt_user("Enter library version used in last release (from tsk3/Makefile.am)");
        if ($a =~ /(\d+):(\d+):(\d+)/) {
            $cur = $1;
            $rev = $2;
            $age = $3;
            last;
        }
        print "Invalid response: $a (should be 1:2:3)\n";
    }

    my $irem;
    while (1) {
        $irem = prompt_user("Have any interfaces been removed? [y/n]");
        last if (($irem eq "n") || ($irem eq  "y"));
        print "Invalid response: $irem\n";
    }

    my $iadd = "n";
    my $ichg = "n";
    if ($irem eq "n") {
        while (1) {
            $iadd = prompt_user("Have any interfaces been added? [y/n]");
            last if (($iadd eq "n") || ($iadd eq  "y"));
            print "Invalid response: $iadd\n";
        }

        if ($iadd eq "n") {
            while (1) {
                $ichg = prompt_user("Have any interfaces been changed? [y/n]");
                last if (($ichg eq "n") || ($ichg eq  "y"));
                print "Invalid response: $ichg\n";
            }
        }
    }

    my $IFILE = "tsk3/Makefile.am";
    my $OFILE = "tsk3/Makefile.am2";

    open (CONF_IN, "<${IFILE}") or 
        die "Cannot open $IFILE";
    open (CONF_OUT, ">${OFILE}") or 
        die "Cannot open $OFILE";

    my $found = 0;
    while (<CONF_IN>) {
        if (/^(libtsk.*?version\-info )\d+:\d+:\d+(.*?)$/) {
            if ($irem eq "y") {
                $cur++;
                $rev = 0;
                $age = 0;
            }
            elsif ($iadd eq "y") {
                $cur++;
                $rev = 0;
                $age++;
            }
            elsif ($ichg eq "y") {
                $cur++;
                $rev = 0;
            }
            else {
                $rev++;
            }
            print CONF_OUT "$1${cur}:${rev}:${age}$2\n";
            $found++;
        }
        else {
            print CONF_OUT $_;
        }
    }
    close (CONF_IN);
    close (CONF_OUT);

    if ($found != 1) {
        die "Error: Found only $found (instead of 1) occurances of version-info lib makefile";
    }

    unlink ($IFILE) or die "Error deleting $IFILE";
    rename ($OFILE, $IFILE) or die "Error renaming $OFILE";
}


# Update the autotools / autobuild files in current source directory
sub update_build() {
    print "Updating local makefiles\n";

    unlink ("./configure");
    system ("./bootstrap");
    die ("configure missing after bootstrap") unless (-x  "./configure");

    unlink ("./Makefile");
    system ("./configure > /dev/null");
    die ("makefile missing after ./configure") unless (-e "./Makefile");
}


# Make the tarball using make in current source directory
sub make_tar {
    unlink $TARBALL if (-e $TARBALL);
    system ("make dist > /dev/null");
    die "Missing $TARBALL" unless (-e $TARBALL);
}

# Verify that the tar ball contains all of the
# expected files
sub verify_tar {
    rename ("${TARBALL}", "${RELDIR}/${TARBALL}") or die "error renaming sleuthkit tar ball";

    chdir ("${RELDIR}") or die "Error changing directory to ${RELDIR}";

    # remove existing directory
    system ("rm -rf ${TSK_RELDIR}") if (-d "${TSK_RELDIR}");

    # open new one
    system ("tar xfz ${TARBALL}");
    die "Missing dist dir in release" unless (-d "${TSK_RELDIR}");

    exec_pipe(*OUT, 
    "diff -r ${SVNDIR}/${BRANCH} ${TSK_RELDIR} | grep -v \.svn | grep -v Makefile | grep -v \.deps | grep -v gdb_history | grep -v bootstrap | grep -v libtool | grep -v DS_Store | grep -v config.h | grep -v build-html | grep -v autom4te.cache | grep -v config.log | grep -v config.status | grep -v stamp-h1 | grep -v xcode | grep -v win32\/doc | grep -v \"\\.\\#\"");

    my $a = "y";
    my $foo = read_pipe_line(*OUT);
    if ($foo ne "") {
        do {
            print "$foo";
            $foo = read_pipe_line(*OUT);
        } while ($foo ne "");
        print "The above files are diffs between the source dir and opened tar file\n";
        while (1) {
            $a = prompt_user ("Continue? [y/n]");
            last if (($a eq "y") || ($a eq "n"));
            print "Invalid answer\n";
        }
    }
    close (OUT);

    print "Compiling package to ensure that it all works\n";
    # Compile to see if it all works
    chdir ("${TSK_RELDIR}") or die "error changing into $TSK_RELDIR";

    die "Missing configure in tar file" unless (-e "./configure");

    print "Running configure\n";
    system ("./configure > /dev/null");
    die "Error running configure in tar file" unless (-e "./Makefile");

    print "Running make\n";
    system ("make > /dev/null");
    die "Error compiling tar file" unless ((-x "tools/fstools/fls") && (-x "tests/read_apis"));

    chdir "..";

    system ("rm -rf ${TSK_RELDIR}");

    chdir "${SVNDIR}/${BRANCH}" or die "Error changing dirs back to ${SVNDIR}/${BRANCH}";

    # stop if asked to
    die ("Stopping") if $a eq "n";
}


####################################################
# release workflow

# Get the version argument
if (scalar (@ARGV) != 2) {
    print stderr "Missing branch and version argument (branches/sleuthkit-3.0 3.0.1)\n";
    print stderr "\tbranch: Branch to release from\n";
    print stderr "\tversion: Version of release\n";
    exit;
}
$BRANCH = $ARGV[0];

$VER = $ARGV[1];
unless ($VER =~ /^\d+\.\d+\.\d+(b\d+)?$/) {
    die "Invalid version number: $VER (1.2.3 or 1.2.3b1 expected)";
}
$TSK_RELDIR = "sleuthkit-${VER}";
$TARBALL = "${TSK_RELDIR}.tar.gz";

$RELDIR = `pwd`;
chomp ($RELDIR);
$SVNDIR = "$RELDIR/..";

die "branch directory ${BRANCH} missing" 
	unless (-d "${SVNDIR}/${BRANCH}");

die "tag directory ${TSK_RELDIR} already exists" 
	if (-e "${SVNDIR}/tags/${TSK_RELDIR}");

chdir "${SVNDIR}/${BRANCH}" or die "Error changing directories to ${SVNDIR}/${BRANCH}";

# All of these die of they need to abort
clean_src();
verify_precheckin();

# Create a tag and jump into that directory
tag_dir();

# Update the version info in that tag
update_configver();
# update_vsver();
update_hver();
update_libver();
update_pkgver();
update_build();

checkin_vers();

make_tar();
verify_tar();

print "File saved as ${TARBALL}\n";
