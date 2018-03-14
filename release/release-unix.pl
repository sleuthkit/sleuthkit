#!/usr/bin/perl

# Unix release script for TSK. This creates the SVN tag directory
# and then updates the needed version numbers. It also double checks
# that everything compiles. 
# 
# It must be run from a Unix-like system.  It is currently being used
# on OS X, but other systems should work. 

use strict;
use File::Copy;

# global variables
my $VER;
my $TSK_RELNAME; # sleuthkit-${VER}
my $RELDIR;     # full path release folder
my $GITDIR;
my $CLONEDIR;   # where a fresh copy of the repo was cloned to.
my $TARBALL;
my $BRANCH;

my $TESTING = 0;
print "TESTING MODE (no commits)\n" if ($TESTING);

my $CI = 0;   # Continous Integration Run

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


# Creates clean clone repo and goes into it.
sub clone_repo() {
    del_clone();

    # CI makes not changes, so use http version
    if ($CI) {
        system ("git clone https://github.com/sleuthkit/sleuthkit.git ${CLONEDIR}");
    } else {
        system ("git clone git\@github.com:sleuthkit/sleuthkit.git ${CLONEDIR}");
    }
    chdir "${CLONEDIR}" or die "Error changing into $CLONEDIR";

    system ("git checkout ${BRANCH}");
}

# Deletes the clone directory -- if it exists
sub del_clone() {
    if (-d "$CLONEDIR") {
        system ("rm -rf ${CLONEDIR}");
    }
}


# Verify that all files in the current source directory
# are checked in.  dies if any are modified.
sub verify_precheckin {

    #system ("git pull");

    print "Verifying everything is checked in\n";
    exec_pipe(*OUT, "git status -s | grep \"^ M\"");

    my $foo = read_pipe_line(*OUT);
    if ($foo ne "") {
        print "Files not checked in\n";
        while ($foo ne "") {
            print "$foo";
            $foo = read_pipe_line(*OUT);
        }
        die "stopping" unless ($TESTING);
    }
    close(OUT);

    print "Verifying everything is pushed\n";
    exec_pipe(*OUT, "git status -sb | grep \"^##\" | grep \"ahead \"");
    my $foo = read_pipe_line(*OUT);
    if ($foo ne "") {
            print "$foo";
        print "Files not pushed to remote\n";
        die "stopping" unless ($TESTING);
    }
    close(OUT);
}

# Create a tag 
sub tag_dir {
    unless ($TESTING) {
        print "Generating signed tag.\n"; 
        system ("git tag -s ${TSK_RELNAME} -m \"Tag for release ${TSK_RELNAME}\"");
        system ("git push origin ${TSK_RELNAME}");
    }
}

# Commit the updated version info in the current source directory
sub checkin_vers {
    unless ($TESTING) {
        print "Checking in version updates to current branch\n";
        system ("git commit -a -m \"New version files for ${VER}\"");
        system ("git push origin ${BRANCH}");
    }
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
        die "$found (instead of 1) occurrences of AC_INIT found in configure.ac";
    }

    unlink ("configure.ac") or die "Error deleting configure.ac";
    rename ("configure2.ac", "configure.ac") or die "Error renaming tmp configure.ac file";
}

# Update the version in the .h file in current source directory
sub update_hver {

    print "Updating the version in tsk_base.h\n";
    
    open (CONF_IN, "<tsk/base/tsk_base.h") or die "Cannot open tsk/base/tsk_base.h";
    open (CONF_OUT, ">tsk/base/tsk_base2.h") or die "Cannot open tsk/base/tsk_base2.h";

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
        die "$found (instead of 2) occurrences of VERSION in tsk_base.h";
    }

    unlink ("tsk/base/tsk_base.h") or die "Error deleting tsk/base/tsk_base.h";
    rename ("tsk/base/tsk_base2.h", "tsk/base/tsk_base.h") or die "Error renaming tmp tsk/base/tsk_base.h file";
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
        die "Error: Found $found (instead of 1) occurrences of Version: in RPM spec file";
    }

    unlink ($IFILE) or die "Error deleting $IFILE";
    rename ($OFILE, $IFILE) or die "Error renaming $OFILE";
}

# Update the version in the library in current source directory
# note that this version is independent from the
# release version.
sub update_libver {
    return if ($CI);

    print "Updating Unix API version\n";

    print "\nGit History for tsk/Makefile.am:\n";
    exec_pipe(*OUT, "git log -- --pretty=short tsk/Makefile.am | head -12");
    my $foo = read_pipe_line(*OUT);
    while ($foo ne "") {
        print "$foo";
        $foo = read_pipe_line(*OUT);
    }
    close(OUT);

    my $a;
    while (1) {
        $a = prompt_user("Update this version (no if this is a restart or you already did it) [y/n]");
        last if (($a eq "n") || ($a eq  "y"));
        print "Invalid response: $a\n";
    }
    return if ($a eq "n");

    exec_pipe(*OUT, "cat tsk/Makefile.am | grep version\-info");
    print "Current Makefile Contents: " . read_pipe_line(*OUT) . "\n";
    close (OUT);


    my $cur;
    my $rev;
    my $age;
    while (1) {
        $a = prompt_user("Enter library version used in last release (from tsk/Makefile.am)");
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
        $irem = prompt_user("Have any interfaces been removed or changed? [y/n]");
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

    my $IFILE = "tsk/Makefile.am";
    my $OFILE = "tsk/Makefile.am2";

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
        die "Error: Found only $found (instead of 1) occurrences of version-info lib makefile";
    }

    unlink ($IFILE) or die "Error deleting $IFILE";
    rename ($OFILE, $IFILE) or die "Error renaming $OFILE";
}


# Update the autotools / autobuild files in current source directory
sub bootstrap() {
    print "Updating local makefiles with version info\n";

    unlink ("./configure");
    unlink ("./Makefile");

    system ("./bootstrap");
    die ("configure missing after bootstrap") unless (-x  "./configure");

    system ("./configure > /dev/null");
    die ("makefile missing after ./configure") unless (-e "./Makefile");
}


# Make the tarball using make in current source directory
sub make_tar {
    unlink $TARBALL if (-e $TARBALL);
    system ("make dist > /dev/null");
    die "Missing $TARBALL after make dist" unless (-e $TARBALL);
}

# Compiles the framework to verify it is all good
sub compile_framework() {
    chdir ("framework") or die "error changing into framework";

    print "Running bootstrap\n";
    system ("./bootstrap");
    die "Error running bootstrap in framework" unless (-e "./configure");

    print "Running configure\n";
    system ("./configure > /dev/null");
    die "Error running framework configure in tar file" unless (-e "./Makefile");

    print "Running make\n";
    system ("make > /dev/null");
    die "Error compiling framework" unless ((-e "tools/tsk_analyzeimg/tsk_analyzeimg") && (-e "runtime/modules/libtskEntropyModule.a"));
    chdir "..";
}

# Verify that the tar ball contains all of the
# expected files
# Starts and ends in the clone dir
sub verify_tar {
    copy ("${TARBALL}", "/tmp/${TARBALL}") or die "error renaming sleuthkit tar ball";

    chdir ("/tmp/") or die "Error changing directory to /tmp";

    # remove existing directory
    system ("rm -rf ${TSK_RELNAME}") if (-d "${TSK_RELNAME}");

    # open new one
    system ("tar xfz ${TARBALL}");
    die "Error opening .tgz file.  Directory does not exist." unless (-d "${TSK_RELNAME}");

    exec_pipe(*OUT, 
    "diff -r ${CLONEDIR} ${TSK_RELNAME} | grep -v \.git | grep -v Makefile | grep -v \.deps | grep -v gdb_history | grep -v bootstrap | grep -v libtool | grep -v DS_Store | grep -v config.h | grep -v build-html | grep -v autom4te.cache | grep -v config.log | grep -v config.status | grep -v stamp-h1 | grep -v xcode | grep -v win32\/doc | grep -v release | grep -v \"\\.\\#\"");

    my $a = "y";
    my $foo = read_pipe_line(*OUT);
    if ($foo ne "") {
        do {
            print "$foo";
            $foo = read_pipe_line(*OUT);
        } while ($foo ne "");
        print "The above files are diffs between the source dir and opened tar file\n";
        if ($CI) {
            die "Files were missing from tar file";
        } else {
            while (1) {
                $a = prompt_user ("Continue? [y/n]");
                last if (($a eq "y") || ($a eq "n"));
                print "Invalid answer\n";
            }
        }
    }
    close (OUT);

    print "Compiling package to ensure that it all works\n";
    # Compile to see if it all works
    chdir ("${TSK_RELNAME}") or die "error changing into $TSK_RELNAME";

    die "Missing configure in tar file" unless (-e "./configure");

    print "Running configure\n";
    system ("./configure > /dev/null");
    die "Error running configure in tar file" unless (-e "./Makefile");

    print "Running make\n";
    system ("make > /dev/null");
    die "Error compiling tar file (tools/fstools/fls not found)" unless (-x "tools/fstools/fls");

    print "Testing Test\n";
    chdir "tests" or die "Error changing directories to test";
    system ("make check > /dev/null");
    die "Error compiling tests (tests/read_apis not found)" unless (-x "read_apis");
    chdir "..";

    print "Building Java JAR\n";
    chdir "bindings/java" or die "Error changing directories to java";
    system ("ant");
    die "Error making jar file (bindings/java/dist/sleuthkit-*.jar not found)" unless (glob("dist/sleuthkit-*.jar"));
    chdir "../..";

    # Compile the framework
    # compile_framework();

    # We're done.  Clean up
    chdir "..";
    system ("rm -rf ${TSK_RELNAME}");
    system ("rm ${TARBALL}");

    chdir "${CLONEDIR}" or die "Error changing dirs back to ${RELDIR}";

    # stop if asked to
    die ("Stopping") if $a eq "n";
}



sub copy_tar() {
    copy ("${TARBALL}", "$RELDIR") or die "error moving sleuthkit tar ball to release folder";
    print "File saved as ${TARBALL} (in release folder)\n";
}


####################################################
# release workflow

# Get the version argument
if (scalar (@ARGV) != 1) {
    print stderr "Missing release version argument (i.e.  3.0.1)\n";
    print stderr "Makes a release of the current branch\n";
    print stderr "  Or: ci as argument\n";
    exit;
}

$VER = $ARGV[0];
if ($VER eq "ci") {
  $VER = "0.0.0";
  $CI = 1;
  $TESTING = 1;
} elsif  ($VER =~ /^\d+\.\d+\.\d+(b\d+)?$/) {
   # Nothing to do
} else {
    die "Invalid version number: $VER (1.2.3 or 1.2.3b1 expected)";
}

$TSK_RELNAME = "sleuthkit-${VER}";
$TARBALL = "${TSK_RELNAME}.tar.gz";
$RELDIR = `pwd`;
chomp ($RELDIR);
$GITDIR = "$RELDIR/..";
$CLONEDIR = "$RELDIR/clone";


# Get the current branch name
exec_pipe(*OUT, "git branch | grep \"^\*\"");
my $foo = read_pipe_line(*OUT);
if ($foo =~ /^\* (.+)$/) {
    $BRANCH = $1;
    print "Making release from branch: ${BRANCH}\n";
}
else {
    print "Error parsing current branch name: $foo";
    die "stopping";
}
close(OUT);

unless ($CI) {
    # Verify the tag doesn't already exist
    exec_pipe(*OUT, "git tag | grep \"${TSK_RELNAME}\$\"");
    my $foo = read_pipe_line(*OUT);
    if ($foo ne "") {
        print "Tag ${TSK_RELNAME} already exists\n";
        print "Remove with 'git tag -d ${TSK_RELNAME}'\n";
        die "stopping";
    }
    close(OUT);
}

chdir ".." or die "Error changing directories to root";
verify_precheckin();
chdir "$RELDIR" or die "error changing back into release";


# Make a new clone of the repo
clone_repo();

# Update the version info in that tag
update_configver();
update_hver();
update_libver();
update_pkgver();

bootstrap();
checkin_vers();

unless ($CI) {
    my $a;
    while (1) {
        $a = prompt_user("Tag and release? (or stop if only updating version in branch) [y/n]");
        last if (($a eq "n") || ($a eq "y"));
        print "Invalid response: $a\n";
    }
    exit if ($a eq "n");

    # Create a tag 
    tag_dir();
}

make_tar();
verify_tar();

copy_tar();
unless ($CI) {
    print "You still need to merge into master and develop from the clone\n";
}

