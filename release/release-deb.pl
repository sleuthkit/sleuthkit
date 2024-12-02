#!/usr/bin/perl

# Makes deb file based on release tag
# 

use strict;

my $TESTING = 0;
print "TESTING MODE (no commits)\n" if ($TESTING);

unless (@ARGV == 1) {
	print stderr "Missing arguments: version\n";
	print stderr "    for example: release-deb.pl 3.1.0\n";
	exit(1);
}

my $RELDIR = `pwd`;	# The release directory
chomp $RELDIR;
my $TSKDIR = "$RELDIR/../";

my $VER = $ARGV[0];
my $TAGNAME = "sleuthkit-${VER}";

my $TAR1FILE = "${TSKDIR}/../sleuthkit-java_${VER}.orig.tar.xz";
my $TAR2FILE = "${TSKDIR}/../sleuthkit-java_${VER}.debian.tar.xz";
my $DEBFILE = "${TSKDIR}/../sleuthkit-java_${VER}-1_amd64.deb";
my $BUILDFILE = "${TSKDIR}/../sleuthkit-java_${VER}-1_amd64.build";
my $BUILDINFOFILE = "${TSKDIR}/../sleuthkit-java_${VER}-1_amd64.buildinfo";
my $CHANGESFILE = "${TSKDIR}/../sleuthkit-java_${VER}-1_amd64.changes";
my $DSCFILE = "${TSKDIR}/../sleuthkit-java_${VER}-1.dsc";
my $DDEBFILE = "${TSKDIR}/../sleuthkit-java-dbgsym_${VER}-1_amd64.ddeb";

die ("ERROR: ${TAR1FILE} file already exists") if (-e ${TAR1FILE});
die ("ERROR: ${TAR2FILE} file already exists") if (-e ${TAR2FILE});
die ("ERROR: ${DEBFILE} file already exists") if (-e ${DEBFILE});
die ("ERROR: ${BUILDFILE} file already exists") if (-e ${BUILDFILE});
die ("ERROR: ${BUILDINFOFILE} file already exists") if (-e ${BUILDINFOFILE});
die ("ERROR: ${CHANGESFILE} file already exists") if (-e ${CHANGESFILE});
die ("ERROR: ${DSCFILE} file already exists") if (-e ${DSCFILE});



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

	`git reset --hard HEAD > /dev/null`;
	# Make sure we have no changes in the current tree
	exec_pipe(*OUT, "git status -s | grep \"^ M\"");
	my $foo = read_pipe_line(*OUT);
	if ($foo ne "") {
	    print "Changes stil exist in current repository -- commit them\n";
	    die "stopping";
	}

	# Make sure src dir is up to date
	print "Updating source directory\n";
	`git checkout develop`;
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


# Make deb
sub build_deb {
	print "Running bootstrap\n";
	`rm configure`;
	`./bootstrap`;
	die ("Configure missing") unless (-e "configure");


	print "Running 'dh_make'. Ignore messages about overwriting, and it's OK if it goes blank\n";
	`dh_make --s -y -e \“info\@sleuthkit.org\” -p sleuthkit-java_${VER} --createorig`;

	die ("ERROR: ${TAR1FILE} file not created") unless (-e ${TAR1FILE});

	print "Running debuild\n";
	`debuild -us -uc`;
	if (-e ${DEBFILE}) {
		print "${DEBFILE} created\n";
	} else {
		die "deb file was not created\n";
	}
}

sub cleanup {
	print "Removing intermediate files\n";
	`rm -f $TAR1FILE`;
	`rm -f $TAR2FILE`;
	`rm -f $BUILDFILE`;
	`rm -f $BUILDINFOFILE`;
	`rm -f $CHANGESFILE`;
	`rm -f $DSCFILE`;
	`rm -f $DDEBFILE`;
}


##############################

chdir ("$TSKDIR") or die "Error changing to TSK dir $TSKDIR";

update_code();
build_deb();
cleanup();
