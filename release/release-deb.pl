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
#my $TSKDIR = "$RELDIR/../";
my $TSKDIR = "$RELDIR/sleuthkit/";

my $VER = $ARGV[0];
my $TAGNAME = "sleuthkit-${VER}";
my $TARFILE = "${TSKDIR}/../sleuthkit-java_${VER}.orig.tar.xz";
my $DEBFILE = "${TSKDIR}/../sleuthkit-java_${VER}-1_amd64.deb";
die ("ERROR: ${TARFILE} file already exists") if (-e ${TARFILE});
die ("ERROR: ${DEBFILE} file already exists") if (-e ${DEBFILE});



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

	die ("ERROR: ${TARFILE} file not created") unless (-e ${TARFILE});

	print "Running debuild\n";
	`debuild -us -uc`;
	if (-e ${DEBFILE}) {
		print "${DEBFILE} created\n";
	} else {
		die "deb file was not created\n";
	}
}


##############################

chdir ("$TSKDIR") or die "Error changing to TSK dir $TSKDIR";

update_code();
build_deb();
