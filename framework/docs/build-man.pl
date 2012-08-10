#!/usr/bin/perl -w

# uses pandoc (http://johnmacfarlane.net/pandoc/) to
# generate man and html pages for the tools in the
# framework.
#
# Stores the results in the man folder
use strict;

die "pandoc not found" unless (-x "/usr/local/bin/pandoc");

opendir (DIR, ".") or die "Error opening docs folder";
while (my $f = readdir(DIR)) {    
    next unless ($f =~ /^(.*?)\.1\.md$/);
    my $f1 = $1;
    system("pandoc -s -w man ${f} -o ../man/${f1}\.1");
    system("pandoc -s --toc ${f} -o ../man/${f1}\.html");
}
closedir (DIR);
