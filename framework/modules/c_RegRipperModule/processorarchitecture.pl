#-----------------------------------------------------------
# processorarchitecture.pl
#
# copyright 2012 Basis Technology
#-----------------------------------------------------------
package processorarchitecture;
use strict;

my %config = (hive          => "System",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20121109);

sub getConfig{return %config}

sub getShortDescr {
	return "Get the processor architecture of the os";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching processorarchitecture v.".$VERSION);
    ::rptMsg("processorarchitecture v.".$VERSION); # 20110830 [fpi] + banner
    ::rptMsg("(".getHive().") ".getShortDescr()."\n"); # 20110830 [fpi] + banner

	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

# Code for System file, getting CurrentControlSet
 my $current;
	my $key_path = 'Select';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		$current = $key->get_value("Current")->get_data();
		
		my $env_path = "ControlSet00".$current."\\Control\\Session Manager\\Environment";
		my $env;
		if ($env = $root_key->get_subkey($env_path)) {
			
			eval {
				my $architecture = $env->get_value("PROCESSOR_ARCHITECTURE")->get_data();
				::rptMsg("ProcessorArchitecture = ".$architecture);
			};
			::rptMsg($@) if ($@);
			
		}	
		else {
			::rptMsg($env_path." not found.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
		::logMsg($key_path." not found.");
	}
}
1;
