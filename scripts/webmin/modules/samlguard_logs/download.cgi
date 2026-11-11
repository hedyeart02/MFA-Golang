#!/usr/bin/perl
BEGIN { push(@INC, ".."); }
use WebminCore;
&init_config();
&foreign_require("samlguard_status", "samlguard-lib.pl");

my $cfg = &samlguard_status::sg_cfg();
my $journalctl = &samlguard_status::sg_find_bin('journalctl');
my $out = '';
if ($journalctl) {
	(undef, $out) = &samlguard_status::sg_run_cmd($journalctl, '-u', $cfg->{'service_name'}, '-n', '1000', '--no-pager');
} else {
	$out = "journalctl not found on this host.\n";
}

print "Content-Type: text/plain; charset=utf-8\n";
print "Content-Disposition: attachment; filename=\"samlguard-logs.txt\"\n\n";
print $out;
