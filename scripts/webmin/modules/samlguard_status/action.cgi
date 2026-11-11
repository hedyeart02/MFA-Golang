#!/usr/bin/perl
require './samlguard-lib.pl';
&ReadParse();

if ($ENV{'REQUEST_METHOD'} ne 'POST') {
	&error('Invalid request method (POST required)');
}

my $action = $in{'action'} || '';
my %allowed = (
	'start'   => 'start',
	'stop'    => 'stop',
	'restart' => 'restart',
	'enable'  => 'enable',
	'disable' => 'disable',
);

if (!$allowed{$action}) {
	&error('Unknown action');
}

my $cfg = &sg_cfg();
my $systemctl = &sg_find_bin('systemctl');
if (!$systemctl) {
	&redirect('index.cgi?err=' . &urlize('systemctl was not found on this host'));
	exit;
}

my ($rc, $out) = &sg_run_cmd($systemctl, $allowed{$action}, $cfg->{'service_name'});
if ($rc == 0) {
	&webmin_log($action, 'service', $cfg->{'service_name'});
	&redirect('index.cgi?msg=' . &urlize("Action '$action' completed for $cfg->{'service_name'}"));
} else {
	$out =~ s/\r?\n/ /g;
	&redirect('index.cgi?err=' . &urlize("Action '$action' failed: $out"));
}
