#!/usr/bin/perl
BEGIN { push(@INC, ".."); }
use WebminCore;
&init_config();
&foreign_require("samlguard_status", "samlguard-lib.pl");

if ($ENV{'REQUEST_METHOD'} ne 'POST') {
	&error('Invalid request method (POST required)');
}

&ReadParseMime(2097152);

my $cfg = &samlguard_status::sg_cfg();
my $cert_dir = $cfg->{'cert_dir'};

my $data = $in{'certfile'};
my $fname = $in{'target_name'} || $in{'certfile_filename'} || '';
$fname =~ s/^.*[\\\/]//;
$fname =~ s/^\s+|\s+$//g;

if (!defined($data) || $data eq '') {
	&redirect('index.cgi?err=' . &urlize('No file content uploaded'));
	exit;
}

if ($fname eq '' || $fname =~ /\.\./ || $fname !~ /^[A-Za-z0-9._-]+$/) {
	&redirect('index.cgi?err=' . &urlize('Invalid filename. Use only letters, numbers, dots, underscores, and hyphens.'));
	exit;
}

if (!-d $cert_dir) {
	mkdir($cert_dir, 0700) or &error("Failed to create $cert_dir: $!");
	&samlguard_status::sg_chown_service_user($cert_dir);
}

my $dest = "$cert_dir/$fname";
&lock_file($dest);
open(my $fh, '>', $dest) or &error("Failed to write $dest: $!");
binmode($fh);
print $fh $data;
close($fh);

my $mode = ($fname =~ /\.(key|pem)$/i) ? 0600 : 0644;
chmod($mode, $dest);
&samlguard_status::sg_chown_service_user($dest);
&unlock_file($dest);

&webmin_log('upload', 'cert', $dest);
&redirect('index.cgi?msg=' . &urlize("Uploaded $fname to $cert_dir. Restart SAMLGuard in Status if replacing active certificates."));
