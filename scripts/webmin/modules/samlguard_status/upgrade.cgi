#!/usr/bin/perl
BEGIN { push(@INC, ".."); }
use WebminCore;
use File::Temp qw(tempdir);
use File::Copy qw(copy);
&init_config();
&foreign_require("samlguard_status", "samlguard-lib.pl");

if ($ENV{'REQUEST_METHOD'} ne 'POST') {
	&error('Invalid request method (POST required)');
}

# Allow up to 100 MB upload for release .tar.gz or compiled binary
&ReadParseMime(104857600);

my $cfg = &samlguard_status::sg_cfg();
my $data = $in{'package'};
my $fname = $in{'package_filename'} || '';
$fname =~ s/^.*[\\\/]//;
$fname =~ s/^\s+|\s+$//g;

if (!defined($data) || $data eq '') {
	&redirect('index.cgi?err=' . &urlize('No upgrade file uploaded. Select a .tar.gz release archive or samlguard binary.'));
	exit;
}

my $tmpdir = tempdir(CLEANUP => 1);
my $upload_path = "$tmpdir/upload.bin";
open(my $ufh, '>', $upload_path) or &error("Failed to write temporary upload: $!");
binmode($ufh);
print $ufh $data;
close($ufh);

my $new_bin = '';
my $new_unit = '';

# Detect gzip (.tar.gz / .tgz) by magic bytes or filename
my $is_gzip = ($fname =~ /\.(tar\.gz|tgz)$/i || substr($data, 0, 2) eq "\x1f\x8b") ? 1 : 0;

if ($is_gzip) {
	my $tar = &samlguard_status::sg_find_bin('tar');
	if (!$tar) {
		&redirect('index.cgi?err=' . &urlize('tar utility not found on host; upload the uncompressed samlguard binary instead.'));
		exit;
	}
	my $extract_dir = "$tmpdir/extract";
	mkdir($extract_dir, 0700) or &error("Failed to create extract directory: $!");
	my ($rc, $out) = &samlguard_status::sg_run_cmd($tar, '-xzf', $upload_path, '-C', $extract_dir);
	if ($rc != 0) {
		&redirect('index.cgi?err=' . &urlize("Failed to extract archive: $out"));
		exit;
	}

	my $find = &samlguard_status::sg_find_bin('find');
	if ($find) {
		my ($frc, $fout) = &samlguard_status::sg_run_cmd($find, $extract_dir, '-type', 'f', '-name', 'samlguard');
		if ($frc == 0 && $fout) {
			my @matches = grep { $_ ne '' } split(/\r?\n/, $fout);
			$new_bin = $matches[0] if @matches;
		}
		my ($urc, $uout) = &samlguard_status::sg_run_cmd($find, $extract_dir, '-type', 'f', '-name', 'samlguard.service');
		if ($urc == 0 && $uout) {
			my @umatches = grep { $_ ne '' } split(/\r?\n/, $uout);
			$new_unit = $umatches[0] if @umatches;
		}
	}
	if (!$new_bin) {
		&redirect('index.cgi?err=' . &urlize('Archive does not contain a samlguard binary.'));
		exit;
	}
} else {
	$new_bin = $upload_path;
}

# Validate ELF executable header and -version check before touching live binary
open(my $bfh, '<', $new_bin) or &error("Failed to read candidate binary: $!");
binmode($bfh);
my $magic = '';
read($bfh, $magic, 4);
close($bfh);

if ($magic ne "\x7fELF") {
	&redirect('index.cgi?err=' . &urlize('Uploaded file is not a valid Linux ELF binary or .tar.gz release archive.'));
	exit;
}

chmod(0755, $new_bin);
my ($vrc, $vout) = &samlguard_status::sg_run_cmd($new_bin, '-version');
$vout =~ s/\r?\n/ /g;
$vout =~ s/^\s+|\s+$//g;
if ($vrc != 0 || $vout eq '') {
	&redirect('index.cgi?err=' . &urlize("Candidate binary failed -version check (exit $vrc): $vout"));
	exit;
}

my $target_bin = $cfg->{'binary_path'};
my $svc = $cfg->{'service_name'};
my $systemctl = &samlguard_status::sg_find_bin('systemctl');
my $setcap = &samlguard_status::sg_find_bin('setcap');

# Backup existing binary & SQLite DB
my @ts = localtime();
my $stamp = sprintf("%04d%02d%02d-%02d%02d%02d", $ts[5]+1900, $ts[4]+1, $ts[3], $ts[2], $ts[1], $ts[0]);

my $bin_backup = '';
if (-f $target_bin) {
	$bin_backup = "$target_bin.bak.$stamp";
	copy($target_bin, $bin_backup) or &error("Failed to backup existing binary to $bin_backup: $!");
	chmod(0755, $bin_backup);
}

my $db_file = $cfg->{'data_dir'} . '/samlguard.db';
if (-f $db_file) {
	my $db_backup = "$db_file.bak.$stamp";
	if (copy($db_file, $db_backup)) {
		chmod(0600, $db_backup);
		&samlguard_status::sg_chown_service_user($db_backup);
	}
}

my $was_active = 0;
if ($systemctl) {
	my ($irc, $iout) = &samlguard_status::sg_run_cmd($systemctl, 'is-active', $svc);
	$iout =~ s/\s+$//;
	if ($irc == 0 && $iout eq 'active') {
		$was_active = 1;
		&samlguard_status::sg_run_cmd($systemctl, 'stop', $svc);
	}
}

# Atomically replace binary
my $staged_bin = "$target_bin.new.$$";
&lock_file($target_bin);
copy($new_bin, $staged_bin) or do {
	&unlock_file($target_bin);
	&error("Failed to stage new binary at $staged_bin: $!");
};
chmod(0755, $staged_bin);
chown(0, 0, $staged_bin);
if (!rename($staged_bin, $target_bin)) {
	unlink($staged_bin);
	&unlock_file($target_bin);
	&error("Failed to replace $target_bin: $!");
}
&unlock_file($target_bin);

if ($setcap) {
	&samlguard_status::sg_run_cmd($setcap, 'cap_net_bind_service=+ep', $target_bin);
}

if ($new_unit && -f $new_unit && $cfg->{'unit_path'}) {
	my $unit_dest = $cfg->{'unit_path'};
	&lock_file($unit_dest);
	if (copy($new_unit, $unit_dest)) {
		chmod(0644, $unit_dest);
	}
	&unlock_file($unit_dest);
	if ($systemctl) {
		&samlguard_status::sg_run_cmd($systemctl, 'daemon-reload');
	}
}

if ($systemctl && -r $cfg->{'unit_path'}) {
	my ($src, $sout) = &samlguard_status::sg_run_cmd($systemctl, 'start', $svc);
	if ($src != 0) {
		# Automatic rollback
		if ($bin_backup && -f $bin_backup) {
			copy($bin_backup, $target_bin);
			chmod(0755, $target_bin);
			if ($setcap) {
				&samlguard_status::sg_run_cmd($setcap, 'cap_net_bind_service=+ep', $target_bin);
			}
			if ($was_active) {
				&samlguard_status::sg_run_cmd($systemctl, 'start', $svc);
			}
		}
		&redirect('index.cgi?err=' . &urlize("Upgrade rolled back because $svc failed to start: $sout"));
		exit;
	}
}

&webmin_log('upgrade', 'application', $vout);
&redirect('index.cgi?msg=' . &urlize("Upgraded SAMLGuard successfully ($vout). Previous binary and database were backed up."));

