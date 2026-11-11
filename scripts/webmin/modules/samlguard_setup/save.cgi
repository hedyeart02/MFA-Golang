#!/usr/bin/perl
use File::Basename;
BEGIN { push(@INC, ".."); }
use WebminCore;
&init_config();
&foreign_require("samlguard_status", "samlguard-lib.pl");
&ReadParse();

if ($ENV{'REQUEST_METHOD'} ne 'POST') {
	&error('Invalid request method (POST required)');
}

my $cfg = &samlguard_status::sg_cfg();
my $path = $cfg->{'config_path'};
my $content = $in{'yaml_content'};
if (!defined($content) || $content =~ /^\s*$/) {
	&redirect('index.cgi?err=' . &urlize('Configuration content cannot be empty'));
	exit;
}

$content =~ s/\r\n/\n/g;
$content .= "\n" unless $content =~ /\n$/;

my $dir = dirname($path);
if (!-d $dir) {
	mkdir($dir, 0700) or &error("Failed to create directory $dir: $!");
	&samlguard_status::sg_chown_service_user($dir);
}

if (-f $path) {
	if (open(my $in_fh, '<', $path)) {
		local $/ = undef;
		my $old = <$in_fh>;
		close($in_fh);
		if (defined($old) && open(my $bak_fh, '>', "$path.bak")) {
			print $bak_fh $old;
			close($bak_fh);
			chmod(0600, "$path.bak");
			&samlguard_status::sg_chown_service_user("$path.bak");
		}
	}
}

&lock_file($path);
open(my $out_fh, '>', $path) or &error("Failed to write $path: $!");
print $out_fh $content;
close($out_fh);
chmod(0600, $path);
&samlguard_status::sg_chown_service_user($path);
&unlock_file($path);

&webmin_log('save', 'config', $path);

if ($in{'save_restart'}) {
	my $systemctl = &samlguard_status::sg_find_bin('systemctl');
	if ($systemctl) {
		my ($rc, $out) = &samlguard_status::sg_run_cmd($systemctl, 'restart', $cfg->{'service_name'});
		if ($rc == 0) {
			&redirect('index.cgi?msg=' . &urlize("Configuration saved and $cfg->{'service_name'} restarted."));
			exit;
		} else {
			$out =~ s/\r?\n/ /g;
			&redirect('index.cgi?err=' . &urlize("Configuration saved, but restart failed: $out"));
			exit;
		}
	}
}

&redirect('index.cgi?msg=' . &urlize("Configuration saved to $path (backup written to $path.bak)."));
