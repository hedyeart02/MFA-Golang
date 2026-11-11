BEGIN { push(@INC, ".."); }
use WebminCore;
&init_config();

sub sg_cfg
{
	return {
		service_name => ($config{'service_name'} && $config{'service_name'} =~ /^[A-Za-z0-9_.@-]+$/) ? $config{'service_name'} : 'samlguard',
		binary_path  => $config{'binary_path'}  || '/usr/local/bin/samlguard',
		config_path  => $config{'config_path'}  || '/etc/samlguard/config.yaml',
		cert_dir     => $config{'cert_dir'}     || '/etc/samlguard/cert',
		data_dir     => $config{'data_dir'}     || '/var/lib/samlguard',
		unit_path    => $config{'unit_path'}    || '/etc/systemd/system/samlguard.service',
	};
}

sub sg_run_cmd
{
	my (@cmd) = @_;
	my $out = '';
	my $pid = open(my $fh, '-|');
	if (!defined($pid)) {
		return (1, "Failed to fork command: $!");
	}
	if ($pid == 0) {
		open(STDERR, '>&', \*STDOUT);
		exec(@cmd);
		print "exec failed: $!\n";
		exit(127);
	}
	local $/ = undef;
	$out = <$fh>;
	close($fh);
	my $rc = $? >> 8;
	$out = '' unless defined($out);
	return ($rc, $out);
}

sub sg_find_bin
{
	my ($name) = @_;
	for my $dir ('/bin', '/usr/bin', '/sbin', '/usr/sbin', '/usr/local/bin') {
		my $p = "$dir/$name";
		return $p if -x $p;
	}
	return undef;
}

sub sg_read_yaml_summary
{
	my ($path) = @_;
	my %vals;
	return \%vals unless $path && -r $path;

	open(my $fh, '<', $path) or return \%vals;
	my $section = '';
	while (my $line = <$fh>) {
		$line =~ s/\r?\n$//;
		next if $line =~ /^\s*$/ || $line =~ /^\s*#/;

		if ($line =~ /^([A-Za-z0-9_]+):\s*(?:#.*)?$/) {
			$section = $1;
			next;
		}
		if ($line =~ /^([A-Za-z0-9_]+):\s*(.+?)\s*$/) {
			$section = '';
			my ($k, $v) = ($1, $2);
			$v = sg_clean_yaml_scalar($v);
			$vals{$k} = $v;
			next;
		}
		if ($section ne '' && $line =~ /^\s{2,4}([A-Za-z0-9_]+):\s*(.*?)\s*$/) {
			my ($k, $v) = ($1, $2);
			$v = sg_clean_yaml_scalar($v);
			$vals{"$section.$k"} = $v;
			next;
		}
	}
	close($fh);
	return \%vals;
}

sub sg_clean_yaml_scalar
{
	my ($v) = @_;
	return '' unless defined($v);
	if ($v =~ /^"(.*)"(?:\s*#.*)?$/) {
		return $1;
	}
	if ($v =~ /^'(.*)'(?:\s*#.*)?$/) {
		return $1;
	}
	$v =~ s/\s+#.*$//;
	$v =~ s/^\s+|\s+$//g;
	return $v;
}

sub sg_get_endpoint_info
{
	my $cfg = &sg_cfg();
	my $y = &sg_read_yaml_summary($cfg->{'config_path'});

	my $port = 8443;
	if ($y->{'server.port'} && $y->{'server.port'} =~ /^\d+$/ && $y->{'server.port'} >= 1 && $y->{'server.port'} <= 65535) {
		$port = int($y->{'server.port'});
	}

	my $tls = 0;
	my $tls_raw = defined($y->{'tls.enabled'}) ? $y->{'tls.enabled'} : $y->{'server.tls_enabled'};
	if (defined($tls_raw) && lc($tls_raw) eq 'true') {
		$tls = 1;
	}

	my $scheme = $tls ? 'https' : 'http';
	my $host = $ENV{'HTTP_HOST'} || 'localhost';
	$host =~ s/:\d+$//;
	$host = 'localhost' unless $host =~ /^[A-Za-z0-9.\[\]-]+$/;

	return {
		port       => $port,
		tls        => $tls,
		scheme     => $scheme,
		local_url  => "$scheme://127.0.0.1:$port",
		public_url => "$scheme://$host:$port",
		yaml       => $y,
	};
}

sub sg_service_status
{
	my $cfg = &sg_cfg();
	my $svc = $cfg->{'service_name'};
	my $systemctl = &sg_find_bin('systemctl');

	my %st = (
		has_systemctl => ($systemctl ? 1 : 0),
		binary_exists => (-x $cfg->{'binary_path'} ? 1 : 0),
		config_exists => (-r $cfg->{'config_path'} ? 1 : 0),
		unit_exists   => (-r $cfg->{'unit_path'}   ? 1 : 0),
		active        => 'unknown',
		enabled       => 'unknown',
		main_pid      => '-',
		since         => '-',
		memory        => '-',
		version       => '-',
		health        => 'not checked',
	);

	if ($st{'binary_exists'}) {
		my ($rc, $vout) = &sg_run_cmd($cfg->{'binary_path'}, '-version');
		if ($rc == 0 && $vout) {
			$vout =~ s/\r?\n/ /g;
			$vout =~ s/^\s+|\s+$//g;
			$st{'version'} = $vout;
		}
	}

	if ($systemctl) {
		my ($rc_a, $out_a) = &sg_run_cmd($systemctl, 'is-active', $svc);
		$out_a =~ s/\s+$//;
		$st{'active'} = $out_a || ($rc_a == 0 ? 'active' : 'inactive');

		my ($rc_e, $out_e) = &sg_run_cmd($systemctl, 'is-enabled', $svc);
		$out_e =~ s/\s+$//;
		$st{'enabled'} = $out_e || 'disabled';

		my ($rc_s, $out_s) = &sg_run_cmd($systemctl, 'show', $svc, '--property=MainPID,ActiveEnterTimestamp,MemoryCurrent');
		if ($rc_s == 0 && $out_s) {
			for my $line (split(/\r?\n/, $out_s)) {
				if ($line =~ /^MainPID=(\d+)$/) {
					$st{'main_pid'} = $1 > 0 ? $1 : '-';
				} elsif ($line =~ /^ActiveEnterTimestamp=(.+)$/) {
					$st{'since'} = $1 ne '' ? $1 : '-';
				} elsif ($line =~ /^MemoryCurrent=(\d+)$/) {
					my $bytes = $1 + 0;
					if ($bytes > 0 && $bytes < 1099511627776) {
						$st{'memory'} = sprintf('%.1f MB', $bytes / (1024 * 1024));
					}
				}
			}
		}
	}

	my $ep = &sg_get_endpoint_info();
	$st{'endpoint'} = $ep;

	my $curl = &sg_find_bin('curl');
	if ($curl && $st{'active'} eq 'active') {
		my ($rc_h, $out_h) = &sg_run_cmd($curl, '-sk', '--max-time', '2', "$ep->{'local_url'}/health");
		$out_h =~ s/\s+$//;
		if ($rc_h == 0 && $out_h ne '') {
			$st{'health'} = "OK ($out_h)";
		} else {
			$st{'health'} = "Unreachable (exit $rc_h)";
		}
	} elsif ($st{'active'} ne 'active') {
		$st{'health'} = 'Service not running';
	}

	return \%st;
}

sub sg_chown_service_user
{
	my ($path) = @_;
	my (undef, undef, $uid, $gid) = getpwnam('samlguard');
	if (defined($uid) && defined($gid)) {
		chown($uid, $gid, $path);
	}
}

sub sg_alert
{
	my ($html_msg, $type) = @_;
	$type ||= 'info';
	if (defined(&ui_alert_box)) {
		return &ui_alert_box($html_msg, $type);
	}
	my %colors = (
		'success' => [ '#e6f4ea', '#137333', '#a8dab5' ],
		'danger'  => [ '#fce8e6', '#c5221f', '#f6aea9' ],
		'warn'    => [ '#fef7e0', '#b06000', '#fdd663' ],
		'info'    => [ '#e8f0fe', '#1967d2', '#aecbfa' ],
	);
	my $c = $colors{$type} || $colors{'info'};
	return "<div style='background:$c->[0];color:$c->[1];border:1px solid $c->[2];padding:8px 12px;margin:8px 0;border-radius:3px;'>$html_msg</div>\n";
}

1;
