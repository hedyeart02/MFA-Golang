BEGIN { push(@INC, ".."); }
use WebminCore;
&init_config();

sub module_install
{
	my $cfgdir = $config_directory || '/etc/webmin';

	my $catfile = "$cfgdir/webmin.catnames";
	my %catnames;
	&lock_file($catfile);
	&read_file($catfile, \%catnames);
	if (!$catnames{'samlguard'}) {
		$catnames{'samlguard'} = 'SAMLGuard';
		&write_file($catfile, \%catnames);
	}
	&unlock_file($catfile);

	my $catsfile = "$cfgdir/webmin.cats";
	my %modcats;
	&lock_file($catsfile);
	&read_file($catsfile, \%modcats);
	my $changed = 0;
	foreach my $m (qw(samlguard_status samlguard_setup samlguard_certs samlguard_logs samlguard_about)) {
		if (!defined($modcats{$m}) || $modcats{$m} ne 'samlguard') {
			$modcats{$m} = 'samlguard';
			$changed = 1;
		}
	}
	if ($changed) {
		&write_file($catsfile, \%modcats);
	}
	&unlock_file($catsfile);

	if (defined(&flush_webmin_caches)) {
		&flush_webmin_caches();
	}
}

1;
