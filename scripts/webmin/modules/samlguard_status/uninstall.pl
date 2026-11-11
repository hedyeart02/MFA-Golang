BEGIN { push(@INC, ".."); }
use WebminCore;
&init_config();

sub module_uninstall
{
	my $cfgdir = $config_directory || '/etc/webmin';

	my $catfile = "$cfgdir/webmin.catnames";
	if (-r $catfile) {
		my %catnames;
		&lock_file($catfile);
		&read_file($catfile, \%catnames);
		if (exists $catnames{'samlguard'}) {
			delete $catnames{'samlguard'};
			&write_file($catfile, \%catnames);
		}
		&unlock_file($catfile);
	}

	my $catsfile = "$cfgdir/webmin.cats";
	if (-r $catsfile) {
		my %modcats;
		&lock_file($catsfile);
		&read_file($catsfile, \%modcats);
		my $changed = 0;
		foreach my $m (qw(samlguard_status samlguard_setup samlguard_certs samlguard_logs samlguard_about)) {
			if (exists $modcats{$m}) {
				delete $modcats{$m};
				$changed = 1;
			}
		}
		if ($changed) {
			&write_file($catsfile, \%modcats);
		}
		&unlock_file($catsfile);
	}

	if (defined(&flush_webmin_caches)) {
		&flush_webmin_caches();
	}
}

1;
