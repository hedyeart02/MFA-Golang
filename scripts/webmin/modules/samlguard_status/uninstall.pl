sub module_uninstall
{
	my $catfile = "$config_directory/webmin.catnames";
	if (-r $catfile) {
		my %cats;
		&lock_file($catfile);
		&read_file($catfile, \%cats);
		if (exists $cats{'samlguard'}) {
			delete $cats{'samlguard'};
			&write_file($catfile, \%cats);
		}
		&unlock_file($catfile);
	}
}

1;
