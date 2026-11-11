sub module_install
{
	my $catfile = "$config_directory/webmin.catnames";
	my %cats;
	&lock_file($catfile);
	&read_file($catfile, \%cats);
	if (!$cats{'samlguard'}) {
		$cats{'samlguard'} = 'SAMLGuard';
		&write_file($catfile, \%cats);
	}
	&unlock_file($catfile);
}

1;
