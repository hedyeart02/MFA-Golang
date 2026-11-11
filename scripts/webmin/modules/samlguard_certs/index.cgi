#!/usr/bin/perl
use POSIX qw(strftime);
BEGIN { push(@INC, ".."); }
use WebminCore;
&init_config();
&foreign_require("samlguard_status", "samlguard-lib.pl");
&ReadParse();

&ui_print_header(undef, 'SAMLGuard Certificates', '', undef, 1, 1);

my $cfg = &samlguard_status::sg_cfg();
my $cert_dir = $cfg->{'cert_dir'};
my $openssl = &samlguard_status::sg_find_bin('openssl');

if ($in{'msg'}) {
	print &samlguard_status::sg_alert(&html_escape($in{'msg'}), 'success');
}
if ($in{'err'}) {
	print &samlguard_status::sg_alert(&html_escape($in{'err'}), 'danger');
}

print &ui_columns_start([
	'File',
	'Size',
	'Modified',
	'Certificate Details',
], 100);

if (-d $cert_dir) {
	opendir(my $dh, $cert_dir) or &error("Failed to open $cert_dir: $!");
	my @files = sort grep { $_ ne '.' && $_ ne '..' && -f "$cert_dir/$_" } readdir($dh);
	closedir($dh);

	if (@files) {
		for my $f (@files) {
			my $full = "$cert_dir/$f";
			my @st = stat($full);
			my $size = defined($st[7]) ? "$st[7] B" : '-';
			my $mtime = defined($st[9]) ? strftime('%Y-%m-%d %H:%M:%S', localtime($st[9])) : '-';
			my $details = '-';

			if ($f =~ /\.key$/i) {
				$details = 'Private key (restricted)';
			} elsif ($openssl && $f =~ /\.(crt|cer|pem)$/i) {
				my ($rc, $out) = &samlguard_status::sg_run_cmd($openssl, 'x509', '-in', $full, '-noout', '-subject', '-issuer', '-enddate');
				if ($rc == 0 && $out) {
					$details = &html_escape($out);
					$details =~ s/\r?\n/<br>/g;
				} else {
					$details = 'Not an X.509 certificate (or key/PEM blob)';
				}
			}

			print &ui_columns_row([
				&html_escape($f),
				&html_escape($size),
				&html_escape($mtime),
				$details,
			]);
		}
	} else {
		print &ui_columns_row([ 'No files found in ' . &html_escape($cert_dir), '', '', '' ]);
	}
} else {
	print &ui_columns_row([ 'Directory does not exist: ' . &html_escape($cert_dir), '', '', '' ]);
}

print &ui_columns_end();

print "<br>\n";
print &ui_form_start('upload.cgi', 'form-data');
print &ui_table_start('Upload Certificate or Key', 'width=100%', 2);
print &ui_table_row('Target Directory', &html_escape($cert_dir));
print &ui_table_row('Certificate / Key File', &ui_upload('certfile', 40));
print &ui_table_row('Optional Target Filename', &ui_textbox('target_name', '', 40) . ' <small>(leave blank to keep original filename)</small>');
print &ui_table_end();
print &ui_form_end([ [ 'upload', 'Upload File' ] ]);

&ui_print_footer('/', $text{'index'});
