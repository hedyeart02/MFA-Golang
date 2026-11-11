#!/usr/bin/perl
BEGIN { push(@INC, ".."); }
use WebminCore;
&init_config();
&foreign_require("samlguard_status", "samlguard-lib.pl");
&ReadParse();

&ui_print_header(undef, 'SAMLGuard Setup', '', undef, 1, 1);

my $cfg = &samlguard_status::sg_cfg();
my $ep  = &samlguard_status::sg_get_endpoint_info();
my $y   = $ep->{'yaml'};

if ($in{'msg'}) {
	print &samlguard_status::sg_alert(&html_escape($in{'msg'}), 'success');
}
if ($in{'err'}) {
	print &samlguard_status::sg_alert(&html_escape($in{'err'}), 'danger');
}

print &ui_table_start('Detected Configuration Summary', 'width=100%', 2);
print &ui_table_row('Config File', &html_escape($cfg->{'config_path'}));
print &ui_table_row('Listen Port / TLS', &html_escape("$ep->{'port'} (" . ($ep->{'tls'} ? 'HTTPS enabled' : 'HTTP') . ")"));
print &ui_table_row('SAML Entity ID', &html_escape($y->{'saml.entity_id'} || '-'));
print &ui_table_row('Downstream ACS URL', &html_escape($y->{'saml.acs_url'} || '-'));
print &ui_table_row('ITA API URL', &html_escape($y->{'ita.api_url'} || '-'));
print &ui_table_row('Database Path', &html_escape($y->{'database.path'} || '-'));
print &ui_table_row('Web Admin Console',
	"<a href='" . &html_escape($ep->{'public_url'}) . "/admin/settings' target='_blank' rel='noopener'>"
	. &html_escape($ep->{'public_url'}) . "/admin/settings</a>");
print &ui_table_end();

print "<br>\n";

my $raw = '';
if (-r $cfg->{'config_path'}) {
	open(my $fh, '<', $cfg->{'config_path'}) or &error("Failed to read $cfg->{'config_path'}: $!");
	local $/ = undef;
	$raw = <$fh>;
	close($fh);
	$raw = '' unless defined($raw);
} else {
	print &samlguard_status::sg_alert("Configuration file " . &html_escape($cfg->{'config_path'}) . " does not exist yet. Saving below will create it.", 'warn');
}

print &ui_form_start('save.cgi', 'post');
print &ui_table_start('Edit config.yaml', 'width=100%', 2);
print &ui_table_row('YAML Content',
	&ui_textarea('yaml_content', $raw, 28, 95, 'off', 0, "style='width:100%;font-family:monospace;'"));
print &ui_table_end();
print &ui_form_end([
	[ 'save', 'Save Configuration' ],
	[ 'save_restart', 'Save & Restart SAMLGuard' ],
]);

&ui_print_footer('/', $text{'index'});
