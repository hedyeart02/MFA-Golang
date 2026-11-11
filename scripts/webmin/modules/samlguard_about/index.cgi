#!/usr/bin/perl
BEGIN { push(@INC, ".."); }
use WebminCore;
&init_config();
&foreign_require("samlguard_status", "samlguard-lib.pl");

&ui_print_header(undef, 'About SAMLGuard', '', undef, 1, 1);

my $cfg = &samlguard_status::sg_cfg();
my $st  = &samlguard_status::sg_service_status();
my $ep  = $st->{'endpoint'};
my $base = $ep->{'public_url'};

print &ui_table_start('SAMLGuard SAML 2.0 MFA Gateway', 'width=100%', 2);
print &ui_table_row('Application', 'SAMLGuard — Lightweight SAML 2.0 Proxy IdP & MFA Gateway');
print &ui_table_row('Installed Version', &html_escape($st->{'version'}));
print &ui_table_row('Runtime Mode', 'Standalone Go HTTP/HTTPS service managed via systemd');
print &ui_table_row('Binary Path', &html_escape($cfg->{'binary_path'}));
print &ui_table_row('Config Path', &html_escape($cfg->{'config_path'}));
print &ui_table_row('Certificate Directory', &html_escape($cfg->{'cert_dir'}));
print &ui_table_row('Data Directory', &html_escape($cfg->{'data_dir'}));
print &ui_table_row('Systemd Unit', &html_escape($cfg->{'unit_path'}));
print &ui_table_end();

print "<br>\n";
print &ui_table_start('Standalone Web & SAML Endpoints', 'width=100%', 2);
print &ui_table_row('Admin Console', "<a href='" . &html_escape($base) . "/admin/settings' target='_blank' rel='noopener'>" . &html_escape($base) . "/admin/settings</a>");
print &ui_table_row('SAML SSO Endpoint', &html_escape("$base/saml/sso"));
print &ui_table_row('SAML ACS Endpoint', &html_escape("$base/saml/acs"));
print &ui_table_row('SAML Metadata', "<a href='" . &html_escape($base) . "/saml/metadata' target='_blank' rel='noopener'>" . &html_escape($base) . "/saml/metadata</a>");
print &ui_table_row('Health Check', "<a href='" . &html_escape($base) . "/health' target='_blank' rel='noopener'>" . &html_escape($base) . "/health</a>");
print &ui_table_row('Prometheus Metrics', &html_escape("$base/metrics"));
print &ui_table_end();

&ui_print_footer('/', $text{'index'});
