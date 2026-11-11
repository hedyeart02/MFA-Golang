#!/usr/bin/perl
require './samlguard-lib.pl';
&ReadParse();

&ui_print_header(undef, 'SAMLGuard Status', '', undef, 1, 1);

my $cfg = &sg_cfg();
my $st  = &sg_service_status();
my $ep  = $st->{'endpoint'};

if ($in{'msg'}) {
	print &sg_alert(&html_escape($in{'msg'}), 'success');
}
if ($in{'err'}) {
	print &sg_alert(&html_escape($in{'err'}), 'danger');
}

if (!$st->{'binary_exists'} || !$st->{'unit_exists'}) {
	my $warn = "SAMLGuard daemon is not fully installed on this host yet.<br>";
	$warn .= "Missing: ";
	my @missing;
	push(@missing, "binary (" . &html_escape($cfg->{'binary_path'}) . ")") unless $st->{'binary_exists'};
	push(@missing, "systemd unit (" . &html_escape($cfg->{'unit_path'}) . ")") unless $st->{'unit_exists'};
	$warn .= join(', ', @missing) . ".<br>";
	$warn .= "Run <code>sudo ./scripts/linux/install.sh ./bin/samlguard-linux-amd64</code> on the server to install the standalone SAMLGuard service.";
	print &sg_alert($warn, 'warn');
}

my $active_badge = $st->{'active'} eq 'active'
	? "<span style='color:#0a7d2c;font-weight:bold;'>Running (active)</span>"
	: "<span style='color:#b00020;font-weight:bold;'>" . &html_escape($st->{'active'}) . "</span>";

print &ui_table_start('SAMLGuard Service Status', 'width=100%', 2);
print &ui_table_row('Service State', $active_badge);
print &ui_table_row('Boot Startup', &html_escape($st->{'enabled'}));
print &ui_table_row('Main PID', &html_escape($st->{'main_pid'}));
print &ui_table_row('Active Since', &html_escape($st->{'since'}));
print &ui_table_row('Memory Usage', &html_escape($st->{'memory'}));
print &ui_table_row('Health Endpoint', &html_escape($st->{'health'}));
print &ui_table_row('Binary Version', &html_escape($st->{'version'}));
print &ui_table_row('Standalone Admin Console',
	"<a href='" . &html_escape($ep->{'public_url'}) . "/admin/settings' target='_blank' rel='noopener'>"
	. &html_escape($ep->{'public_url'}) . "/admin/settings</a>");
print &ui_table_row('SAML Metadata URL',
	"<a href='" . &html_escape($ep->{'public_url'}) . "/saml/metadata' target='_blank' rel='noopener'>"
	. &html_escape($ep->{'public_url'}) . "/saml/metadata</a>");
print &ui_table_end();

print "<br>\n";

if ($st->{'has_systemctl'} && $st->{'unit_exists'}) {
	print &ui_buttons_start();
	if ($st->{'active'} eq 'active') {
		print &ui_buttons_row('action.cgi', 'Restart SAMLGuard', 'Restart the standalone SAMLGuard service to apply configuration or certificate changes.',
			&ui_hidden('action', 'restart'));
		print &ui_buttons_row('action.cgi', 'Stop SAMLGuard', 'Stop the SAMLGuard MFA gateway service.',
			&ui_hidden('action', 'stop'));
	} else {
		print &ui_buttons_row('action.cgi', 'Start SAMLGuard', 'Start the standalone SAMLGuard MFA gateway service.',
			&ui_hidden('action', 'start'));
	}
	if ($st->{'enabled'} eq 'enabled') {
		print &ui_buttons_row('action.cgi', 'Disable on Boot', 'Prevent SAMLGuard from starting automatically at system boot.',
			&ui_hidden('action', 'disable'));
	} else {
		print &ui_buttons_row('action.cgi', 'Enable on Boot', 'Start SAMLGuard automatically when the server boots.',
			&ui_hidden('action', 'enable'));
	}
	print &ui_buttons_end();
}

&ui_print_footer('/', $text{'index'});
