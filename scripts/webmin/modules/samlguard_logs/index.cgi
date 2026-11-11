#!/usr/bin/perl
BEGIN { push(@INC, ".."); }
use WebminCore;
&init_config();
&foreign_require("samlguard_status", "samlguard-lib.pl");
&ReadParse();

&ui_print_header(undef, 'SAMLGuard Debug & Logs', '', undef, 1, 1);

my $cfg = &samlguard_status::sg_cfg();
my $ep  = &samlguard_status::sg_get_endpoint_info();
my $lines = ($in{'lines'} && $in{'lines'} =~ /^(50|100|300|1000)$/) ? $in{'lines'} : '100';
my $filter = defined($in{'filter'}) ? $in{'filter'} : '';
$filter =~ s/[\r\n]//g;

print &ui_form_start('index.cgi', 'get');
print &ui_table_start('Log View Options', 'width=100%', 2);
print &ui_table_row('Lines', &ui_select('lines', $lines, [ [ '50', '50' ], [ '100', '100' ], [ '300', '300' ], [ '1000', '1000' ] ]));
print &ui_table_row('Filter Text', &ui_textbox('filter', $filter, 40) . ' <small>(case-insensitive substring match)</small>');
print &ui_table_end();
print &ui_form_end([ [ 'show', 'Refresh Logs' ] ]);

print "<p><a href='download.cgi'>Download recent logs (1000 lines)</a></p>\n";

my $journalctl = &samlguard_status::sg_find_bin('journalctl');
my $log_text = '';
if ($journalctl) {
	my ($rc, $out) = &samlguard_status::sg_run_cmd($journalctl, '-u', $cfg->{'service_name'}, '-n', $lines, '--no-pager');
	if ($filter ne '') {
		my @matched = grep { index(lc($_), lc($filter)) >= 0 } split(/\r?\n/, $out);
		$log_text = join("\n", @matched);
	} else {
		$log_text = $out;
	}
} else {
	$log_text = 'journalctl not found on this host.';
}

print &ui_table_start("Service Logs ($cfg->{'service_name'})", 'width=100%', 1);
print &ui_table_row(undef, "<pre style='max-height:420px;overflow:auto;background:#111;color:#e5e7eb;padding:10px;border-radius:4px;white-space:pre-wrap;'>"
	. &html_escape($log_text || '(no log entries)') . "</pre>");
print &ui_table_end();

print "<br>\n";
my $db_path = $ep->{'yaml'}->{'database.path'} || "$cfg->{'data_dir'}/samlguard.db";
if ($db_path !~ /^\//) {
	$db_path = "$cfg->{'data_dir'}/$db_path";
	$db_path =~ s#/\./#/#g;
}
my $db_status = -f $db_path ? sprintf('Exists (%.1f KB)', (-s $db_path) / 1024) : 'Not created yet';

my $ss = &samlguard_status::sg_find_bin('ss');
my $listen_info = 'ss utility not available';
if ($ss) {
	my ($rc_ss, $out_ss) = &samlguard_status::sg_run_cmd($ss, '-tlnp');
	if ($rc_ss == 0) {
		my @hits = grep { /:$ep->{'port'}\b/ || /samlguard/ } split(/\r?\n/, $out_ss);
		$listen_info = @hits ? join("\n", @hits) : "No socket listening on port $ep->{'port'}";
	}
}

print &ui_table_start('Runtime Diagnostics', 'width=100%', 2);
print &ui_table_row('Data Directory', &html_escape($cfg->{'data_dir'}) . (-d $cfg->{'data_dir'} ? ' (exists)' : ' (missing)'));
print &ui_table_row('SQLite Database', &html_escape("$db_path - $db_status"));
print &ui_table_row('Listening Socket Check', "<pre style='margin:0;'>" . &html_escape($listen_info) . "</pre>");
print &ui_table_end();

&ui_print_footer('/', $text{'index'});
