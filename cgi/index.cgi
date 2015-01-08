#!/usr/local/cpanel/3rdparty/bin/perl
# start main

use CGI::Carp qw(fatalsToBrowser);
use File::Path;
use File::Copy;
use Fcntl qw(:DEFAULT :flock);
use IPC::Open3;

use lib '/usr/local/cpanel', '/usr/local/cpanel/whostmgr/docroot/cgi';
use whmlib;

use Cpanel::cPanelFunctions ();
use Cpanel::Form			();
use Cpanel::Config          ();
use Cpanel::Version         ();
use Whostmgr::ACLS			();

Whostmgr::ACLS::init_acls();

$| = 1;
print "Content-type: text/html\r\n\r\n";

if (!Whostmgr::ACLS::hasroot()) {
	print "You do not have access to cPanel Linux Malware Detect.\n";
	exit();
}

unless (-e "/usr/local/sbin/maldet") {
	print "Doesn't look like Linux Malware Detect is installed";
	exit();
}

if (-e "/usr/local/cpanel/bin/register_appconfig") {
	$script = "index.cgi";
	$versionfile = "/usr/local/cpanel/whostmgr/docroot/cgi/addons/maldet/version.txt";
} else {
        exit();
}

eval ('use Cpanel::Rlimit			();');
unless ($@) {Cpanel::Rlimit::set_rlimit_to_infinity()}

open (IN, "<$versionfile") or die $!;
$myv = <IN>;
close (IN);
chomp $myv;

defheader("cPanel Malware Detect - maldet v$myv");

%FORM = Cpanel::Form::parseform();

if ($FORM{action} eq "upgrade") {
	print "Retrieving new maldet package...\n";
	print "<pre style='font-family: Courier New, Courier; font-size: 12px'>";
	system ("rm -Rfv /usr/src/cpanel_addon-maldet; cd /usr/src ; git clone https://github.com/steadramon/cpanel_addon-maldet.git 2>&1");
	print "</pre>";
	if (-e "/usr/src/cpanel_addon-maldet/version.txt") {
		print "Installing new version of maldet";
		print "<pre style='font-family: Courier New, Courier; font-size: 12px'>";
		system ("cd /usr/src/cpanel_addon-maldet ; ./install 2>&1");
		print "</pre>";
		print "Tidying up...\n";
		print "<pre style='font-family: Courier New, Courier; font-size: 12px'>";
		system ("rm -Rfv /usr/src/cpanel_addon-maldet");
		print "</pre>";
		print "...All done.\n";
	}

	open (IN, "<$versionfile") or die $!;
	$myv = <IN>;
	close (IN);
	chomp $myv;

	print "<p align='center'><form action='$script' method='post'><input type='submit' class='input' value='Return'></form></p>\n";
}
elsif ($FORM{action} eq "reports") {
	&list_reports;
}
elsif ($FORM{action} eq "last_report") {
	&last_report;
}
elsif ($FORM{action} eq "purge") {
	&purge;
}
elsif ($FORM{action} eq "update_rules") {
	&update_rules;
}
elsif ($FORM{action} eq "view_report") {
	&view_report;
}
elsif ($FORM{action} eq "lmd_config") {
        &lmd_config;
}
elsif ($FORM{action} eq "savelmd_config") {
        &savelmd_config;
}
elsif ($FORM{action} eq "scan_user") {
	&scan_user;
}
elsif ($FORM{action} eq "help") {
	print "<h2>Testing</h2>";
	print "<p align='center'><form action='$script' method='post'><input type='submit' class='input' value='Return'></form></p>\n";
}
else {
	&index;
}
print "<p>&copy;2015 <a href='https://github.com/steadramon/cpanel_addon-maldet' target='_blank'>steadramon</a></p>\n";
print "<pre style='font-family: Courier New, Courier; font-size: 12px'>maldet v$myv</pre>";
# end main

sub index {
	my @users;
	opendir (DIR, "/var/cpanel/users") or die $!;
	while (my $user = readdir (DIR)) {
		if ($user =~ /^\./) {next}
		my (undef,undef,undef,undef,undef,undef,undef,$homedir,undef,undef) = getpwnam($user);
		$homedir =~ /(.*)/;
		$homedir = $1;
		if ($homedir eq "") {next}
		if (not -d "$homedir") {next}
		push (@users, $user);
        }
	closedir (DIR);
	@users = sort @users;


	print "<table class='sortable' width='95%' align='center'>\n";
	print "<tr><th align='left' colspan='2'>Linux Malware Detect Control (<u><a href='$script?action=help'>Help</a></u>)</th></tr>";
	print "<tr class='tdshade2'><form action='$script' method='post'><td><input type='hidden' name='action' value='scan_user'> <select name='user' size='10'>";
	foreach my $user (@users) {
		print "<option value='$user'>$user</option>";
        }
	print "</select>";
	print "</td><td width='100%'>You can scan a user public_html directory <input type='submit' class='input' value='Scan'></td></form></tr>\n";
	print "<tr class='tdshade1'><form action='$script' method='post'><td><input type='hidden' name='action' value='last_report'><input type='submit' class='input' value='View Last Report'></td><td width='100%'>You can view the last report from LMD</td></form></tr>\n";
	print "<tr class='tdshade2'><form action='$script' method='post'><td><input type='hidden' name='action' value='reports'><input type='submit' class='input' value='View Past Reports'></td><td width='100%'>You can view past reports from LMD</td></form></tr>\n";
	print "</table><br>\n";

	print "<table class='sortable' width='95%' align='center'>\n";
	print "<tr><th align='left' colspan='2'>Configure Linux Malware Detect</th></tr>";
	print "<tr class='tdshade1'><form action='$script' method='post'><td><input type='hidden' name='action' value='lmd_config'><input type='hidden' name='template' value='conf.maldet'><input type='submit' class='input' value='Main Config'></td><td width='100%'>Configure LMD main config</td></form></tr>\n";
	print "<tr class='tdshade2'><form action='$script' method='post'><td><input type='hidden' name='action' value='lmd_config'><input type='hidden' name='template' value='ignore_file_ext'><input type='submit' class='input' value='Ignore File Extension'></td><td width='100%'>Configure LMD ignore file extensions</td></form></tr>\n";
	print "</table><br>\n";

	print "<table class='sortable' width='95%' align='center'>\n";
	print "<tr><th align='left' colspan='2'>Advanced</th></tr>";
	print "<tr class='tdshade1'><form action='$script' method='post'><td><input type='hidden' name='action' value='update_rules'><input type='submit' class='input' value='Update LMD'></td><td width='100%'>Update malware detection signatures from rfxn.com</td></form></tr>\n";
	print "<tr class='tdshade2'><form action='$script' method='post'><td><input type='hidden' name='action' value='purge'><input type='submit' class='input' value='Purge Reports'></td><td width='100%'>Clear logs, quarantine queue, session and temporary data.</td></form></tr>\n";
	print "</table><br>\n";


	print "<table class='sortable' width='95%' align='center'>\n";
	my ($status, $text) = &urlget("https://raw.githubusercontent.com/steadramon/cpanel_addon-maldet/master/version.txt");
	my $actv = $text;
	chomp $actv;

	my $up = 0;

	print "<tr><th align='left' colspan='2'>Upgrade</th></tr>";
	if ($actv ne "") {
		if ($actv =~ /^[\d\.]*$/) {
			if ($actv > $myv) {
				print "<tr><form action='$script' method='post'><td><input type='hidden' name='action' value='upgrade'><input type='submit' class='input' value='Upgrade cPanel Maldet'></td><td width='100%'><b>A new version of maldet (v$actv) is available. Upgrading will retain your settings<br><a href='https://raw.githubusercontent.com/steadramon/cpanel_addon-maldet/master/changelog.txt' target='_blank'>View ChangeLog</a></b></td></form></tr>\n";
			} else {
				print "<tr><td colspan='2'>You appear to be running the latest version of maldet. An Upgrade button will appear here if a new version becomes available</td></tr>\n";
			}
			$up = 1;
		}
	}
	unless ($up) {
		print "<tr><td colspan='2'>Failed to determine the latest version of maldet. An Upgrade button will appear here if new version is detected</td></tr>\n";
	}
	print "</table><br>\n";
}

###############################################################################
sub lmd_config {
        sysopen (IN, "/usr/local/maldetect/$FORM{template}", O_RDWR | O_CREAT);
        flock (IN, LOCK_SH);
        my @confdata = <IN>;
        close (IN);
        chomp @confdata;

        print "<form action='$script' method='post'>\n";
        print "<input type='hidden' name='action' value='savelmd_config'>\n";
	print "<input type='hidden' name='template' value='$FORM{template}'>\n";
        print "<fieldset><legend><b>Edit $FORM{template}</b></legend>\n";
        print "<table align='center'>\n";
        print "<tr><td><textarea name='formdata' cols='80' rows='40' style='font-family: Courier New, Courier; font-size: 12px' wrap='off'>\n";
        foreach my $line (@confdata) {
                $line =~ s/\&/\&amp\;/g;
                $line =~ s/>/\&gt\;/g;
                $line =~ s/</\&lt\;/g;
                print $line."\n";
        }
	print "</textarea></td></tr></table></fieldset>\n";
        print "<p align='center'><input type='submit' class='input' value='Change'></p>\n";
        print "</form>\n";
        print "<p align='center'><form action='$script' method='post'><input type='submit' class='input' value='Return'></form></p>\n";
}

sub savelmd_config {

        $FORM{formdata} =~ s/\r//g;
        sysopen (OUT, "/usr/local/maldetect/$FORM{template}", O_WRONLY | O_CREAT);
        flock (OUT, LOCK_EX);
        seek (OUT, 0, 0);
        truncate (OUT, 0);
        if ($FORM{formdata} !~ /\n$/) {$FORM{formdata} .= "\n"}
        print OUT $FORM{formdata};
        close (OUT);

	print "<p>File $FORM{template} updated</p>";
        print "<p align='center'><form action='$script' method='post'><input type='submit' class='input' value='Return'></form></p>\n";

}

sub list_reports {
	print "<table class='sortable' width='95%' align='center'>\n";
	print "<tr class='tableheader'><th>Date</th><th>Scan ID</th>";

	my %hash;

	my @reports = `/usr/local/sbin/maldet --report list`;
	foreach my $line (@reports) {
		if ($line =~ /TIME: (.+) \| SCAN ID: (.+)/) { 
			$hash{$2} = $1;			
		}
	}

	my $line_count=0;
	my $tclass;

	foreach my $name (sort keys %hash) {
		$line_count++;
		if ( ( $line_count % 2 ) == 0 ) {
			$tclass = 'tdshade1';
		}
		else {
			$tclass = 'tdshade2';
		}
		print "<tr class='$tclass'><td>$hash{$name}</td><td><a href='$script?action=view_report&id=$name'>$name</a></td></tr>";
	}
	print "</table>";

        print "<p align='center'><form action='$script' method='post'><input type='submit' class='input' value='Return'></form></p>\n";
}

sub purge {

	print "Purging temporary files and logs\n";
	print "<pre style='font-family: Courier New, Courier; font-size: 12px'>";
        &printcmd("/usr/local/sbin/maldet --purge");
        print "</pre>";
       	print "<p align='center'><form action='$script' method='post'><input type='submit' class='input' value='Return'></form></p>\n";

}

sub update_rules {

	print "Updating LMD\n";
        print "<pre style='font-family: Courier New, Courier; font-size: 12px'>";
        &printcmd("/usr/local/sbin/maldet --update-ver");
        print "</pre>";
	print "Updating ruleset\n";
        print "<pre style='font-family: Courier New, Courier; font-size: 12px'>";
        &printcmd("/usr/local/sbin/maldet --update");
        print "</pre>";
        print "<p align='center'><form action='$script' method='post'><input type='submit' class='input' value='Return'></form></p>\n";

}

sub last_report {

	open (IN, "</usr/local/maldetect/sess/session.last") or die $!;
	$lastreport = <IN>;
	close (IN);
	chomp $lastreport;

        sysopen (IN, "/usr/local/maldetect/sess/session.$lastreport", O_RDWR | O_CREAT);
        flock (IN, LOCK_SH);
        my @confdata = <IN>;
        close (IN);
        chomp @confdata;

        print "<form action='$script' method='post'>\n";
        print "<input type='hidden' name='action' value='savems_config'>\n";
        print "<input type='hidden' name='template' value='$FORM{template}'>\n";
        print "<fieldset><legend><b>Viewing Log $FORM{id}</b></legend>\n";
        print "<table align='center'>\n";
        print "<tr><td><textarea name='formdata' cols='80' rows='40' style='font-family: Courier New, Courier; font-size: 12px' wrap='off'>\n";
        foreach my $line (@confdata) {
                $line =~ s/\&/\&amp\;/g;
                $line =~ s/>/\&gt\;/g;
                $line =~ s/</\&lt\;/g;
                print $line."\n";
        }
        print "</textarea></td></tr></table></fieldset>\n";
        print "</form>\n";
       	print "<p align='center'><form action='$script' method='post'><input type='submit' class='input' value='Return'></form></p>\n";
}

sub view_report {

        sysopen (IN, "/usr/local/maldetect/sess/session.$FORM{id}", O_RDWR | O_CREAT);
        flock (IN, LOCK_SH);
        my @confdata = <IN>;
        close (IN);
        chomp @confdata;

        print "<form action='$script' method='post'>\n";
        print "<input type='hidden' name='action' value='savems_config'>\n";
        print "<input type='hidden' name='template' value='$FORM{template}'>\n";
        print "<fieldset><legend><b>Viewing Log $FORM{id}</b></legend>\n";
        print "<table align='center'>\n";
       	print "<tr><td><textarea name='formdata' cols='80' rows='40' style='font-family: Courier New, Courier; font-size: 12px' wrap='off'>\n";
       	foreach my $line (@confdata) {
               	$line =~ s/\&/\&amp\;/g;
                $line =~ s/>/\&gt\;/g;
                $line =~ s/</\&lt\;/g;
               	print $line."\n";
        }
        print "</textarea></td></tr></table></fieldset>\n";
       	print "</form>\n";
       	print "<p align='center'><form action='$script?action=reports' method='post'><input type='submit' class='input' value='Return'></form></p>\n";
}

sub scan_user {
	my $user = $FORM{user};
	my (undef,undef,undef,undef,undef,undef,undef,$homedir,undef,undef) = getpwnam($user);
	$homedir .= "/public_html/";
	print "Starting scan...<pre>";
	$tmpDir = '/tmp/malwaredetect';
	if (! -d $tmpDir ) {
		mkpath($tmpDir, 0, 0077);
	}
	chdir $tmpDir;
	print `/usr/local/sbin/maldet -b -a $homedir`;
	print "</pre>";
	print "<p align='center'><form action='$script' method='post'><input type='submit' class='input' value='Return'></form></p>\n";
}

###############################################################################
# start printcmd
sub printcmd {
	my ($childin, $childout);
	my $pid = open3($childin, $childout, $childout, @_);
	while (<$childout>) {print $_}
	waitpid ($pid, 0);
}
# end printcmd
###############################################################################
# start splitlines
sub splitlines {
	my $line = shift;
	my $cnt = 0;
	my $newline;
	for (my $x = 0;$x < length($line) ;$x++) {
		if ($cnt > 120) {
			$cnt = 0;
			$newline .= "<WBR>";
		}
		my $letter = substr($line,$x,1);
		if ($letter =~ /\s/) {
			$cnt = 0;
		} else {
			$cnt++;
		}
		$newline .= $letter;
	}

	return $newline;
}
# end splitlines
###############################################################################

###############################################################################
# start urlget (v1.3)
#
# Examples:
#my ($status, $text) = &urlget("http://prdownloads.sourceforge.net/clamav/clamav-0.92.tar.gz","/tmp/clam.tgz");
#if ($status) {print "Oops: $text\n"}
#
#my ($status, $text) = &urlget("http://www.configserver.com/free/msfeversion.txt");
#if ($status) {print "Oops: $text\n"} else {print "Version: $text\n"}
#
sub urlget {
	my $url = shift;
	my $file = shift;
	my $status = 0;
	my $timeout = 1200;

	use LWP::UserAgent;
	my $ua = LWP::UserAgent->new;
	$ua->timeout(30);
	my $req = HTTP::Request->new(GET => $url);
	my $res;
	my $text;

	($status, $text) = eval {
		local $SIG{__DIE__} = undef;
		local $SIG{'ALRM'} = sub {die "Download timeout after $timeout seconds"};
		alarm($timeout);
		if ($file) {
			$|=1;
			my $expected_length;
			my $bytes_received = 0;
			my $per = 0;
			my $oldper = 0;
			open (OUT, ">$file\.tmp") or return (1, "Unable to open $file\.tmp: $!");
			binmode (OUT);
			print "...0\%\n";
			$res = $ua->request($req,
				sub {
				my($chunk, $res) = @_;
				$bytes_received += length($chunk);
				unless (defined $expected_length) {$expected_length = $res->content_length || 0}
				if ($expected_length) {
					my $per = int(100 * $bytes_received / $expected_length);
					if ((int($per / 5) == $per / 5) and ($per != $oldper)) {
						print "...$per\%\n";
						$oldper = $per;
					}
				} else {
					print ".";
				}
				print OUT $chunk;
			});
			close (OUT);
			print "\n";
		} else {
			$res = $ua->request($req);
		}
		alarm(0);
		if ($res->is_success) {
			if ($file) {
				rename ("$file\.tmp","$file") or return (1, "Unable to rename $file\.tmp to $file: $!");
				return (0, $file);
			} else {
				return (0, $res->content);
			}
		} else {
			return (1, "Unable to download: ".$res->message);
		}
	};
	alarm(0);
	if ($@) {
		return (1, $@);
	}
	if ($text) {
		return ($status,$text);
	} else {
		return (1, "Download timeout after $timeout seconds");
	}
}
# end urlget
###############################################################################

1;

