#!/usr/local/cpanel/3rdparty/bin/perl

BEGIN { unshift @INC, '/usr/local/cpanel', '/usr/local/cpanel/whostmgr/docroot/cgi'; }

use Whostmgr::ACLS          ();
use Whostmgr::HTMLInterface ();
use Cpanel::Template;
use Cpanel;
use Whostmgr::Maldet;
use Cpanel::Config::Users;
use Cpanel::Form                   ();
Whostmgr::ACLS::init_acls();

use Data::Dumper;

print "Content-type: text/html\r\n\r\n";

if ( !$Whostmgr::ACLS::ACL{all} ) {
    Cpanel::Template::process_template(
      'whostmgr',
      {
        "template_file" => "maldet/err.tmpl",
        "error_message" => "Maldet is installed and running!\n",
        "print"         => 1,
      }
    );
    exit();
}

my %FORM           = Cpanel::Form::parseform();

if ( $FORM{'cgiaction'} eq '' ) {
  my @userlist = Cpanel::Config::Users::getcpusers();
  my $version = Whostmgr::Maldet::version();
  my $sigversion = Whostmgr::Maldet::sig_version();
  my $reports = Whostmgr::Maldet::report_list();
  my @configs = Whostmgr::Maldet::configs();
  @userlist = sort(@userlist);
  my $mdconfig = Whostmgr::Maldet::load_mdconfig();
  my $pluginversion = Whostmgr::Maldet::plugin_version();

  Cpanel::Template::process_template(
  'whostmgr',
  {
    "template_file"  => "maldet/index.tmpl",
    "maldet_version" => $version,
    "sig_version"    => $sigversion,
    "users"          => \@userlist,
    "mdconfig"       => $mdconfig,
    "plugin_version" => $pluginversion,
    "config_files"   => \@configs,
    "maldet_reports" => $reports,
    "print"          => 1,
    "scripts"        => [
      '../../../js/sorttable.js',
      '../../../libraries/jquery/3.2.0/jquery-3.2.0.min.js',
    ],
  });

} elsif ( $FORM{'cgiaction'} eq 'viewreport' ) {

  my $report = Whostmgr::Maldet::report($FORM{'reportid'});

  Cpanel::Template::process_template(
  'whostmgr',
  {
    "template_file"  => "maldet/report.tmpl",
    "print"          => 1,
    "report_str"      => $report->{str},
    "report_id"      => $report->{id},
  });

} elsif ( $FORM{'cgiaction'} eq 'updatesigs' ) {

  my $output = Whostmgr::Maldet::update_sigs();

  Cpanel::Template::process_template(
  'whostmgr',
  {
    "template_file"  => "maldet/update.tmpl",
    "print"          => 1,
    "output"      => $output,
    "type"      => 'Signatures',
  });

} elsif ( $FORM{'cgiaction'} eq 'updatelmd' ) {

  my $output = Whostmgr::Maldet::update_maldet();

  Cpanel::Template::process_template(
  'whostmgr',
  {
    "template_file"  => "maldet/update.tmpl",
    "print"          => 1,
    "output"	  => $output,
    "type"	=> 'LMD',
  });

} elsif ( $FORM{'cgiaction'} eq 'edit_config' ) {
  my $output = Whostmgr::Maldet::get_config($FORM{'file'});

  Cpanel::Template::process_template(
  'whostmgr',
  {
    "template_file" => "maldet/editor.tmpl",
    "print"         => 1,
    "config_str"    => $output->{content},
    "config_name"    => $output->{id},
  });
} elsif ( $FORM{'cgiaction'} eq 'save_config' ) {
  Whostmgr::Maldet::save_config($FORM{'config_filename'}, $FORM{'config_content'});
  Whostmgr::HTMLInterface::redirect('index.cgi');
} elsif ( $FORM{'cgiaction'} eq 'scanuser' ) {
  my $output = Whostmgr::Maldet::scan_user($FORM{'username'});

  Cpanel::Template::process_template(
  'whostmgr',
  {
    "template_file" => "maldet/start_scan.tmpl",
    "print"         => 1,
    "output"        => $output,
  });
} elsif ( $FORM{'cgiaction'} eq 'scan_all_recent') {
  my $output = Whostmgr::Maldet::scan_all_recent($FORM{'recent'});

  Cpanel::Template::process_template(
  'whostmgr',
  {
    "template_file" => "maldet/start_scan.tmpl",
    "print"         => 1,
    "output"        => $output,
  });
} elsif ( $FORM{'cgiaction'} eq 'enableuser' ) {
  Whostmgr::Maldet::enable_userscan();
  Whostmgr::HTMLInterface::redirect('index.cgi');
} elsif ( $FORM{'cgiaction'} eq 'disableuser' ) {
  Whostmgr::Maldet::disable_userscan();
  Whostmgr::HTMLInterface::redirect('index.cgi');
}

1;
