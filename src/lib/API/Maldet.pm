use strict;
use warnings;

package Cpanel::API::Maldet;

use Cpanel                     ();
use Cpanel::Plugins::Maldet    ();

sub enabled {
  my ( $args, $result ) = @_;
  my $data = Cpanel::Plugins::Maldet::enabled();
  $result->data($data);
  return 1
}

sub running {
  my ( $args, $result ) = @_;
  my $data = Cpanel::Plugins::Maldet::running();
  $result->data($data);
  return 1
}

sub recent {
  my ( $args, $result ) = @_;
  my $data = Cpanel::Plugins::Maldet::recent();
  $result->data($data);
  return 1
}

sub latest {
  my ( $args, $result ) = @_;
  my $data = Cpanel::Plugins::Maldet::latest();
  $result->data($data);
  return 1;
}

sub scan_home {
  my ( $args, $result ) = @_;
  my $data = Cpanel::Plugins::Maldet::scan_home();
  $result->data($data);
  return 1;
}

sub reports {
  my ( $args, $result ) = @_;
  my $data = Cpanel::Plugins::Maldet::report_list();
  $result->data($data);
  return 1;
}

sub get_report {
  my ( $args, $result) = @_;
  my $data = Cpanel::Plugins::Maldet::report( $args->get('report_id') );
  my $ret = Cpanel::Plugins::Maldet::parse_report($data->{str});
  $result->data($ret);
  return 1;
}

sub quarantine {
  my ( $args, $result) = @_;
  my $data = Cpanel::Plugins::Maldet::quarantine( $args->get('report_id') );
  $result->data($data);
  return 1;
}

sub quarantine_file {
  my ( $args, $result) = @_;
  my $data = Cpanel::Plugins::Maldet::quarantine( $args->get('report_id'), $args->get('file') );
  $result->data($data);
  return 1;
}

sub restore {
  my ( $args, $result) = @_;
  my $data = Cpanel::Plugins::Maldet::restore( $args->get('report_id') );
  $result->data($data);
  return 1;
}

sub restore_file {
  my ( $args, $result) = @_;
  my $data = Cpanel::Plugins::Maldet::restore( $args->get('report_id'), $args->get('file') );
  $result->data($data);
  return 1;
}

1;
