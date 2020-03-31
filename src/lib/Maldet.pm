package Cpanel::Plugins::Maldet;

use strict;
use warnings;

use Cpanel ();
use Cpanel::SafeRun::Errors ();
use Cpanel::SafeDir::MK ();
use Cpanel::PwCache ();
use Cpanel::ForkAsync ();

use File::Copy;
use Date::Parse;
use Time::HiRes;
use IO::Handle;

our $LMD_BIN = '/usr/local/sbin/maldet';
our $LMD_DIR = '/usr/local/maldetect';
our $QUAR_PATH = '/maldet/quarantine';
our $LOG_PATH = '/.maldet/logs';

sub log_file {
  my $home = Cpanel::PwCache::gethomedir();

  my $path = "$home$LOG_PATH";
  my $time = Time::HiRes::gettimeofday();
  my $log  = "${path}/maldet-${time}.log";

  Cpanel::SafeDir::MK::safemkdir($path);
  open( my $fh, '>', $log )
    or die Cpanel::Exception::create(
     'IO::FileOpenError',
     [ 'path' => $log, 'error' => $!, 'mode' => '>' ]
    );

  return ( $log, $fh );
}

sub latest {
  my $lockfile = "$Cpanel::homedir/.maldet.scan";
  my $child_pid;
  my $child_time;

  if ( -e $lockfile) {
    if (open(my $fh, '<', $lockfile)) {
      {
        local $/;
        $child_pid = <$fh>;
        chomp $child_pid;
      }
      close($fh);
      $child_time = (stat($lockfile))[9];
      waitpid( $child_pid, 0 );
      my $reports = Cpanel::Plugins::Maldet::report_list();
      my $report = @{$reports}[0];
      return $report;
    }
  } else {
    my $reports = Cpanel::Plugins::Maldet::report_list();
    my $report = @{$reports}[0];
    return $report;
  }
  return { 'pid' => $child_pid, 'time' => $child_time };
}

sub scan_home {
  my $scandir = "$Cpanel::homedir/public_html";
  my $lockfile = "$Cpanel::homedir/.maldet.scan";

  my $child_pid;
  my $child_time;
  if ( -e $lockfile) {
    if (open(my $fh, '<', $lockfile)) {
      {
        local $/;
        $child_pid = <$fh>;
        chomp $child_pid;
      }
      close($fh);
      $child_time = (stat($lockfile))[9];
      Cpanel::ForkAsync::do_in_child( sub {
        waitpid( $child_pid, 0 );
        exit();
      });
     }
  } else {
    my $reports = Cpanel::Plugins::Maldet::report_list();
    my $last_scan = @{$reports}[0];
    if ($last_scan) {
      my $date = str2time($last_scan->{'date'});
      if (($date + 3600) > time() ) {
        return {};
      }
    }

    $child_time = time();
    $child_pid = Cpanel::ForkAsync::do_in_child( sub {
      $SIG{'INT'} = $SIG{'QUIT'} = $SIG{'ABRT'} = $SIG{'TERM'} = unlink $lockfile;
      open( my $lock_fh, '>', $lockfile );
      print $lock_fh $$;
      close($lock_fh);
      my ( $logfile, $log_fh ) = Cpanel::Plugins::Maldet::log_file();
      my $result = Cpanel::SafeRun::Errors::saferunallerrors($LMD_BIN, '-a', $scandir);
      print $log_fh $result;
      close($log_fh);
      unlink $lockfile;
      exit();
    } );
  }

  return { 'pid' => $child_pid, 'time' => $child_time };
}

sub running {
  my $lockfile = "$Cpanel::homedir/.maldet.scan";
  return ( -e $lockfile ) || 0;
}

sub recent {
  my $reports = Cpanel::Plugins::Maldet::report_list();
  my $last_scan = @{$reports}[0];
  if ($last_scan) {
    my $date = str2time($last_scan->{'date'});
    if (($date + 3600) > time() ) {
      return 1;
    }
  }
  return 0;
}

sub report {
  my $reportid = shift;
  return {'id' => 'unknown', 'str' => 'Report not found!', 'err' => 'Report not found!'} unless $reportid =~ /^[\d\-\.]+$/i;

  my $user = $Cpanel::user;
  my $file = "$LMD_DIR/pub/$user/sess/session.$reportid";

  if (-e $file) {
    my @fileconts;
    my $str;
    if (open(my $fh, '<:encoding(UTF-8)', $file)) {
      {
       	local $/;
        $str = <$fh>;
      }
      close($fh);
      return {'id' => $reportid, 'str' => $str};
    }
    return {'id' => $reportid, 'err' => 'Could not open report', 'str' => 'Error!'};
  } else {
    return {'id' => $reportid, 'err' => 'Report not found', 'str' => 'Report not found!'};
  }
}

sub restore {
  my $reportid = shift;
  my $wanted_file = shift;

  my $report = Cpanel::Plugins::Maldet::report($reportid);
  return if $report->{err};

  my $parsed = Cpanel::Plugins::Maldet::parse_report($report->{'str'});

  my $home = Cpanel::PwCache::gethomedir();
  my $path = "$home$QUAR_PATH/$reportid";
  Cpanel::SafeDir::MK::safemkdir($path);

  foreach my $file (@{$parsed->{'file_arr'}}) {
    next if (($wanted_file) && ($wanted_file ne $file->{'file'}));

    my $basename = $file->{'file'};
    $basename =~ s/\//_/g;

    if (-e $path . "/$basename") {
      move( $path . "/$basename", $file->{file} );
    }
  }

  return 1;
}

sub quarantine {
  my $reportid = shift;
  my $wanted_file = shift;

  my $report = Cpanel::Plugins::Maldet::report($reportid);
  return if $report->{err};

  my $parsed = Cpanel::Plugins::Maldet::parse_report($report->{'str'});

  my $home = Cpanel::PwCache::gethomedir();
  my $path = "$home$QUAR_PATH/$reportid";
  Cpanel::SafeDir::MK::safemkdir($path);

  foreach my $file (@{$parsed->{'file_arr'}}) {
    next if (($wanted_file) && ($wanted_file ne $file->{'file'}));

    if (-e $file->{'file'}) {
      my $basename = $file->{'file'};
      $basename =~ s/\//_/g;
      move( $file->{file}, $path . "/$basename" );
    }
  }

  return 1;

}

sub report_list {
  my $result = Cpanel::SafeRun::Errors::saferunallerrors($LMD_BIN, '--report', 'list');
  my @RES = split( /\n/, $result );
  my @reports;
  foreach my $line (@RES) {
    if ($line =~ /^([\s\w:]+)\s+\|\s+SCANID:\s+([^\s]+).*RUNTIME:\s+([0-9]+)s.*FILES:\s+([0-9]+).*HITS:\s+([0-9]+).*CLEANED:\s+([0-9]+)$/) {
      chomp $1;
      push @reports, { 'date' => $1, 'scanid' => $2, 'runtime' => $3, 'files' => $4, 'hits' => $5, 'cleaned' => $6 };
    }
  }

  \@reports;

}

sub parse_report {
  my $report = shift;
  my $home = Cpanel::PwCache::gethomedir();

  my @RES = split( /\n/, $report );
  my $data = {
    'id' => '',
    'files' => 0,
    'hits' => 0,
    'cleaned' => 0,
    'find' => 0,
    'scan' => 0,
    'start' => 0,
    'end'   => 0,
    'path' => '',
    'str'   => $report,
    'file_arr' => [],
  };
  foreach my $line (@RES) {
    if ($line =~ /^SCAN ID:\s+([\d\.\-]+)$/) {
      $data->{'id'} = $1;
    }
    if ($line =~ /^ELAPSED:\s+([\d]+)s\s+\[find: ([0-9]+)s\]$/) {
      $data->{'scan'} = $1;
      $data->{'find'} = $2;
    }
    if ($line =~ /^PATH:\s+(.*)$/) {
      $data->{'path'} = $1;
    }
    if ($line =~ /^TOTAL FILES:\s+([0-9]+)$/) {
      $data->{'files'} = $1;
    }
    if ($line =~ /^TOTAL HITS:\s+([0-9]+)$/) {
      $data->{'hits'} = $1;
    }
    if ($line =~ /^TOTAL CLEANED:\s+([0-9]+)$/) {
      $data->{'cleaned'} = $1;
    }
    if ($line =~ /^STARTED:\s+(.*)$/) {
      $data->{'start'} = str2time($1);
      $data->{'start_str'} = $1;
    }
    if ($line =~ /^COMPLETED:\s+(.*)$/) {
      $data->{'end'} = str2time($1);
      $data->{'end_str'} = $1;

    }
    if ($line =~ /^([^ ]+)\s+:\s+(.*)$/) {
      my $exists = -e $2;
      my $quarantine = undef;
      if (!$exists) {
        my $basename = $2;
        $basename =~ s/\//_/g;
        my $path = "$home$QUAR_PATH/".$data->{'id'}."/$basename";
        $quarantine = -e $path;
      }
      push @{$data->{'file_arr'}}, { 'signature' => $1, 'file' => $2, 'exists' => $exists, 'quarantine' => $quarantine };
    }
  }

  return $data;
}

sub enabled {
  my $config = Cpanel::Plugins::Maldet::get_config();
  return $config->{scan_user_access} || 0;
}

sub get_config {
  my $file = "$LMD_DIR/conf.maldet";
  my $config;
  if (-e $file) {
    if (open(my $fh, '<', $file)) {
      while (my $row = <$fh>) {
        next if $row =~ /^#/;
        next if $row =~ /^$/;
        if ($row =~ /^([a-z_]+)=\"([^\"]+)\"/) {
          $config->{$1} = $2;
        }
      }
    }
  }
  return $config;
}

1;
