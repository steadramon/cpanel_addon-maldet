package Whostmgr::Maldet;

use strict;
use warnings;

use Cpanel ();
use Cpanel::SafeRun::Dynamic ();
use Cpanel::Binaries ();
use Whostmgr::Accounts::List ();
use Cpanel::SafeRun::Errors;
use Cpanel::PwCache;
use Config::Tiny;
use Cpanel::Config::LoadWwwAcctConf ();

our @config_files = ('conf.maldet', 'ignore_file_ext', 'ignore_inotify', 'ignore_paths', 'ignore_sigs');
our $LMD_BIN = '/usr/local/sbin/maldet';
our $LMD_DIR = '/usr/local/maldetect';
our $LMD_CONF = "$LMD_DIR/conf.maldet";

sub configs {
  return @config_files;
}

sub get_config {
  my $config = shift;
  my %params = map { $_ => 1 } @config_files;
  if (exists($params{$config})) {
    my $file = "$LMD_DIR/$config";
    my $str;
    if (-e $file) {
      if (open(my $fh, '<', $file)) {
        {
          local $/;
          $str = <$fh>;
          chomp $str;
        }
        close($fh);
        return {'id' => $config, 'content' => $str};
      }
    }
    return {'filename' => 'hello'.$config, 'content' => $str};
  }
  return {'error' => 'Invalid config file'};
}

sub save_config {
  my $config = shift;
  my $config_str = shift;

  my %params = map { $_ => 1 } @config_files;
  if (exists($params{$config})) {
    my $file = "$LMD_DIR/$config";
    my $str;
    if (-e $file) {
      if (open(my $fh, '>', $file)) {
        $config_str =~ s/\r\n/\n/g;
        print $fh $config_str;
        close($fh);
      }
    }
  }
}

sub report {
  my $reportid = shift;

  return {'id' => 'unknown', 'str' => 'Report not found!'} unless $reportid =~ /^[\w\-\.]+$/i;

  my $file = "$LMD_DIR/sess/session.$reportid";

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
    return {'id' => $reportid, 'str' => 'Error!'};
  } else {
    return {'id' => $reportid, 'str' => 'Report not found!'};
  }


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

sub update_sigs {
  my $result = Cpanel::SafeRun::Errors::saferunallerrors($LMD_BIN, '--update-sigs');
  return $result;
}

sub update_maldet {
  my $result = Cpanel::SafeRun::Errors::saferunallerrors($LMD_BIN, '--update-ver');
  return $result;
}

sub scan_user {
  my $user = shift;
  my $homedir      = Cpanel::PwCache::gethomedir($user);
  if ($homedir) {
    my $result = Cpanel::SafeRun::Errors::saferunallerrors($LMD_BIN, '-b', '-a', "$homedir/public_html");
    return $result;
  }
}

sub scan_all_recent {
  my $recent = shift;
  $recent = int( $recent )|| 2;

  my $cref = Cpanel::Config::LoadWwwAcctConf::loadwwwacctconf();
  my $homematch = ( defined $cref->{'HOMEMATCH'} ? $cref->{'HOMEMATCH'} : ( -d '/home' ? '/home' : '/usr/home' ) );
  $homematch =~ s/\*//;
  $homematch =~ s/^([^\/].*)/\/$1/;

  my $result = Cpanel::SafeRun::Errors::saferunallerrors($LMD_BIN, '-b', '-r', "$homematch?/?/public_html", $recent);
  return $result;
}

sub plugin_version {
  my $file = "/usr/local/cpanel/whostmgr/docroot/cgi/addons/maldet/version.txt";
  my $content = 'unknown';
  if (-e $file) {
    if (open(my $fh, '<:encoding(UTF-8)', $file)) {
      {
       	local $/;
       	$content = <$fh>;
      }
      close($fh);
    }
  }

  return $content;
}

sub sig_version {
  my $file = "$LMD_DIR/sigs/maldet.sigs.ver";
  my $content = 'unknown';
  if (-e $file) {
    if (open(my $fh, '<:encoding(UTF-8)', $file)) {
      {
        local $/;
        $content = <$fh>;
      }
      close($fh);
    }
  }

  return $content;
}

sub version {
  my $result = Cpanel::SafeRun::Errors::saferunallerrors($LMD_BIN);
  my @RES = split( /\n/, $result );
  my $version = $RES[0];
  $version =~ s/^Linux Malware Detect v//g;
  $version;
}

sub load_mdconfig {
  my $config = Config::Tiny->new;
  $config = Config::Tiny->read( $LMD_CONF );
  return $config->{_};
}

sub enable_userscan {
  my $config = Config::Tiny->new;
  $config = Config::Tiny->read( $LMD_CONF );
  $config->{_}->{'scan_user_access'} = '"1"';
  $config->write( $LMD_CONF );
}

sub disable_userscan {
  my $config = Config::Tiny->new;
  $config = Config::Tiny->read( $LMD_CONF );
  $config->{_}->{'scan_user_access'} = '"0"';
  $config->write( $LMD_CONF );
}

1;
