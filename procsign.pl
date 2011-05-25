#!/usr/bin/perl -w
# This program uses the codesign(1) program to validate the signature
# of all running processes, as well as printing them grouped by certificate
# chain.
#
# on x86_64 systems, run with:
#   VERSIONER_PERL_PREFER_32_BIT=yes ./procsign.pl

use Mac::Processes;

my @hiddenchains;
my $hideapple = 0;
if ($ARGV[0] eq "--hide-apple") {
  push @hiddenchains, "Software Signing/Apple Code Signing Certification Authority/Apple Root CA";
}

my %process_signed_by;
my %ps;
while ( ($psn, $psi) = each(%Process) ) {
  my $executable = $psi->processAppSpec;
  my $pid = GetProcessPID($psn);
  my @signdata = split /\n/, `codesign -dvvv "$executable" 2>&1`;

  if (system("codesign -v $pid 2>&1")) {
    print "\t" . $executable . "\n";
  }
  for (@signdata) {
    chomp;
    my ($key, $value) = split /=/, $_, 2;
    $ps{$psn}{'signdata'}{$key} = [ ] unless $ps{$psn}{'signdata'}{$key};
    if ($value && $value ne "") {
      push @{$ps{$psn}{'signdata'}{$key}}, $value;
    }
  }

  my $path = "";
  $path = join('/', @{$ps{$psn}{'signdata'}{'Authority'}}) if $ps{$psn}{'signdata'}{'Authority'};
  $ps{$psn}{'signpath'} = $path;
  $process_signed_by{$path} = [ ] unless $process_signed_by{$path};
  push @{$process_signed_by{$path}}, $psi;
}

my $lastapp = "";
my $apprepeatcount = 0;
CHAIN: for (sort keys %process_signed_by) {
  my $path = $_;
  my @psis = @{$process_signed_by{$path}};
  my $hidden = 0;
  for (@hiddenchains) {
    next CHAIN if $_ eq $path;
  }
  if ($path) {
    print "\nProcesses signed by $path:\n";
  } else {
    print "\nUnsigned processes:\n";
  }
  for (@psis) {
    my $psi = $_;
    if ($lastapp eq $psi->processAppSpec) {
      $apprepeatcount++;
    } else {
      if ($apprepeatcount > 0) {
	print "\t (x" . $apprepeatcount . ")\n";
      }
      $apprepeatcount=0;
      print "\t" . $psi->processAppSpec . " (pid " .GetProcessPID($psi->processNumber). ")\n";
    }
    $lastapp = $psi->processAppSpec;
  }
  if ($apprepeatcount > 0) {
    print "\t (x" . $apprepeatcount . ")\n";
    $lastapp = ""; $apprepeatcount = 0;
  }
}
