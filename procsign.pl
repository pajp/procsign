#
# This program uses the codesign(1) program to validate the signature
# of all running processes, as well as printing them grouped by certificate
# chain.
#

use Mac::Processes;

my %process_signed_by;
my %ps;
while ( ($psn, $psi) = each(%Process) ) {
  my $executable = $psi->processAppSpec;
  my $pid = GetProcessPID($psn);
  my @signdata = split /\n/, `codesign -dvvv "$executable" 2>&1`;

  if (system("codesign -v $pid")) {
    print "\t" . $executable . "\n";
  }
  for (@signdata) {
    chomp;
    my ($key, $value) = split /=/, $_, 2;
    $ps{$psn}{'signdata'}{$key} = [ ] unless $ps{$psn}{'signdata'}{$key};
    push @{$ps{$psn}{'signdata'}{$key}}, $value unless $value eq "";
  }
  my $path = join('/', @{$ps{$psn}{'signdata'}{'Authority'}});
  $ps{$psn}{'signpath'} = $path;
  $process_signed_by{$path} = [ ] unless $process_signed_by{$path};
  push @{$process_signed_by{$path}}, $psi;
}

my $lastapp = "";
my $apprepeatcount = 0;
for (sort keys %process_signed_by) {
  my $path = $_;
  my @psis = @{$process_signed_by{$path}};
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