# ------------------------------------------------------------------------------
# Copyright 2018	 Oleg Makarov
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
package Seccubus::Scans2;

=head1 NAME $RCSfile: SeccubusScans.pm,v $

This Pod documentation generated from the module SeccubusScans gives a list of
all functions within the module.

=cut

use strict;
use Exporter;
use SeccubusV2;
use Seccubus::DB;
use Seccubus::Rights;
use Seccubus::Notifications;
use Data::Dumper;

our @ISA = ('Exporter');

our @EXPORT = qw (
	get_schedule
	get_nodes
	queue_add
	get_task
	task_from_queue
	run_scan
	%queues
);

use Carp;

our %queues;

sub get_schedule {
	my $sql = 'SELECT scan_id, min, hour, week_day, month_day, month_num, urgency, type FROM schedule';
	my $schedule = sql ('return' => 'ref', 
		   		        'query'  => $sql);


	for my $record (@$schedule) {
		my ($scan_id, $min, $hour, $week_day, $month_day, $month_num, $urgency, $type) = @$record;
		my $check = check_schedule($min, $hour, $week_day, $month_day, $month_num);
		if ($check) {
			my $task = get_task($scan_id);
			queue_add($task, $task -> {node_id}, $urgency);
		}
	}
}


sub queue_add {
	my $task    = shift;
	my $node_id = shift;
	my $urgency = shift;

	# Здесь нужно сделать проверку, можно ли этот таск выполнять на этой ноде, существует ли такая нода и ваще.

	if ($urgency == 0) {
		unshift(@{$queues{$node_id}}, $task);
	} else {
		push(@{$queues{$node_id}}, $task);
	}

}

sub task_from_queue {
	my $node_id = shift;
	if ($#{$queues{$node_id}} > -1) {
		return shift(@{$queues{$node_id}})
	} else {
		return 0;
	}
}


sub get_task {
	my $task_id = shift;
	my %task;
	my @fields = qw(node_id target_ips target_posts scanner port user password scan_id workspace_id scan_policy description scanner_host);
	my $sql = 'SELECT scanners.node_id,
				targets.ips,
				targets.portlist,
				scanners.scannername, 
				scanners.port,
				scanners.user, 
				scanners.password,
				scans2.id,
				scans2.workspace_id,
				scans2.scan_policy,
				scans2.description,
				nodes.host,
				nodes.maxrun
				FROM scans2, targets, scanners, nodes
				WHERE scans2.id = ? and 
				scans2.scanner_id = scanners.id and 
				scans2.target_id = targets.id and
				scanners.node_id = nodes.id';
	my $schedule = sql ('return' => 'ref', 
		                'values' => [$task_id],
		   		        'query'  => $sql);

	for (0..$#fields) {
		$task{$fields[$_]} = ${$schedule}[0][$_];
	}
	return \%task;	
}


sub get_nodes {
	my $nodes_obj = shift;
	my $sql = 'SELECT id, host, maxrun, description, lock_workspace_id FROM nodes';
	my $nodes = sql ('return' => 'ref', 
		   		     'query'  => $sql);
	for my $node (@$nodes) {
		$$nodes_obj -> {$$node[0]} -> {host}              = $$node[1];
		$$nodes_obj -> {$$node[0]} -> {maxrun}            = $$node[2];
		$$nodes_obj -> {$$node[0]} -> {description}       = $$node[3];
		$$nodes_obj -> {$$node[0]} -> {lock_workspace_id} = $$node[4];
		$$nodes_obj -> {$$node[0]} -> {started_scans}     = 0;
	}
	return $nodes;
}


#check_schedule($min, $hour, $week_day, $month_day, $month_num);
sub check_schedule {
	my $count = 0;
	my @localtime;
	(undef, $localtime[0], $localtime[1], $localtime[3],$localtime[4],undef,$localtime[2]) = localtime(time);

	for my $c (0..4) {
		$count++ if (int($_[$c]) == int($localtime[$c]) || ($_[$c] eq '*'));
	}
	return 1 if ($count == 5);
	return 0 if ($count < 5);
}


sub run_scan {
	my $workspace_id = shift;
	my $task = shift;
	my %task = %{ $task };
	my $verbose = 0;
	my $print = 0;
	my $param;

	my $tempfile = "/tmp/seccubus.hosts.$$";

	my $config = SeccubusV2::get_config();
	if ( ! -e $config->{paths}->{scanners} . "/" . $task{scanner} . "/scan" ) {
		die "Scan script for $task{scanner} is not installed at " . $config->{paths}->{scanners} . "/$task{scanner}/scan";
	}

	if ($task{user}) {
		$param .= ' --user \'' . $task{user} . '\' ';
 	}

 	if ($task{scanner_host}) {
 		$param .= ' --server \'' . $task{scanner_host} . '\' ';
 	}

 	if ($task{scanner_port}) {
 		$param .= ' --port \'' . $task{port} . '\' ';
 	}


	if ($task{scanner} =~ /^Nessus/ || $task{scanner} eq "OpenVAS") {
		$param = $param .' --pw \''. $task{password}. '\' ';
	};

	if ($task{scan_policy}) {
		$param = $param .' --policy \''. $task{scan_policy}. '\' ';
	}

	$param .= ' --hosts \'' . $tempfile . '\'';

	open(my $TMP, ">", "$tempfile") or die "Unable to open $tempfile for write";
	print $TMP "$task{target_ips}\n";
	close $TMP;

	$param .= ' --workspace \'' .$workspace_id . '\'';	
	$param .= ' --scan \'' .$task{description} . '\'';	

	my $cmd = $config->{paths}->{scanners} . "/$task{scanner}/scan $param";
	my $printcmd = $config->{paths}->{scanners} . "/$task{scanner}/scan $param";
	if ( $verbose == -1 ) {
		$cmd .= " -q";
		$printcmd .= " -q";
	} else {
		$cmd .= " -v" x $verbose;
		$printcmd .= " -v" x $verbose;
	}
	# Nodelete (issue #14)
	if ( $task{nodelete} ) {
		$cmd .= " --nodelete";
		$printcmd .= " --nodelete";
	}


	# Starting the actual scan
	print "cmd: $printcmd\n" if $print;
	my $result = "cmd: $printcmd\n";
	open( my $CMD, "-|", $cmd) or die "Unable to open pipe to '$printcmd'";
 	select $CMD; $| = 1 if $print;
 	select STDOUT; $| = 1 if $print;
 	while (<$CMD>) {
		$result .= $_;
		print $_ if $print;
	}
	close $CMD;
 	select STDOUT; $| = 0 if $print;
	unlink $tempfile;

	# Sending post scan notifications
	print "Sending notifications for scan end...\n" if $print;
	my $sent = do_notifications($workspace_id, $task{scan_id}, 2);
	print "$sent notification(s) sent\n" if $print;

	return $result;
}

# Close the PM file return 1;
return 1;