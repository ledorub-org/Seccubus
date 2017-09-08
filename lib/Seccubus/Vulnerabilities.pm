# ------------------------------------------------------------------------------
# Copyright 2017 Frank Breedijk, Steve Launius, Oleg 
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
package Seccubus::Vulnerabilities;

=head1 NAME $RCSfile: SeccubusFindings.pm,v $

This Pod documentation generated from the module SeccubusFindings gives a list
of all functions within the module.

=cut

use strict;
use SeccubusV2;
use Seccubus::DB;
use Seccubus::Rights;
use Seccubus::Users;
use Seccubus::Issues;
use Algorithm::Diff qw( diff );
use Data::Dumper;

our @ISA = ('Exporter');

our @EXPORT = qw (
    get_vuln
    update_vuln
    calculate_vuln_status
);

use Carp;

sub update_vuln {
    my %arg = @_;
    # Check if the user has write permissions
    die "You don't have write permissions for this workspace!" unless may_write($arg{workspace_id});

    # Check for mandatory parameters
    foreach my $param ( qw(workspace_id) ) {
        die "Manditory parameter $param missing" unless exists $arg{$param};
    }
    # Check if status is a legal value
    if ( exists $arg{status} ) {
        unless ( ($arg{status} >=  1 && $arg{status} <= 6) || $arg{status} == 99 ) {
            die "Illegal status value $arg{status}";
        }
    }
    # Lets try to find out if a finding allready exists for this
    # host port plugin combination

    $arg{vuln_id} = sql (
        "return"	=> "array",
        "query"		=> "SELECT id
                        FROM vulnerabilities
                        WHERE workspace_id = ? AND ip = ? AND port = ? AND vulnid = ? AND vulntype = ?",
        "values"	=> [ $arg{workspace_id}, $arg{ip}, $arg{port}, $arg{vulnid}, $arg{vulntype} ],
        );

    # Lets set some default values
    $arg{overwrite} = 1 if not exists $arg{overwrite};
    $arg{status} = 1 unless $arg{status} or $arg{vuln_id};
    $arg{severity} = 0 unless exists $arg{severity} or $arg{vuln_id};
    confess("Invalid severity $arg{severity}") if ($arg{severity} < 0 || $arg{severity} > 5);

    my ( @fields, @values );
    foreach my $field ( qw(scan_id ip port plugin severity status run_id unid vulntype vulnid) ) {
        if ( exists($arg{$field}) ) {
            push @fields, $field;
            push @values, $arg{$field};
        }
    }
    if ( $arg{vuln_id} ) {
        # We need to update the record
        my $query = "update vulnerabilities set ";
        $query .= join " = ? , ", @fields;
        $query .= " = ?";
        if ( exists $arg{remark} ) {

            if ( $arg{overwrite}  ) {
                $query .= ", remark = ? ";
                push @values, $arg{remark};
            } else {
                if ( $arg{remark} ) {
                    $query .= ", remark = CONCAT_WS('\n', remark, ?) ";
                    push @values, $arg{remark};
                }
            }
        }
        $query .= "where id = ? and workspace_id = ?";

        sql( "return"	=> "handle",
             "query" 	=> $query,
             "values"	=> [ @values, $arg{vuln_id}, $arg{workspace_id} ]
           );
    } else {
        # We need to create the record
        push @fields, "workspace_id";
        push @values, $arg{workspace_id};
        if ( exists($arg{remark}) ) {
            push @fields, "remark";
            push @values, $arg{remark};
        }
        my $count = @fields;
        $count--;
        my $query = "insert into vulnerabilities(";
        $query .= join ",", @fields;
        $query .= ") values (";
        $query .= "? ," x $count;
        $query .= "? );";
        $arg{vuln_id} = sql( "return"	=> "id",
                    "query"		=> $query,
                    "values"	=> \@values,
                      );
    }

    vuln_finding_link($arg{vuln_id}, $arg{finding_id});
    return $arg{vuln_id};
}


sub vuln_finding_link {
    my $vuln = shift;
    my $finding = shift;

    my $result = sql (
        "return"    => "array",
        "query"     => "SELECT vulnerability_id, finding_id
                        FROM vulnerabilities2findings
                        WHERE vulnerability_id = ? AND finding_id = ?",
        "values"    => [ $vuln, $finding ],
        );
    if ($result == 0) {
        my $result = sql (
            "return"    => "handle",
            "query"     => "INSERT INTO vulnerabilities2findings 
                            (vulnerability_id, finding_id)
                            VALUES (?, ?)",
            "values"    => [ $vuln, $finding ],
            );
    }

}


sub get_vulns_by_finding {
    my $finding = shift;
    my @result = sql (
        "return"    => "array",
        "query"     => "SELECT vulnerability_id
                        FROM vulnerabilities2findings
                        WHERE finding_id = ?",
        "values"    => [ $finding ],
        );
    return @result;
}

sub get_findings_by_vuln {
    my $vuln = shift;
    my @result = sql (
        "return"    => "array",
        "query"     => "SELECT finding_id
                        FROM vulnerabilities2findings
                        WHERE vulnerability_id = ?",
        "values"    => [ $vuln ],
        );
    return @result;
}

sub get_findings_status_by_vuln {
    my $vuln = shift;
    my @findings_id = get_findings_by_vuln($vuln);
    return unless (@findings_id);
    my $status_sql = "SELECT status FROM findings WHERE id IN (";
    $status_sql .= join(",", split(" ", "? " x ($#findings_id + 1))) . ")";

    my @result = sql (
        "return"    => "array",
        "query"     => $status_sql,
        "values"    => [ @findings_id ],
        );
    return @result;
}

sub get_vuln_own_status {
    my $vuln = shift;
    my @status = sql (
        "return"    => "array",
        "query"     => "SELECT status
                        FROM vulnerabilities
                        WHERE id = ?",
        "values"    => [ $vuln ],
        );
    return $status[0];
}

sub calculate_vuln_status {
    my $vuln_id = shift;
    my $own_status = get_vuln_own_status($vuln_id);

    # Status 'InWork' overriding all another statuses;
    if ($own_status == 3) {
        return 3;
    }

    my @f_statuses = get_findings_status_by_vuln($vuln_id);

    # Check if all findings have same status
    unless ( grep {$_ ne $f_statuses[0]} @f_statuses ) {
        return $f_statuses[0];
    }

    # Ignore finding with statuses FalsePos, Gone, Pending, MASKED

    @f_statuses = grep {!  ($_ ~~ (qw(5 8 99 5))) } @f_statuses;

    # Check again if all findings have same status
    unless ( grep {$_ ne $f_statuses[0]} @f_statuses ) {
        return $f_statuses[0];
    }

    # Okay, what next?

    return 0;
}



# Close the PM file.
return 1;
