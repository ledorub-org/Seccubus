# ------------------------------------------------------------------------------
# Copyright 2017 Frank Breedijk, Steve Launius, Petr
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
    diff_vuln
);

use Carp;


sub get_vuln {
    my $workspace_id = shift or die "No workspace_id provided";
    my $finding_id = shift or die "No finding_id provided";

    if ( may_read($workspace_id) ) {
        my $params = [ $workspace_id, $workspace_id ];

        my $query = "
            SELECT 	finding_changes.id, findings.id, host,
                host_names.name, port, plugin,
                finding_changes.finding,
                finding_changes.remark,
                finding_changes.severity, severity.name,
                finding_changes.status, finding_status.name,
                user_id, username, finding_changes.time as changetime,
                runs.time as runtime
            FROM
                finding_changes LEFT JOIN users on (finding_changes.user_id = users.id ),
                finding_status, severity,
                runs, findings LEFT JOIN host_names ON findings.host = host_names.ip
            WHERE
                findings.workspace_id = ? AND
                findings.id = ? AND
                findings.id = finding_changes.finding_id AND
                finding_changes.severity = severity.id AND
                finding_changes.status = finding_status.id AND
                runs.id = finding_changes.run_id
            ORDER BY finding_changes.time DESC, finding_changes.id DESC
            ";


        return sql( "return"	=> "ref",
                    "query"	=> $query,
                    "values"	=> [ $workspace_id, $finding_id ]
                  );
    } else {
        die "Permission denied!";
    }
}


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
    foreach my $field ( qw(scan_id ip port plugin severity status run_id unid vulntype vulnid finding_id) ) {
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
    # Create an audit record
    #create_finding_change($arg{finding_id},$arg{timestamp},$arg{userid});
    return $arg{vuln_id};
}

=head2 create_finding_change (hidden)

This function adds a record to the finding_changes table.

=over 2

=item Parameters

=over 4

=item finding_id  - Manditory

=item timestamp - Optional - Timestamp for this change record

=item user_id - Optional - User_id to "blame" for this change

=back

=item Returns

THe inserted id.

=item Checks

None, this is a hidden function that will not be called through the API. All
checking should have been doine a higher levels.

=back

=cut

sub create_vuln_change {
    my $finding_id = shift or die "No fidnings_id given";
    my $timestamp = shift;
    my $user_id = shift;

    $user_id = get_user_id($ENV{SECCUBUS_USER}) unless $user_id;

    my @new_data = sql( "return"	=> "array",
            "query"		=> "select status, finding, remark, severity, run_id from findings where id = ?",
            "values"	=> [ $finding_id ],
              );
    my @old_data = sql( "return"	=> "array",
            "query"		=> "
                select status, finding, remark, severity, run_id from finding_changes
                where finding_id = ?
                order by id DESC
                limit 1",
            "values"	=> [ $finding_id ],
    );
    my $changed = 0;
    foreach my $i ( (0..4) ) {
        if ( $old_data[$i] ne $new_data[$i] || ( defined($old_data[$i]) && !defined($new_data[$i]) ) ||  ( ! defined($old_data[$i]) && defined($new_data[$i]) ) ) {
            $changed = 1;
            last;
        }
    }
    if ( $changed ) {
        my $query = "insert into finding_changes(finding_id, status, finding, remark, severity, run_id, user_id";
        $query .= ", time" if $timestamp;
        $query .= ") values (?, ?, ?, ?, ?, ?, ?";
        $query .= ", ?" if $timestamp;
        $query .= ")";
        my $values = [ $finding_id, @new_data, $user_id ];
        push @$values, $timestamp if $timestamp;

        sql( "return"	=> "id",
             "query"	=> $query,
             "values"	=> $values,
           );
    }
}

# Close the PM file.
return 1;
