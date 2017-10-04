# ------------------------------------------------------------------------------
# Copyright 2017
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

package Seccubus::Inventory;

use strict;
use Exporter;
use Seccubus::Rights;
 
our @ISA = ('Exporter');

our @EXPORT = qw (
    new
    add_network_oblect
);

use Carp;
use Net::IP;
use Socket;

use SeccubusV2;
use Seccubus::DB;
use Seccubus::Rights;

sub new {
    my ($class, %args) = @_;

    my $self = bless {} , $class;
    die "Workspace number not set" unless ($args{workspace_id});

    $self -> {workspace_id} = $args{workspace_id};

    if (may_write($self -> {workspace_id})) {
        $self -> {write} = 1;
    }

    if (may_read($self -> {workspace_id})) {
        $self -> {read} = 1;
    }

    if ($args{timestamp}) {
        $self -> {timestamp} = $args{timestamp};
    } else {
        $self -> {timestamp} = time();
    }

    return $self;
}

sub check_object {
    my ($self, $parent_id, $key, $value) = @_;
    my $query = "select id from inventory where `parent_id` = ? and `key` = ? and `value` = ?";
    my @result = sql( "return"    => "array",
                "query" => $query,
                "values"    => [$parent_id, $key, $value],
              );
    return $result[0] if ($#result == 0);
    die "Strange problem: many objects with same (parent_id, key, value)\n" if ($#result > 0);
    return 0;
}

sub check_object_by_id {
    my ($self, $id) = @_;

    my $query = "select count(id) from inventory where `id` = ? and workspace_id = ?";
    my @result = sql( "return"    => "array",
                "query" => $query,
                "values"    => [$id, $self -> {workspace_id}],
              );
    return 1 if ($#result == 0);
    return 0;
}

sub update_timestamp {
    my ($self, $obj_id) = @_;
    my $query = "update inventory set timestamp = ? where id = ?";
    my $ref = sql( "return"    => "ref",
                      "query"     => $query,
                      "values"    => [$self -> {timestamp}, $obj_id],
                    );
}

sub get_id_by_key_value{
    my ($self, $key, $value) = @_;

}

sub insert {
    my ($self, %args) = @_;

    # We check if object with this parent already exists
    my $check_id = $self -> check_object($args{parent_id}, $args{key}, $args{value});
    if ($check_id) {
        # Update timestamp in this object to actual
        $self -> update_timestamp($check_id);
        return $check_id;
    }

    $args{timestamp} = $self -> {timestamp};
    $args{change_timestamp} = $self -> {timestamp};
    $args{workspace_id} = $self -> {workspace_id};
    my @keys;
    my @values;
    my $args;
    my $query = "insert into inventory (";
    for (keys %args) {
        push (@keys,'`' . $_ . '`');
        push (@values, "?");
        push (@$args, $args{$_});
    }
    $query .= join (", ", @keys) . ") values (" ;
    $query .= join (", ", @values) . ")";

    my $id = sql( "return"    => "id",
                      "query"     => $query,
                      "values"    => $args,
                    );
    return $id;
}

sub search {
    my ($self, %args) = @_;

    my @qargs;
    my $query = "select id, parent_id, `key`, `value` from inventory where workspace_id = ?";

    push (@qargs, $self -> {workspace_id});
    if ($args{key}) {
        $query .= " and where `key` = ?";
        push (@qargs, $args{key});
    }
    if ($args{value}) {
        $query .= " and where `value` like ?";
        push (@qargs, $args{value});
    }

    my @result = sql( "return"    => "array",
                "query" => $query,
                "values"    => \@qargs,
              );

    return @result;
}

return 1;
    