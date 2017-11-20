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

package Seccubus::Kickstarts;

use strict;
use Exporter;
 
our @ISA = ('Exporter');

our @EXPORT = qw (
    kickstart
);

use Carp;
use Net::IP;
use Socket;
use Data::Dumper;

use SeccubusV2;
use Seccubus::DB;

sub kickstart {
    my $workspace_id = shift or confess "No workspace_id provided to update_run";
    my $timestamp = shift or confess "No timestamp provided to update_run";

    my @kickstarts = sql ( "return"    => "array",
                           "query"     => "SELECT kickstart FROM kickstarts WHERE workspace_id = ? and kickstart = ?;",
                           "values"    => [ $workspace_id, $timestamp ],
                         );
    if ($#kickstarts == -1) {

        my $kickstarts = sql ( "return"    => "handle",
                               "query"     => "INSERT INTO kickstarts VALUES (?, ?);",
                               "values"    => [ $workspace_id, $timestamp ],
                             );
    }
}

return 1;
    