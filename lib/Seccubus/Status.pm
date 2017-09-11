# ------------------------------------------------------------------------------

package Seccubus::Status;

our @ISA = ('Exporter');

our @EXPORT = qw (
    calculate_status
);

use Carp;
use strict;
use SeccubusV2;
use Data::Dumper;

sub calculate_status {
	my @statuses = @_;

	my $buf = shift @statuses;
	while ($#statuses >= 0) {
		my $tmp = shift(@statuses);
		$buf = status_pair($buf, $tmp);
	}
	return $buf;
}

sub status_pair {
	my @status_list = @_;
	@status_list = sort {$a <=> $b} @status_list;

	my %status_human_readable = (
		'New'		  => 1,
	    'Changed'	  => 2,
		'InWork'	  => 3,
		'FalsePos'	  => 4,
		'Gone'		  => 5,
		'Closed'	  => 6,
		'Returned'	  => 7,
		'Pending'	  => 8,
		'AdminReview' => 9,
		'Recurring'	  => 10,
		'MASKED'	  => 99 
	);

	my @status = (                                                                               
        ##########################################################################################################################################
	    ####     New   # Changed  #  # FalsePos #   Gone   #  # Returned # Pending  #  AdminReview  # Recurring   #  MASKED        #             #
        ##########################################################################################################################################
		[] ,           #          #  #          #          #  #          #          #               #             #                #             #
		['', 'New'     ,'Changed' ,'','Changed' ,'Changed' ,'','Returned','New'     ,'AdminReview'  ,'Recurring'  ,'New'        ], # New         #
		['', ''        ,'Changed' ,'','Changed' ,'Changed' ,'','AdminRev','Changed' ,'AdminReview'  ,'Changed'    ,'Changed'    ], # Changed     #
		[] ,           #          #  #          #          #  #          #          #               #             #                # InWork      #
		['', ''        ,''        ,'','FalsePos','Gone'    ,'','AdminRev','Pending' ,'AdminReview'  ,'Recurring'  ,'FalsePos'   ], # FalsePos    #
		['', ''        ,''        ,'',''        ,'Gone'    ,'','AdminRev','Pending' ,'AdminReview'  ,'Recurring'  ,'Gone'       ], # Gone        #
		[] ,           #          #  #          #          #  #          #          #               #             #                # Closed      #
		['', ''        ,''        ,'',''        ,''        ,'','Returned','AdminRev','AdminReview'  ,'Returned'   ,'Returned'   ], # Returned    #
		['', ''        ,''        ,'',''        ,''        ,'',''        ,'Pending' ,'AdminReview'  ,'Recurring'  ,'Pending'    ], # Pending     #
		['', ''        ,''        ,'',''        ,''        ,'',''        ,''        ,'AdminReview'  ,'AdminReview','AdminReview'], # AdminReview #
		['', ''        ,''        ,'',''        ,''        ,'',''        ,''        ,''             ,'Recurring'  ,'Recurring'  ], # Recurring   #
		['', ''        ,''        ,'',''        ,''        ,'',''        ,''        ,''             ,''           ,'MASKED'     ], # Masked      #
	);  ####           #          #  #          #          #  #          #          #               #             #                #             #
        ########################################################################################################################################## 
    return $status_human_readable{$status[$status_list[0]][$status_list[1]]};
}

return 1;