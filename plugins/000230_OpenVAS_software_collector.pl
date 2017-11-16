# Template findings processing plugin for Seccubus
# Header should to contain three fields: name, scanner, and state. 

# ------------------------------------------------------------------------------
# Header:
# ------------------------------------------------------------------------------
# name:    SoftwareCollector
# scanner: OpenVAS
# state:   enabled 
# ------------------------------------------------------------------------------
# Test data (optional):
# ------------------------------------------------------------------------------
# test_data:id:          "103999"
# test_data:finding_txt: "blahblah"
# test_data:finding_txt: "<dpkginfo_item id='937' xmlns='http://oval.mitre.org/XMLSchema/oval-system-characteristics-5'>"
# test_data:finding_txt: "   <name>lynx-cur</name>"
# test_data:finding_txt: "   <arch/>"
# test_data:finding_txt: "   <epoch/>"
# test_data:finding_txt: "   <release/>"
# test_data:finding_txt: "   <version>2.8.8pre4-1</version>"
# test_data:finding_txt: "   <evr datatype="evr_string"/>"
# test_data:finding_txt: "</dpkginfo_item>"
# test_data:finding_txt: "blahblah"
# test_data:finding_txt: "<dpkginfo_item id='13' xmlns='http://oval.mitre.org/XMLSchema/oval-system-characteristics-5linux'>"
# test_data:finding_txt: "   <name>attr</name>"
# test_data:finding_txt: "   <arch/>"
# test_data:finding_txt: "   <epoch/>"
# test_data:finding_txt: "   <release/>"
# test_data:finding_txt: "   <version>1:2.4.47-1ubuntu1</version>"
# test_data:finding_txt: "   <evr datatype='evr_string'/>"
# test_data:finding_txt: "</dpkginfo_item>"
# test_data:finding_txt: "blahblah"
# ------------------------------------------------------------------------------

sub {
    my $ref = shift; # This is reference to finding. 
                     # You can use $$ref -> {finding_field_name}. eg: $$ref -> {ip}.
                     # See doc in Plugins.pm for details


    my $inventory = shift; # This is ref to inventory object.

    if ($$ref -> {id} == '103999') {
        my $ip = $$ref -> {'ip'};
        my $finding = $$ref -> {finding_txt};
        $finding =~ s/\n//g;
        while ($finding =~ m|<dpkginfo_item[^>]*>(.*?)</dpkginfo_item>|m) {
            $finding = $';
            my $item = $1;
            my ($name) = $item =~ m|<name>([^<]+)</name>|;
            my ($version) = $item =~ m|<version>([^<]+)</version>|;
            $$inventory -> add_object('/' . $ip . '/container/software/"' . $name . '"/"' . $version . '"');
        }
    }
    return 1; # You should return 1 if the plugin has normally executed and 0 in other case.
}

