use strict;
use warnings;

use ExtUtils::MakeMaker;
use ExtUtils::MakeMaker::Config;

my $output = WriteMakefile(
    NAME           => 'APNIC::RDAP::OpenID::Proxy',
    AUTHOR         => 'Software <software@apnic.net>',
    LICENSE        => 'bsd',
    VERSION_FROM   => 'lib/APNIC/RDAP/OpenID/Proxy.pm',
    META_MERGE     => {
        resources => {
            repository => 'https://github.com/APNIC-net/rdap-openid-proxy'
        }
    },
    EXE_FILES      => [ qw(bin/rdap-openid-proxy) ],
    PREREQ_PM      => { 'Bytes::Random::Secure'  => 0,
                        'Crypt::JWT'             => 0,
                        'Test::More'             => 0,
                        'HTTP::Daemon'           => 0,
                        'YAML'                   => 0,
                        'LWP::UserAgent'         => 0,
                        'List::MoreUtils'        => 0,
                        'IO::Capture::Stderr'    => 0, }
);

1;
