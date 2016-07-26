package APNIC::RDAP::OpenID::Test::Utils;

use warnings;
use strict;

use APNIC::RDAP::OpenID::IDP;
use APNIC::RDAP::OpenID::Proxy;
use APNIC::RDAP::OpenID::Server;

use YAML;

our @EXPORT_OK = qw(start_test_servers
                    stop_test_servers);

use base qw(Exporter);

sub start_test_servers
{
    my @pids;
    my @servers;

    my $idp = APNIC::RDAP::OpenID::IDP->new();
    if (my $pid = fork()) {
        push @pids, $pid;
        push @servers, $idp;
    } else {
        if (not $ENV{"RDAPOPENID_DEBUG"}) {
            close STDERR;
        }
        $idp->run();
        exit();
    }

    my $idp_port = $idp->{'port'};

    my $server = APNIC::RDAP::OpenID::Server->new(port => 38281);
    if (my $pid = fork()) {
        push @pids, $pid;
        push @servers, $server;
    } else {
        if (not $ENV{"RDAPOPENID_DEBUG"}) {
            close STDERR;
        }
        $server->run();
        exit();
    }

    my $server_port = $server->{'port'};

    my $proxy = APNIC::RDAP::OpenID::Proxy->new(
        port => 0,
        base_rdap_url => 'http://localhost:'.$server_port,
        idp_details => {
            test => {
                id => 'test-id',
                secret => 'test-secret',
                discovery_uri => 'http://localhost:'.$idp_port.'/.well-known/openid-configuration',
            },
        },
        idp_mappings => [
            [ "\@gmail.com", "google" ],
            [ "^.*\$", "test" ]
        ],
        filters => {
            unauthenticated => {
                no_entities => 1
            },
            authenticated => {
                pass_purpose => 1
            },
        }
    );

    if (my $pid = fork()) {
        push @pids, $pid;
        push @servers, $proxy;
    } else {
        if (not $ENV{"RDAPOPENID_DEBUG"}) {
            close STDERR;
        }
        $proxy->run();
        exit();
    }

    my $proxy_port = $proxy->{'port'};

    return [ \@pids, \@servers ];
}

sub stop_test_servers
{
    my ($pids) = @_;

    my $exit_code = $?;

    for my $pid (@{$pids}) {
        kill 9, $pid;
        waitpid $pid, 0;
    }
    
    $? = $exit_code;

    return 1;
}

1;
