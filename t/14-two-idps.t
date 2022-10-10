#!/usr/bin/perl

use warnings;
use strict;

use JSON::XS qw(decode_json);

use lib 't/lib';
use APNIC::RDAP::OpenID::IDP;
use APNIC::RDAP::OpenID::Proxy;
use APNIC::RDAP::OpenID::Server;
use YAML;
use HTTP::CookieJar::LWP;

use APNIC::RDAP::OpenID::Test::Utils qw(stop_test_servers);

use Test::More tests => 7;

my @pids;
my @servers;

{
    my $idp1 = APNIC::RDAP::OpenID::IDP->new(iss => 'test-iss-1');
    if (my $pid = fork()) {
        push @pids, $pid;
        push @servers, $idp1;
    } else {
        if (not $ENV{"RDAPOPENID_DEBUG"}) {
            close STDERR;
        }
        $idp1->run();
        exit();
    }

    my $idp1_port = $idp1->{'port'};

    my $idp2 = APNIC::RDAP::OpenID::IDP->new(iss => 'test-iss-2');
    if (my $pid = fork()) {
        push @pids, $pid;
        push @servers, $idp2;
    } else {
        if (not $ENV{"RDAPOPENID_DEBUG"}) {
            close STDERR;
        }
        $idp2->run();
        exit();
    }

    my $idp2_port = $idp2->{'port'};

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
        issuer_identifier_supported => 1,
        idp_details => {
            test1 => {
                id => 'test1-id',
                secret => 'test1-secret',
                discovery_uri => 'http://localhost:'.$idp1_port.'/.well-known/openid-configuration',
            },
            test2 => {
                id => 'test2-id',
                secret => 'test2-secret',
                discovery_uri => 'http://localhost:'.$idp2_port.'/.well-known/openid-configuration',
            },
        },
        redirect_uri => 'http://localhost:0/authorised',
        idp_mappings => [
            [ "\@gmail.com", "google" ],
            [ "\@test1.example.com\$", "test1" ],
            [ "\@test2.example.com\$", "test2" ],
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
    $server_port = $servers[3]->{'port'};
    my $host = "http://localhost:$server_port";

    my $jar = HTTP::CookieJar::LWP->new();
    my $ua = LWP::UserAgent->new(cookie_jar => $jar);

    my $res = $ua->get("$host/farv1_session/login?farv1_id=some-id");
    is($res->code(), 400,
        'Failed discovery (unhandled ID) treated as bad request');

    $res = $ua->get("$host/farv1_session/login?farv1_iss=test-iss-3");
    is($res->code(), 400,
        'Failed discovery (unknown ISS) treated as bad request');

    $res = $ua->get("$host/farv1_session/login?farv1_iss=test-iss-1");
    is($res->code(), 200, 'Logged in to first IDP');
    my $content = decode_json($res->content());
    is($content->{'farv1_session'}->{'iss'},
        'test-iss-1',
        'Got expected iss value');

    $res = $ua->get("$host/farv1_session/logout");
    is($res->code(), 200, 'Logged out of first IDP');

    $res = $ua->get("$host/farv1_session/login?farv1_iss=test-iss-2");
    is($res->code(), 200, 'Logged in to second IDP');
    $content = decode_json($res->content());
    is($content->{'farv1_session'}->{'iss'},
        'test-iss-2',
        'Got expected iss value');
}

END {
    stop_test_servers(\@pids);
}

1;
