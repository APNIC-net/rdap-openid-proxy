#!/usr/bin/perl

use warnings;
use strict;

use JSON::XS qw(decode_json);

use lib './t/lib';
use APNIC::RDAP::OpenID::Test::Utils qw(start_test_servers
                                        stop_test_servers);
use HTTP::CookieJar::LWP;

use Test::More tests => 5;

my $pids;

{
    my $data = start_test_servers();
    $pids = $data->[0];
    my $servers = $data->[1];
    my $server_port = $servers->[2]->{'port'};
    my $host = "http://localhost:$server_port";

    my $jar = HTTP::CookieJar::LWP->new();
    my $ua = LWP::UserAgent->new(cookie_jar => $jar);

    my $res = $ua->get("$host/farv1_session/login?id=some-id");
    is($res->code(), 200, 'Authenticated request was successful');
    my $content = decode_json($res->content());
    is($content->{'farv1_session'}->{'sessionInfo'}->{'tokenExpiration'},
        2,
        'Token has expected expiry time');

    diag "Sleeping for 1s...";
    sleep(1);

    $res = $ua->get("$host/farv1_session/status");
    is($res->code(), 200, 'Status fetch was successful');
    $content = decode_json($res->content());

    is($content->{'farv1_session'}->{'sessionInfo'}->{'tokenExpiration'},
        1,
        'Token has expected expiry time');

    for (1..3) {
        diag "Sleeping for 1s...";
        sleep(1);
    }

    $res = $ua->get("$host/farv1_session/status");
    is($res->code(), 409, 'Status fetch was unsuccessful');
    $content = decode_json($res->content());
}

END {
    stop_test_servers($pids);
}

1;
