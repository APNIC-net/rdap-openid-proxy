#!/usr/bin/perl

use warnings;
use strict;

use JSON::XS qw(decode_json);

use lib './t/lib';
use APNIC::RDAP::OpenID::Test::Utils qw(start_test_servers
                                        stop_test_servers);
use HTTP::CookieJar::LWP;

use Test::More tests => 13;

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

    $res = $ua->get("$host/domain/203.in-addr.arpa");
    is($res->code(), 200, 'Authenticated request was successful');
    my $content = decode_json($res->content());
    ok($content->{'entities'},
        'Authenticated request contains entities');

    $res = $ua->get("$host/farv1_session/refresh?fail=1");
    is($res->code(), 200, 'Got refresh response');
    $content = decode_json($res->content());
    like($content->{'notices'}->{'description'}->[0],
        qr/failed/,
        'Unable to refresh session (forced failure)');
    ok($content->{'farv1_session'},
        'Session present in response (session has not expired yet)'); 

    for (1..3) {
        diag "Sleeping for 1s...\n";
        sleep(1);
    }

    $res = $ua->get("$host/domain/203.in-addr.arpa");
    is($res->code(), 403, 'Authenticated request failed (expired)');

    $res = $ua->get("$host/farv1_session/refresh?fail=1");
    is($res->code(), 200, 'Got refresh response');
    $content = decode_json($res->content());
    like($content->{'notices'}->{'description'}->[0],
        qr/failed/,
        'Unable to refresh session (forced failure)');
    ok((not $content->{'farv1_session'}),
        'No session in response (session has expired)'); 

    $res = $ua->get("$host/farv1_session/refresh");
    is($res->code(), 200, 'Got refresh response');
    $content = decode_json($res->content());
    like($content->{'notices'}->{'description'}->[0],
        qr/succeeded/,
        'Refreshed session successfully');

    $res = $ua->get("$host/domain/203.in-addr.arpa");
    is($res->code(), 200, 'Authenticated request succeeded (refreshed)');
}

END {
    stop_test_servers($pids);
}

1;
