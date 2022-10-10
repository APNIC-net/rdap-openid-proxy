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
    my $data = start_test_servers({ implicit_token_refresh_supported => \1 });
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

    for (1..3) {
        diag "Sleeping for 1s...\n";
        sleep(1);
    }

    $res = $ua->get("$host/domain/203.in-addr.arpa");
    is($res->code(), 200, 'Authenticated request succeeded (auto-refresh)');

    for (1..3) {
        diag "Sleeping for 1s...\n";
        sleep(1);
    }

    $res = $ua->get("$host/farv1_session/status");
    is($res->code(), 200, 'Status request succeeded (auto-refresh)');
}

END {
    stop_test_servers($pids);
}

1;
