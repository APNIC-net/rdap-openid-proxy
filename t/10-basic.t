#!/usr/bin/perl

use warnings;
use strict;

use JSON::XS qw(decode_json);

use lib './t/lib';
use APNIC::RDAP::OpenID::Test::Utils qw(start_test_servers
                                        stop_test_servers);

use Test::More tests => 4;

my $pids;

{
    my $data = start_test_servers();
    $pids = $data->[0];
    my $servers = $data->[1];
    my $server_port = $servers->[2]->{'port'};
    my $host = "http://localhost:$server_port";

    my $ua = LWP::UserAgent->new();
    my $res = $ua->get("$host/domain/203.in-addr.arpa?id=some-id");
    is($res->code(), 200, 'Authenticated request was successful');
    my $content = decode_json($res->content());
    ok($content->{'entities'},
        'Authenticated request contains entities');

    $res = $ua->get("$host/domain/203.in-addr.arpa");
    is($res->code(), 200, 'Unauthenticated request was successful');
    $content = decode_json($res->content());
    ok((not $content->{'entities'}),
        'Unauthenticated request does not contain entities');
}

END {
    stop_test_servers($pids);
}

1;
