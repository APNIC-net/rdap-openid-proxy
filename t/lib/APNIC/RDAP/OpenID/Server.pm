package APNIC::RDAP::OpenID::Server;

use warnings;
use strict;

use File::Slurp qw(read_file);
use HTTP::Daemon;
use HTTP::Status qw(:constants);

our $VERSION = '0.01';

sub new
{
    my $class = shift;
    my %args = @_;
    my $self = \%args;

    if (not defined $self->{"port"}) {
        $self->{"port"} = 8082;
    }

    my $ua = LWP::UserAgent->new();
    $self->{'ua'} = $ua;

    my $d = HTTP::Daemon->new(
        LocalPort => $self->{"port"},
        ReuseAddr => 1,
        ReusePort => 1
    );
    if (not $d) {
        die "Unable to start server: $!";
    }
    $self->{"port"} = $d->sockport();
    $self->{"d"} = $d;

    bless $self, $class;
    return $self;
}

sub run
{
    my ($self) = @_;

    my $d = $self->{"d"};
    while (my $c = $d->accept()) {
        while (my $r = $c->get_request()) {
            my $method = $r->method();
            my $path = $r->uri()->path();
            print STDERR "$method $path\n";

            my $res = eval {
		my $object_path = "t/objects/$path";
                my $res;
		if (-e $object_path) {
		    my $data = read_file($object_path);
		    $res = HTTP::Response->new(HTTP_OK);
		    $res->header('Content-Type' => 'application/rdap+json');
		    $res->content($data);
		} else {
                    $res = HTTP::Response->new(HTTP_NOT_FOUND);
		}
                $res;
            };
            if (my $error = $@) {
                print STDERR "Unable to process request: $error\n";
                $c->send_error(500);
            } else {
                warn "sending response";
                my $res_str = $res->as_string();
                $res_str =~ s/\n/\\n/g;
                $res_str =~ s/\r/\\r/g;
                print STDERR "$res_str\n";
                $c->send_response($res);
            }


        }
        $c->close();
        undef $c;
    }
}

1;
