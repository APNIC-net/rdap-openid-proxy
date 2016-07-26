package APNIC::RDAP::OpenID::Utils;

use warnings;
use strict;

use Digest::SHA qw(sha256);
use MIME::Base64 qw(encode_base64);

our @EXPORT_OK = qw(access_token_hash);

use base qw(Exporter);

sub access_token_hash
{
    my ($alg, $input) = @_; 

    if ($alg ne 'RS256') {
	warn "Unsupported algorithm '$alg'";
	return;
    }
    my $digest = sha256($input);
    my $len = length($digest);
    my $first_half = substr($digest, 0, ($len / 2));
    my $encoded = encode_base64($first_half);
    chomp $encoded;
    $encoded =~ s/=//g;
    return $encoded;
}

1;
