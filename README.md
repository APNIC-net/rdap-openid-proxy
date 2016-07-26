# rdap-openid-proxy

An OpenID Connect authentication proxy for an RDAP server, based on
[draft-hollenbeck-regext-rdap-openid](https://tools.ietf.org/html/draft-hollenbeck-regext-rdap-openid).
This is a proof-of-concept only, and is not intended for production
use.

## Dependencies

Perl dependencies are listed in `Makefile.PL`.

## Installation

    perl Makefile.PL
    make
    make test
    sudo make install

## Configuration

Configuration is in YAML format, like so:

    port: {port}
    base_rdap_url: {base-rdap-url}
    idp_details:
      {name}:
        id: {idp-client-id}
        secret: {idp-client-secret}
        discovery_uri: {idp-discovery-uri}
      ...
    idp_mappings:
      - [ {regex}, {name} ]
      - ...
    filters:
      unauthenticated:
        {filter_name}: {enabled}
      authenticated:
        {filter_name}: {enabled}

`port` is the port on which the server will run.

`base_rdap_url` is the base URL of the RDAP server for which this
server is operating as a proxy.

`idp_details` maps from a server-specific name for an
identity provider to the configuration details for that provider.

`idp_mappings` is a list of lists, where each element list contains a
Perl regular expression and an identity provider name.  This is used
to map from the user-provided `id` argument to an identity provider:
the provider for the first expression that matches the `id` argument
will be used for the relevant request.  [Provider issuer
discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery)
is not currently implemented.

`filters` affect how requests to or responses from the proxied RDAP
server are handled.  For unauthenticated requests, two filters
are defined:

   * `no_entities`, which strips top-level entities from the response; and
   * `deny`, which returns `403 Forbidden` for all requests.

For authenticated requests, two filters are defined:

   * `pass_authenticated`, which passes an `authenticated=1` query
     argument to the backend; and
   * `pass_purpose`, which passes a `purpose` query argument to the
     backend, using the purpose from the user's `userinfo` endpoint.

## Example usage

Using a configuration file like so, with Google as the provider:

    port: 38279
    base_rdap_url: http://rdap.apnic.net
    idp_details:
      google:
        id: {client-id}.apps.googleusercontent.com
        secret: {client-secret}
        discovery_uri: https://accounts.google.com/.well-known/openid-configuration
    idp_mappings:
      - [ "@gmail.com", "google" ]
    filters:
      unauthenticated:
        no_entities: 1

An unauthenticated request can be sent like so:

    $ curl http://localhost:38279/domain/203.in-addr.arpa
    {"ldhName":"203.in-addr.arpa", ...

An authenticated request can be sent in the same way, by including
`id={username}@gmail.com` as a query argument in the URL.

The `/tokens` endpoint can be used to retrieve access and refresh
tokens, to facilitate scripted authenticated access to the server.
This mode of operation, as well as the revocation and refresh
operations, are covered in detail in the specification.

## Notes

   * This has only been tested with Google's identity provider, so other
     providers may not work as expected.

## License

See [LICENSE.txt](LICENSE.txt).
