Our Single-Sign-On ("SSO") server and client library for multi-tenant architectures. Usable both as:

- remote SSO server
- embeddable inside a standalone application

The server works also on AWS Lambda.

Signs [JWT](https://jwt.io/)s and forwards said token to the consumer site via its local
auth gateway (that sets the cookie).

![](docs/screenshot.png)


Architecture
------------

![](docs/architecture.png)

Essentially, your consumer services configure one base URL (like `https://function61.com/id`) as
trusted. Based on that URL, the consumer library's gateway code knows where to send users for logging in,
and that the trusted public keys are downloadable from https://function61.com/id/.well-known/jwks.json

Each of these public keys can sign JWTs that the consumer code accepts.

Our ID server implements [JSON Web Key Sets](https://auth0.com/docs/tokens/json-web-tokens/json-web-key-sets).


Status
------

Not ready for use by other organizations than function61. Reasons include, but not limited to:

- Some must-change details are hardcoded
- Important functionality missing, like OAuth2, WebAuthn, password resets
- Large changes are coming (hook into [EventHorizon](https://github.com/function61/eventhorizon))


Setting up
----------

### Generate signing key

```console
$ ./id genkey
qBQWxnKj7DUUQsnojWdwCui96Ur9dpU5F2wq8orpt0NBlhBCbZg05zXOpwOtxkwd77dkKcHzte1837xfLALKpg
```

This is an [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) private key. Guard it well.
Only your SSO server should be able to access it.


### Start ID server

Before starting the server, you need to pass the signing key as ENV variable
`SIGNING_PRIVATE_KEY`.

Tip: `$ ./id genkey > dev.env`, then add `export SIGNING_PRIVATE_KEY=` in front.


CLI
---

There's also a small CLI for testing the client API.


### Fetch user's details

Assuming you have an ID server at `https://example.com/id` and you know the user's auth
token, you can fetch the user's details from CLI by:

```console
$ ./id client user-get https://example.com/id "$token"
{
    "id": "E3aREYX7dBE",
    "created": "2020-05-21T00:00:00Z",
    "email": "bob@example.com"
}
```


Security
--------

User's passwords are stored using PBKDF2, and never leave the SSO service - not even the hashes.

Project lead is:

- aware of and understands [OWASP Top Ten](https://owasp.org/www-project-top-ten/), particularly:
	* CSRF
	* Unvalidated redirects](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).
- aware of common JWT pitfalls
- a [security-minded person](https://joonas.fi/tags/infosec/)


Roadmap
-------

Everything mentioned in the "Status" section.

Instead of having a "fully-trusted" SSO signing key `-----BEGIN PRIVATE KEY-----`, we
should wrap they key in a X.509 certificate which is signed by our own CA.

This way consumer webservices could check JWT trust not by trusting the SSO signing key,
but by trusting the CA and the revokation process.
