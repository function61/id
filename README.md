Our Single-Sign-On ("SSO") server and client library.

The server works also on AWS Lambda.

Signs [JWT](https://jwt.io/)s and forwards said token to the consumer site via its local
auth gateway (that sets the cookie).

![](docs/screenshot.png)

NOTE: graphics are to improve soon :D


Architecture
------------

![](docs/architecture.png)


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
$ id genkey
-----BEGIN PRIVATE KEY-----
...
...
-----END PRIVATE KEY-----
```

### Start ID server

Before starting the server, you need to pass the signing key as ENV variable
`SIGNING_PRIVATE_KEY`.

You need to replace newlines with literal `\n`, i.e. the key from generation example
becomes `-----BEGIN PRIVATE KEY-----\n...\n...\n-----END PRIVATE KEY-----`.


CLI
---

There's also a small CLI for testing the client API.


### Fetch user's details

Assuming you have an ID server at `https://example.com/id` and you know the user's auth
token, you can fetch the user's details from CLI by:

```console
$ id client user-get https://example.com/id "$token"
{
    "id": "E3aREYX7dBE",
    "created": "2020-05-21T00:00:00Z",
    "email": "bob@example.com"
}
```


Security
--------

User's passwords are stored using PBKDF2, and never leave the SSO service - not even the hashes.




Roadmap
-------

Everything mentioned in the "Status" section.

Instead of having a "fully-trusted" SSO signing key `-----BEGIN PRIVATE KEY-----`, we
should wrap they key in a X.509 certificate which is signed by our own CA.

This way consumer webservices could check JWT trust not by trusting the SSO signing key,
but by trusting the CA and the revokation process.
