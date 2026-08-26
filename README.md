# EUDI Keycloak extension

A Keycloak extension that signs users in with an **EU Digital Identity Wallet**, and issues its own
verifiable credentials to that wallet.

Both directions have been made to work on a real phone, against the official EUDI reference wallet —
but not to the same degree. **Signing in is ready**: the flow completes with an encrypted response
under the OpenID4VC High Assurance Interoperability Profile, using the wallet unmodified. **Issuing
is work in progress**: the same instance issues an SD-JWT VC card over OID4VCI and accepts it back,
demonstrated end to end, but only against a wallet rebuilt for the purpose.

*Independent project. Not affiliated with, nor endorsed by, Red Hat or the European Commission.*

## Why it is built this way

A wallet here is **not a feature bolted onto an application; it is a Keycloak identity provider.**
Anything that already speaks OIDC gets wallet login without changing a line, and what the holder
signs into is an ordinary Keycloak account — with the roles, sessions, tokens and account console
that come with it.

The alternative, a standalone verifier service, would have been quicker to demonstrate and would
have left every integration still to do.

## What is ready, and what is still work in progress


| | |
|---|---|
| **Sign in with a PID** — [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | **Ready and usable.** Works with the **unmodified** official EUDI wallet, on a real phone. |
| **Issue a card** — [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) | **Works, but work in progress.** Demonstrated end to end, and reproducible only against a rebuilt wallet — for two independent reasons. |

**Verification is the part to look at.** A stock wallet, an official PID, and a login that
completes: that path is finished and needs nothing from this repository beyond what is here.
Issuance works too — the instance really does issue its own SD-JWT VC and accept it back — but
calling it usable would be overselling it, because nobody can reproduce it with a wallet from a
store. Here is what stands in the way.

**A wallet builds the wrong credential request.**
[OpenID4VCI 1.0 §8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2)
requires `credential_identifier` as soon as the Token Response carries `authorization_details` of
type `openid_credential` — which Keycloak always sends — and forbids `credential_configuration_id`
in that case. The reference
wallet's library sends the configuration-based form unconditionally, so issuance fails with
*"Authorization detail type of openid_credential require usage of credential identifiers in
credential request"*. The fix is upstream PR
[`eudi-lib-android-wallet-core#369`](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/pull/369),
opened on 2026-06-30 and still unmerged.

**And a wallet would not trust this issuer anyway.** A wallet checks issuer trust *at issuance
time*, against a signed List of Trusted Entities — ETSI TS 119 602. The official EUDI list carries
its seven anchors and is not open to self-service, so no third-party issuer appears in it. The list
a wallet reads is wallet *configuration*, not a protocol constant, so a rebuilt wallet can be
pointed at another one — but that list must **enrich, never replace**: it has to carry the official
entries byte for byte alongside the new anchor, because the PID that bootstraps every identity here
is issued by one of them. A list holding only your own anchor fixes issuance by breaking enrolment.

Signing in with an official PID needs none of this.

The tooling that builds such a list, and the wallet patches that go with it, are not published here.
They exist and they work; they are simply not something anyone has asked for yet. If you want to
stand up an issuer of your own, open an issue and they will follow.

## Status — read this before deploying anything


**This is a working prototype, validated against the EUDI *pre-production* environment. It is
neither certified nor audited, and it is not intended for production use without your own
assessment.**

Concretely: trust anchors come from `preprod.pki.eudiw.dev`, the verifier certificate comes from the
EUDI Relying Party Registration Service, whose environment is explicitly non-productive, and testing
uses the Utopia test PID. Nothing here has been through eIDAS conformance.

## What it implements


- **OpenID4VP** verifier: signed Request Object served by reference, `client_id` using the
  `x509_hash` prefix, DCQL queries, and `direct_post.jwt` — responses encrypted with an ephemeral
  ECDH-ES key published per request in `client_metadata`, as the HAIP profile requires.
- **Identity brokering**: the presentation becomes a Keycloak federated identity, with a
  configurable subject claim per credential type.
- **Issuer pinning**: a credential of our own type is accepted only if its chain validates against
  pinned anchors — with no permissive fallback, deliberately.
- **OID4VCI issuance** of an SD-JWT VC card, offered from the account console — work in progress,
  see above.
- **A unified flow**: one request declares our card and the PID as two optional sets, so the holder
  presents what they hold and the verifier infers the situation without server-side state.

## Layout


| Path | What it is |
|---|---|
| `oid4vp-core` | Protocol engine: request building, DCQL, verification, trust, encryption. No Keycloak SPI. |
| `oid4vp-login` | The Keycloak side: identity provider, endpoints, protocol mappers, card catalogue. |
| `account-console` | A rebuilt Keycloak account console adding a "request a card" page. |
| `demo` | A realm template for a self-contained demo. |
| `scripts/prepare-demo` | Generates the demo PKI and renders that template. Needs only `openssl`. |
| `tools` | The pinned build image for the account console. |
| `Containerfile` | Assembles a runtime image carrying the three jars. Compiles nothing. |
| `docs` | [`GETTING-STARTED.md`](docs/GETTING-STARTED.md) and [`TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md). |

## Quick start


You need a container engine and nothing else — no JDK, no Maven, no Node. Commands are written with
`docker`; `podman` accepts all of them unchanged.

```bash
docker run --rm -v "$PWD":/workspace:z -v kc-oid4vp-m2:/root/.m2:z -w /workspace \
  maven:3.9-eclipse-temurin-17 mvn package
```

Two details in that line are load-bearing, and both are documented traps rather than style:

- **`"$PWD"`, never `./`.** A bind-mount source without a leading `/` can be read as a *named
  volume*, which is then created empty. The build appears to work and produces nothing.
- **`:z`** relabels for SELinux. It is a Docker-origin option, understood by both engines and
  harmless where SELinux is absent — so it is safe to keep on any host.

To assemble a runtime image once the jars are built — `docker build` and `podman build` consume
the same file:

```bash
docker build -f Containerfile -t eudi-keycloak-extension:26.7.2 .
```

Full walkthrough, including running it and signing in: [`docs/GETTING-STARTED.md`](docs/GETTING-STARTED.md).

If something fails — and several failure messages here do not describe their cause — start with
[`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).

## How this started, and where it is


One person learning OpenID4VP and OID4VCI by building with them — not by reading the specifications
first and implementing afterwards. The reading is still going on, alongside the code, and a section
lands very differently once you have already been bitten by the thing it describes. This repository
is that ongoing exploration of how the whole ecosystem actually fits together, made public because
the findings are worth more shared than kept.

A representative afternoon: the wallet answers *"The requested document is not available in your
EUDI Wallet"*. The document is in the wallet. The message means the request asked for **zero
claims** — `all {}` over an empty list returns `true`, so one string covers two opposite failures.
An evening went to a phone whose clock was 1.7 seconds slow, meeting a `nbf` with no tolerance; the
wallet's word for that is "Oups". Another went to discovering that a card was refused because the
query asked for `id` while the card carries `sub`.

[`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) is what accumulated. Every entry is a wall, the
shape of that wall, and the forehead that found it. If it saves you one evening, it has already paid
for itself.

**And there is still a lot to do.** The login page needs work — error strings are hardcoded in
JavaScript and cannot be translated, the polling never backs off, and nothing tells the holder what
is about to be shared. Revocation is not there: certificate CRL/OCSP is feasible today, Token Status
List is not, being absent from Keycloak 26.7. The verifier still reads a static PEM where it should
read a trust list. Only SD-JWT VC is supported, so mdoc and W3C VC are untouched. And issuance
still needs an upstream fix that has not been merged.

None of that is hidden in a backlog: it is what someone reading this should know before assuming
the parts they need are finished.

## Licence


Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Copyright 2026 Bernard Chesnoy.

Much of this repository was written with the assistance of Claude, an AI assistant by Anthropic.
