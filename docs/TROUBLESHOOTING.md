# Troubleshooting

Symptoms observed while integrating this extension with the official EUDI reference wallet, and what
each one actually meant. Several of these messages do not describe their cause; those are first.

Every entry here was reproduced against a real wallet on a real device, not inferred from reading.

## Messages that mean something other than what they say

### "The requested document is not available in your EUDI Wallet"

**This does not mean the wallet lacks the credential.** It means the request asked for no claims.

The wallet raises it from:

```kotlin
val requestedClaimsAreEmpty = combinationsDomain
    .flatMap { it.matches }.all { it.requestedClaims.isEmpty() }
```

`all {}` on an **empty** list returns `true`, so one message covers two opposite failures: no matching
credential at all, *and* a match whose query requested nothing.

**Rule: every DCQL credential query must request at least one claim.** A query carrying only
`format` and `meta.vct_values` is treated as empty whatever the wallet holds, and the credential is
never offered.

Watch the claim path, too. A query asking for `id` against a card whose subject claim is `sub`
produces the identical message, because claim matching fails and the credential drops out.

### A credential is held, valid, and simply never offered

`DcqlRequestProcessor.findMatchesForQuery` discards candidates in three places, each with
`return@mapNotNull null` and **no log line at all**:

| Condition | Effect |
|---|---|
| `findCredential()` returns null | outside the validity window — note it filters on validity only, so an already-used credential is still returned |
| `hasCnfClaim()` false | no holder key binding in the SD-JWT |
| `getClaims()` throws | exception swallowed |

A credential can therefore be present, valid, correctly typed and invisible, with nothing anywhere
saying why. Candidate selection also requires the document's `format` to equal
`SdJwtVcFormat(vct)` exactly and its `findCredential()` to be non-null.

### `invalid_proof` — "Failed to validate x5c certificate chain"

Keycloak reads the `x5c` header of the wallet's key-attestation JWT, builds a `CertPath` and runs a
PKIX `CertPathValidator` whose trust anchors come from **`javax.net.ssl.trustStore`** — the JVM's TLS
truststore. The chain presented is the wallet provider's, rooted in an EUDI CA, and no EUDI CA is in
a stock `cacerts`.

Fix: load that root through `KC_TRUSTSTORE_PATHS`. Two things worth knowing before you do:

- `truststore-paths` is a **runtime** option, not a build one — it is absent from
  `kc.sh build --help-all` (where `--db` is present). It therefore survives `start --optimized`.
- It **adds** to the default truststore rather than replacing it; Keycloak 26.7 offers no option to
  exclude the default. The flip side: whatever you anchor there is also trusted for Keycloak's own
  outgoing TLS.

The anchor to load is named in the leaf certificate itself, in its Authority Information Access
extension. The chain may contain a single certificate, with no intermediate.

### `haip profile requires an encrypted response mode (direct_post.jwt or dc_api.jwt)`

The wallet implements the OpenID4VC High Assurance Interoperability Profile and rejects
`direct_post`. The request must use `response_mode: direct_post.jwt` and carry `client_metadata`
with an ephemeral encryption key specific to that request.

### `Authorization detail type of openid_credential require usage of credential identifiers in credential request`

Not a configuration error. OID4VCI 1.0 §8.2 requires an identifier-based credential request as soon
as the token endpoint response carries `authorization_details` — which Keycloak always sends — and
`eudi-lib-android-wallet-core` 0.29.0 always builds a configuration-based one. Fixed by upstream
PR #369, unmerged as of 2026-08.

### A generic "Oups! Something went wrong" during issuance

Check the device clock first. Wallet attestations are validated with `check(now >= notBefore)` and
**no tolerance**; a device running a second or two behind makes the attestation "not yet valid", and
the failure surfaces with no detail. A 1.7-second skew was enough.

### Keycloak logs "Non-secure context detected… review your proxy settings"

Easy to dismiss as noise; it is not. `KC_PROXY_HEADERS=xforwarded` alone is not enough — if the
ingress does not actually pass `X-Forwarded-Proto: https`, cookies are issued without `Secure`, the
session is not kept, and authentication loops or returns 403 on token retrieval.

## Identity and trust traps

### One person, two accounts

The Utopia test PID carries a **trailing space** in `family_name` (and its given/family names are
swapped). Any subject claim derived from a name will therefore produce a different identity
depending on which PID is presented, and Keycloak will create a second account and then fail on the
email conflict.

Do not derive identity from a name. The point of issuing your own credential is to mint a subject
that is stable by construction.

### Two certificate authorities whose names differ by one field

`PID Issuer CA 02` (**C=EU**) and `PID Issuer CA - UT 02` (**C=UT**) are different authorities. The
first signs relying-party and wallet-provider certificates; the second signs the Utopia test PIDs.
Both may need to be present. Mistaking one for the other costs an evening.

### `ownIssuerAnchorsPem` empty while `ownVct` is set

Every credential of that type is refused with `ISSUER_NOT_AUTHORIZED`, and the refusal is **fatal to
the whole transaction** — a legitimate holder is locked out entirely rather than falling back to
their PID. The setting takes a bundle; keep both anchors present across an authority rotation.

## Credential lifetime

### The card says "1 / 1" and the counter never moves

Two different counters are easy to confuse:

- `usageCount` increments on every presentation, and is not displayed.
- The displayed ratio is `credentialsCount()`, which counts **stored credential objects**. An object
  is only removed under a `OnceOnly` policy.

When the issuer advertises no `credential_reuse_policy`, the wallet applies its own default. In the
EUDI wallet that default is `RotatingBatch` with a single instance for any unknown credential type —
PIDs are named explicitly and get `OnceOnly`, which is why only their counter moves.

Consequence: **you never run out**, because nothing enforces a limit — but the same signed token is
re-presented to every verifier, which is exactly what one-time-use credentials exist to avoid.

**Raising `batch_credential_issuance.batch_size` alone changes nothing**, because the wallet caps
the count at `min(issuerBatchSize, itsOwnNumberOfCredentials)`. Per ETSI TS 119 472-3, an issuer
that advertises `credential_reuse_policy` overrides both the batch size and the wallet's default —
that is the interoperable lever.

## Build traps

### A provider ships something you deleted

Symptom: Keycloak registers a theme, mapper or provider that is no longer anywhere in the
sources — visible in the admin console's server info, or simply working when it should not exist.

`mvn package` without `clean` repackages whatever is left in `target/classes`. A resource deleted
from `src/main/resources` stays there from the previous build and goes into the jar again, at every
build, indefinitely. Nothing fails, because a stale artefact is a perfectly valid one.

Observed on 2026-08-25: a jar was still registering an account theme abandoned nine days earlier,
with its own `META-INF/keycloak-themes.json`. A `--no-cache` container rebuild did not help — the
staleness was in `target/`, not in any layer cache.

**Rule: `mvn clean package` whenever a resource has been removed or renamed.** The same trap hits
the account console for a different reason, and is documented in
[`GETTING-STARTED.md`](GETTING-STARTED.md): without `clean`, Maven keeps the previous front-end
bundle and the jar ends up with two hashed `main-*.js` files.

A quick check on any jar, when something is registered that should not be:

```bash
unzip -l target/<artefact>.jar | grep -E 'theme/|META-INF/keycloak-'
```

## Method notes

Two habits saved more time than any single fix.

**Grep a JAR only after decompressing it.** Archive entries are DEFLATE-compressed, so `grep` on the
`.jar` finds nothing and the silence reads exactly like a negative result. Use `unzip -p | grep -a`,
and always include a **positive control** — a string you know is there — so an empty result means
absent rather than mismeasured.

**Do not compare image digests across tools.** Podman keeps the digest computed at build time while
a registry recomputes its own on push; they differ with nothing wrong. Compare the artefact:
`sha256sum` the JAR inside the running container and on disk.
