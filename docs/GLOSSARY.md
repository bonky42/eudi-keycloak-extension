# Glossary

The acronyms this repository uses, explained as it uses them.

Only terms you will actually meet here are listed: in the configuration fields, in the log lines, in
the messages a wallet sends back. Where this project has a real value for something, that value is
given rather than a placeholder — the point is to let you recognise the thing when you see it, not
to define it in the abstract.

## Read this first: there are two trust chains, not one

Almost every confusion in this domain comes from collapsing two questions that have separate
answers, separate certificates and separate lists:

| Question | Our credential | Issued by | Checked against |
|---|---|---|---|
| *May this verifier ask?* | the **RPAC** | the **RPRS** | the **WRPAC** list |
| *May this issuer attest?* | `Pavillon-Noir DS 01` under `Pavillon-Noir Issuer CA 01` | ourselves | the **PubEAA** list |

This extension plays both roles, so both chains are present in one deployment, and a failure in
either surfaces as a wallet saying no. Knowing which one is failing is most of the diagnosis.

## What a wallet holds and shows

**VC** — *Verifiable Credential*. A card. What a wallet stores.

**VP** — *Verifiable Presentation*. What the holder shows a verifier from that card, for one
transaction.

**PID** — *Person Identification Data*. The state-issued identity credential, `vct`
`urn:eudi:pid:1`. Worth knowing: the five mandatory attributes are `family_name`, `given_name`,
`birth_date`, `birth_place`, `nationality` — **none of them is an identifier**.
`personal_administrative_number` exists but is optional and its policy varies by Member State. This
is why this project issues its own credential rather than identifying anyone by their PID.

**EAA** — *Electronic Attestation of Attributes*. Any attestation that is not a PID. The credential
this Keycloak issues, `urn:pn:account-holder:1`, is one. **QEAA** is a qualified one; **PuB-EAA** is
one issued by a public body.

**SD-JWT VC** — the credential format used throughout here (`dc+sd-jwt`). A JWT whose claims are
individually disclosable, so a holder reveals `age_over_18` without revealing a birth date.

**KB-JWT** — *Key Binding JWT*. Signed by the holder over the verifier's `nonce` and audience, it
proves the presenter holds the credential's private key rather than a copy of the credential.

## The protocols

**OID4VP** — *OpenID for Verifiable Presentations*. The protocol in which **this extension is the
verifier**: it builds a request, a wallet answers with a presentation.

**OID4VCI** — *…for Verifiable Credential Issuance*. The protocol in which **this extension is the
issuer**. Distinct code path, distinct trust chain, same deployment.

**DCQL** — *Digital Credentials Query Language*. The query: which credential types, which claims.
It is the `dcqlQueryJson` field of the identity provider. **Every credential query must ask for at
least one claim** — a query with no claims matches nothing, and the wallet's refusal says
"not available", which is not what happened. See [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).

**HAIP** — *High Assurance Interoperability Profile*. The strict profile the EUDI reference wallet
implements. It is what requires the encrypted response (`direct_post.jwt`), the per-request
ephemeral encryption key in `client_metadata`, and a non-self-signed signing certificate.

**OIDC4IDA** — the identity-assurance standard whose `verified_claims` structure this extension
emits: what was verified, by which method, against which trust framework, and when.

## Being trusted

**RP** — *Relying Party*. The verifier. This extension, when it asks.

**RPRS** — *RP Registration Service*. The EUDI registry that issues access certificates to
verifiers: `registry.serviceproviders.eudiw.dev`. Registration is self-service against its
non-production environment. It generates the key pair itself and accepts **no CSR**, which is why
the verifier's key always arrives from outside and can only be imported — never generated in
place.

**RPAC** — *RP Access Certificate*. What the RPRS issued us. It travels as the request's `x5c`, the
verifier's `client_id` is derived from it, and it is what makes a wallet name this verifier on
screen instead of refusing an unknown one.

**WRPAC** — the list of authorities entitled to issue RPACs. A wallet reads it to decide whether
ours means anything.

**LoTE** — *List of Trusted Entities*, **ETSI TS 119 602**. A signed JWT listing trusted issuers.
**This is what a wallet actually reads.** Not to be confused with:

**TL / TSL / LoTL** — *Trusted List*, **ETSI TS 119 612**. The older eIDAS mechanism, in XML. A
different standard, a different format, a different pipeline — and *not* what the reference wallet
consults for issuer trust. Producing one of these when the other was needed cost this project an
evening.

**TSP** — *Trust Service Provider*. The entity a trusted list names.

## Certificates and keys

**`x5c`** — the certificate chain carried in a JWT header. The verifier's request carries its RPAC
there; a wallet's key attestation carries its own chain there.

**`x509_hash`** — the client-identifier scheme this verifier uses: `x509_hash:` followed by the
SHA-256 of the signing certificate's DER, base64url. Ours is
`x509_hash:dXMf1_a6Vbn97dGOgk0fJGz1qMRbzmLVgdGPN-wD89c`. The wallet recomputes it from the `x5c` and
refuses the request if the two disagree, which is why nothing else may compute it independently.

**`kid`** — a key identifier. **JWKS** — the set of public keys a server publishes.

**DS** — *Document Signer*. The certificate that actually signs issued credentials, sitting under
the issuing CA. Ours is `Pavillon-Noir DS 01` under `Pavillon-Noir Issuer CA 01`.

**AKI** — *Authority Key Identifier*. A short fingerprint of a CA's key, and the way DCQL's
`trusted_authorities` names an anchor without embedding a certificate.

## Keycloak

**SPI** — *Service Provider Interface*. Keycloak's extension mechanism. Everything here is one:
the identity provider, the key provider, the protocol mapper, the admin endpoint.

**IdP** — *Identity Provider*, here meaning Keycloak's identity **brokering**: a third party
attests an identity and Keycloak links it to a local account.

**Realm key provider** — a realm-scoped component that supplies keys. `oid4vp-verifier-key` is
this extension's, and it is where the verifier's signing key lives. It is not merely tidier: a
value held in an identity provider's configuration is served back verbatim by the administration
API and written verbatim into the admin event log, because `StripSecretsUtils.stripBroker` masks
`clientSecret` by name and nothing else.

## Other formats you may see

**mdoc** — the ISO 18013-5 credential format, `mso_mdoc`. The EUDI reference *verifier* requests
PIDs in this format; this extension does not implement it and requests `dc+sd-jwt`. A wallet holding
only an mdoc PID cannot answer our query at all.

**Digital Credentials API** — the browser API (`navigator.credentials.get()`) that routes a request
to a local wallet without a QR code. A second transport for the same protocol; not implemented here.
