package org.keycloak.protocol.oid4vc.vp.testsupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.security.KeyPair;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A simulated OID4VP wallet answering a Request Object: it decodes the JWT for
 * {@code nonce}/{@code client_id}/{@code state}/{@code dcql_query}, picks or issues a credential
 * whose {@code vct} satisfies the query, then builds the SD-JWT plus KB-JWT presentation.
 *
 * <p>The Request Object is decoded WITHOUT verifying its signature. A real wallet SHOULD
 * authenticate the request's issuer before acting on it; this harness only needs the claims.</p>
 */
public class SimulatedWallet {

    /** Malicious or degraded wallet behaviours, for the negative end-to-end tests.
     *  {@code NONE} is the happy path. */
    public enum Tamper {
        NONE, WRONG_NONCE, WRONG_AUD, REPLAY_OTHER_PRESENTATION,
        TAMPERED_DISCLOSURE, FOREIGN_HOLDER_KEY, USER_DENIES,
        /** Files the presentation under ANOTHER credential query's key: the wallet lies about the
         *  label. Proves the key decides nothing. */
        MISLABELLED_KEY
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Decoder B64URL_DECODER = Base64.getUrlDecoder();
    private static final Base64.Encoder B64URL_NOPAD = Base64.getUrlEncoder().withoutPadding();

    private final TestCredentialIssuer issuer;
    /** Not {@code final}: {@link #adoptHolderKeyOf} lets one test wallet take over another's key,
     *  the only way to present a card bound by {@code cnf} to that key. */
    private KeyPair holderKeyPair;
    private final Map<String, Object> claims;

    /** The only {@code vct} this wallet can FORGE: the one it was born holding, its PID. Any other
     *  type must have been handed to it by {@link #receive}. Without that bound the wallet would
     *  forge our own card on demand and permanently simulate "the holder already has both" — the
     *  very complacency these tests exist to remove. */
    private final String nativeVct;

    /** Cards received from an issuer over OID4VCI, keyed by vct. A held card is PRESENTED as is;
     *  only the native vct is forged locally when absent. */
    private final Map<String, String> held = new LinkedHashMap<>();

    private String lastState;
    private ObjectNode lastClientMetadata;

    public SimulatedWallet(TestCredentialIssuer issuer) {
        this(issuer, defaultPidClaims(), "urn:eudi:pid:1");
    }

    /**
     * Injects the claims issued into the credential — {@code email} for identity matching,
     * {@code given_name}/{@code family_name} for the created user's profile. They are issued as
     * given, regardless of the paths the DCQL lists: the verifier checks the {@code vct} only.
     */
    public SimulatedWallet(TestCredentialIssuer issuer, Map<String, Object> claims) {
        this(issuer, claims, "urn:eudi:pid:1");
    }

    /** Chooses the wallet's native {@code vct}, the only one it can forge on the fly, for a test
     *  that needs to vary what this wallet was born holding. */
    public SimulatedWallet(TestCredentialIssuer issuer, Map<String, Object> claims, String nativeVct) {
        this.issuer = issuer;
        this.holderKeyPair = issuer.newHolderKeyPair();
        this.claims = new LinkedHashMap<>(claims);
        this.nativeVct = nativeVct;
    }

    /**
     * Decodes the Request Object, without verifying its signature, and builds the OID4VP 1.0
     * response: a JSON object keyed by the {@code id} of every credential query this wallet can
     * satisfy. A query it cannot satisfy is simply ABSENT from the object (section 8.1).
     *
     * @return le JSON du {@code vp_token}, ou {@code null} si {@code tamper == USER_DENIES}
     */
    public String respondTo(String requestObjectJwt, Tamper tamper) {
        JsonNode payload = decodePayloadWithoutVerifying(requestObjectJwt);

        String nonce = payload.get("nonce").asText();
        String clientId = payload.get("client_id").asText();
        this.lastState = payload.get("state").asText();
        this.lastClientMetadata = (ObjectNode) payload.get("client_metadata");

        if (tamper == Tamper.USER_DENIES) {
            return null;
        }
        long now = payload.get("iat").asLong();

        ObjectNode vpToken = MAPPER.createObjectNode();
        for (JsonNode credentialQuery : payload.path("dcql_query").path("credentials")) {
            String queryId = credentialQuery.path("id").asText();
            JsonNode vctValues = credentialQuery.path("meta").path("vct_values");
            if (!vctValues.isArray() || vctValues.isEmpty()) {
                continue;
            }
            String vct = vctValues.get(0).asText();

            String credential = held.get(vct);
            if (credential == null && vct.equals(nativeVct)) {
                credential = issuer.issue(vct, claims, holderKeyPair.getPublic(),
                    now - 1000, now + 100_000);
            }
            if (credential == null) {
                continue;   // this wallet holds no such card: the key is absent (section 8.1)
            }
            vpToken.putArray(keyFor(queryId, payload, tamper))
                .add(present(credential, nonce, clientId, now, tamper));
        }
        if (vpToken.isEmpty()) {
            throw new IllegalStateException("no credential in this wallet satisfies the request");
        }
        try {
            return MAPPER.writeValueAsString(vpToken);
        } catch (Exception e) {
            throw new IllegalStateException("failed to serialize vp_token", e);
        }
    }

    /** Which key to file this presentation under: its own, except in
     *  {@link Tamper#MISLABELLED_KEY} where the wallet labels it as ANOTHER declared query. */
    private String keyFor(String queryId, JsonNode payload, Tamper tamper) {
        if (tamper != Tamper.MISLABELLED_KEY) {
            return queryId;
        }
        for (JsonNode other : payload.path("dcql_query").path("credentials")) {
            String otherId = other.path("id").asText();
            if (!otherId.equals(queryId)) {
                return otherId;
            }
        }
        return queryId;
    }

    /** Builds the presentation (credential plus KB-JWT), applying the requested tampering. */
    private String present(String credential, String nonce, String clientId, long now, Tamper tamper) {
        if (tamper == Tamper.TAMPERED_DISCLOSURE) {
            credential = tamperFirstDisclosure(credential);
        }
        String presentedNonce = tamper == Tamper.WRONG_NONCE ? nonce + "-tampered" : nonce;
        String presentedAud = tamper == Tamper.WRONG_AUD ? clientId + "-tampered" : clientId;
        KeyPair kbSigningKey =
            tamper == Tamper.FOREIGN_HOLDER_KEY ? issuer.newHolderKeyPair() : holderKeyPair;

        String kbJwt = tamper == Tamper.REPLAY_OTHER_PRESENTATION
            ? KbJwtSigner.sign(kbSigningKey, presentedNonce, presentedAud, "some-other-presentation~", now)
            : KbJwtSigner.sign(kbSigningKey, presentedNonce, presentedAud, credential, now);
        return credential + kbJwt;
    }

    /** The {@code state} claim extracted from the last decoded Request Object. */
    public String lastState() {
        return lastState;
    }

    /**
     * Seals a vp_token the way a HAIP wallet does, against the ephemeral key the verifier
     * advertised in the last Request Object this wallet read.
     *
     * @param enc {@code A128GCM} or {@code A256GCM} — the wallet's choice, per the profile
     */
    public String sealedResponse(String vpToken, String enc) {
        ObjectNode body = MAPPER.createObjectNode();
        body.set("vp_token", readTree(vpToken));
        body.put("state", lastState);
        return TestJwe.seal((ObjectNode) lastClientMetadata.get("jwks").get("keys").get(0),
            enc, body.toString());
    }

    private static JsonNode readTree(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException("failed to parse JSON", e);
        }
    }

    /** The holder key pair, carried in the cnf of held credentials. It signs both the OID4VCI
     *  proof of possession and the presentation's KB-JWT. */
    public KeyPair holderKeyPair() {
        return holderKeyPair;
    }

    public void receive(String vct, String credential) {
        held.put(vct, credential);
    }

    /** The card held for this {@code vct}, or {@code null} — used to move a card from one test
     *  wallet to another. */
    public String credentialOf(String vct) {
        return held.get(vct);
    }

    /** Takes over another wallet's holder key. A received card is bound by {@code cnf} to the key
     *  of whoever requested it, so presenting it from another wallet requires that key — otherwise
     *  the KB-JWT would not verify, which is exactly as it should be. */
    public void adoptHolderKeyOf(SimulatedWallet other) {
        this.holderKeyPair = other.holderKeyPair();
    }

    public boolean holds(String vct) {
        return held.containsKey(vct);
    }

    private JsonNode decodePayloadWithoutVerifying(String jwt) {
        String[] segments = jwt.split("\\.", -1);
        if (segments.length != 3) {
            throw new IllegalArgumentException("Request Object must have 3 JWT segments");
        }
        try {
            return MAPPER.readTree(B64URL_DECODER.decode(segments[1]));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decode Request Object payload", e);
        }
    }

    private static Map<String, Object> defaultPidClaims() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Marie");
        claims.put("age_over_18", true);
        return claims;
    }

    /** Alters the first disclosed value after issuance, so its digest no longer matches {@code _sd}. */
    private String tamperFirstDisclosure(String credential) {
        String[] parts = credential.split("~", -1);
        if (parts.length < 3) {
            throw new IllegalStateException("credential has no disclosure to tamper");
        }
        try {
            ArrayNode disclosure = (ArrayNode) MAPPER.readTree(B64URL_DECODER.decode(parts[1]));
            disclosure.set(2, MAPPER.getNodeFactory().textNode("Tampered-Value"));
            parts[1] = B64URL_NOPAD.encodeToString(MAPPER.writeValueAsBytes(disclosure));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to tamper disclosure", e);
        }
        return String.join("~", parts);
    }
}
