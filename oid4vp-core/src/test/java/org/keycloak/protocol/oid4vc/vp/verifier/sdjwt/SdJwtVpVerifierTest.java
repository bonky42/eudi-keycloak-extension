package org.keycloak.protocol.oid4vc.vp.verifier.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.model.DcqlQuery;
import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;
import org.keycloak.protocol.oid4vc.vp.testsupport.KbJwtSigner;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestCredentialIssuer;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;
import org.keycloak.protocol.oid4vc.vp.trust.IssuerDecision;
import org.keycloak.protocol.oid4vc.vp.trust.OwnVctIssuerAuthorization;
import org.keycloak.protocol.oid4vc.vp.trust.TrustPolicy;
import org.keycloak.protocol.oid4vc.vp.trust.TrustStore;
import org.keycloak.protocol.oid4vc.vp.verifier.PresentationRequestContext;
import org.keycloak.protocol.oid4vc.vp.verifier.VpErrorCode;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerificationException;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerifierFactory;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The whole SD-JWT VC verification chain: the happy path, plus one negative test per link. */
class SdJwtVpVerifierTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final long NOW = 2_000_000_000L;
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC);

    private static final String NONCE = "test-nonce-123";
    private static final String CLIENT_ID = "test-client-app";
    private static final String VCT = "urn:eudi:pid:1";

    private static final String PID_QUERY_JSON = """
        {
          "credentials": [
            {
              "id": "pid",
              "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eudi:pid:1"] },
              "claims": [
                { "path": ["given_name"] },
                { "path": ["age_over_18"] }
              ]
            }
          ]
        }""";

    private static Map<String, Object> pidClaims() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Marie");
        claims.put("age_over_18", true);
        return claims;
    }

    private static PresentationRequestContext contextWith(TrustStore trustStore) {
        return new PresentationRequestContext(NONCE, CLIENT_ID, DcqlQuery.fromJson(PID_QUERY_JSON), TrustPolicy.acceptingAll(trustStore), "pid");
    }

    private static String withKbJwt(String credential, KeyPair holder, long kbIat) {
        return credential + KbJwtSigner.sign(holder, NONCE, CLIENT_ID, credential, kbIat);
    }

    /**
     * Flips the last bit of the signature's last byte. Done on bytes, not on the base64 character:
     * the final base64url character of a 64-byte ECDSA P1363 signature carries only 2 real bits,
     * the other 4 being padding, so flipping the character can touch padding alone and leave the
     * decoded signature unchanged — observed as flakiness in the full suite.
     */
    private static String corruptIssuerSignature(String credential) {
        int firstTilde = credential.indexOf('~');
        String issuerJwt = credential.substring(0, firstTilde);
        String rest = credential.substring(firstTilde);
        String[] segments = issuerJwt.split("\\.", -1);

        byte[] sig = Base64.getUrlDecoder().decode(segments[2]);
        sig[sig.length - 1] ^= 0x01;
        segments[2] = Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

        return segments[0] + "." + segments[1] + "." + segments[2] + rest;
    }

    /** Replaces the disclosed value of {@code claimName} and re-encodes the disclosure. */
    private static String tamperDisclosureValue(String credential, String claimName, Object newValue) throws Exception {
        String[] parts = credential.split("~", -1);
        for (int i = 1; i < parts.length - 1; i++) {
            JsonNode node = MAPPER.readTree(Base64.getUrlDecoder().decode(parts[i]));
            if (node.get(1).asText().equals(claimName)) {
                ArrayNode newDisclosure = MAPPER.createArrayNode();
                newDisclosure.add(node.get(0));
                newDisclosure.add(claimName);
                newDisclosure.addPOJO(newValue);
                parts[i] = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(MAPPER.writeValueAsBytes(newDisclosure));
            }
        }
        return String.join("~", parts);
    }

    /**
     * Adds a second valid disclosure for an already disclosed claim name, whose digest really is in
     * {@code _sd} — unlike {@link #tamperDisclosureValue}, which leaves {@code _sd} alone. The
     * issuer JWT is re-signed with the same issuer key, so trust and signature stay valid and only
     * link 4, the duplicated claim name, may fail.
     */
    private static String addDuplicateDisclosure(String credential, KeyPair issuerKeyPair,
                                                   String claimName, Object duplicateValue) throws Exception {
        int firstTilde = credential.indexOf('~');
        String issuerJwt = credential.substring(0, firstTilde);
        String disclosuresPart = credential.substring(firstTilde + 1); // reste, se termine par '~'
        String[] segments = issuerJwt.split("\\.", -1);

        String newDisclosure = buildDisclosure(claimName, duplicateValue);
        String newDigest = sha256B64Url(newDisclosure);

        ObjectNode payload = (ObjectNode) MAPPER.readTree(Base64.getUrlDecoder().decode(segments[1]));
        ArrayNode sd = (ArrayNode) payload.get("_sd");
        sd.add(newDigest);

        String headerB64 = segments[0];
        String payloadB64 = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(MAPPER.writeValueAsBytes(payload));
        String signingInput = headerB64 + "." + payloadB64;

        Signature signature = Signature.getInstance("SHA256withECDSAinP1363Format");
        signature.initSign(issuerKeyPair.getPrivate());
        signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        String signatureB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());

        String newIssuerJwt = signingInput + "." + signatureB64;

        return newIssuerJwt + "~" + disclosuresPart + newDisclosure + "~";
    }

    private static String buildDisclosure(String name, Object value) throws Exception {
        byte[] saltBytes = new byte[16];
        new SecureRandom().nextBytes(saltBytes);
        String salt = Base64.getUrlEncoder().withoutPadding().encodeToString(saltBytes);

        ArrayNode disclosureArray = MAPPER.createArrayNode();
        disclosureArray.add(salt);
        disclosureArray.add(name);
        disclosureArray.addPOJO(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(MAPPER.writeValueAsBytes(disclosureArray));
    }

    private static String sha256B64Url(String asciiInput) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(asciiInput.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    // ---- Chemin heureux ----------------------------------------------------

    @Test
    void happyPathVerifiesPidPresentation() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 1000, NOW + 100_000);
        String vpToken = withKbJwt(credential, holder, NOW);

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VerifiedPresentation result = new SdJwtVpVerifier(CLOCK).verify(vpToken, context);

        assertEquals("Marie", result.getClaims().get("given_name"));
        assertEquals(Boolean.TRUE, result.getClaims().get("age_over_18"));
        assertEquals("https://test-issuer.example.org", result.getIssuer());
        assertEquals(VCT, result.getVct());
        assertEquals(chain.caCert.getSubjectX500Principal().getName(), result.getTrustAnchorSubject());
    }

    // ---- Maillon 1 : kb-jwt absent -----------------------------------------

    @Test
    void missingKbJwtThrowsInvalidKeyBinding() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 1000, NOW + 100_000);
        // no KB-JWT appended: the credential already ends on '~'

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(credential, context));
        assertEquals(VpErrorCode.INVALID_KEY_BINDING, ex.getCode());
    }

    // ---- Link 2: untrusted x5c chain -----------------------------------------

    @Test
    void untrustedIssuerCertificateThrowsUntrustedIssuer() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 1000, NOW + 100_000);
        String vpToken = withKbJwt(credential, holder, NOW);

        // The trust store knows only the rogue CA, which the real chain never reaches.
        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.rogueCaCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(vpToken, context));
        assertEquals(VpErrorCode.UNTRUSTED_ISSUER, ex.getCode());

        // The message must name the chain that was actually presented. Without it an operator sees
        // only "does not chain with any of the trust anchors" and has no way to learn WHICH issuer
        // showed up — which is exactly the wall hit on 2026-08-13 against a real wallet. Issuer
        // certificate DNs are metadata about the issuer, never holder data.
        assertTrue(ex.getMessage().contains("presented chain:"),
            "the failure must name the presented chain, or it is undiagnosable: " + ex.getMessage());
        assertTrue(ex.getMessage().contains(chain.issuerCert.getSubjectX500Principal().getName()),
            "the leaf subject must appear: " + ex.getMessage());
        assertTrue(ex.getMessage().contains(chain.issuerCert.getIssuerX500Principal().getName()),
            "the issuer of the leaf must appear — that is the anchor the operator needs to add: "
                + ex.getMessage());
    }

    // ---- Link 3: corrupted issuer signature ---------------------------------

    @Test
    void corruptedIssuerSignatureThrowsInvalidSignature() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 1000, NOW + 100_000);
        String corrupted = corruptIssuerSignature(credential);
        String vpToken = withKbJwt(corrupted, holder, NOW);

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(vpToken, context));
        assertEquals(VpErrorCode.INVALID_SIGNATURE, ex.getCode());
    }

    // ---- Link 4: tampered disclosure -----------------------------------------

    @Test
    void tamperedDisclosureThrowsDisclosureMismatch() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 1000, NOW + 100_000);
        String tampered = tamperDisclosureValue(credential, "given_name", "Pierre");
        String vpToken = withKbJwt(tampered, holder, NOW);

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(vpToken, context));
        assertEquals(VpErrorCode.DISCLOSURE_MISMATCH, ex.getCode());
    }

    @Test
    void duplicateDisclosedClaimNameThrowsDisclosureMismatch() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 1000, NOW + 100_000);
        // Both digests really are in _sd; only the duplicated name may fail link 4.
        String duplicated = addDuplicateDisclosure(credential, chain.issuerKeyPair, "given_name", "Not-Marie");
        String vpToken = withKbJwt(duplicated, holder, NOW);

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(vpToken, context));
        assertEquals(VpErrorCode.DISCLOSURE_MISMATCH, ex.getCode());
    }

    // ---- Maillon 5 : KB-JWT (4 tests) ----------------------------------------

    @Test
    void wrongNonceThrowsInvalidKeyBinding() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 1000, NOW + 100_000);
        String kbJwt = KbJwtSigner.sign(holder, "wrong-nonce", CLIENT_ID, credential, NOW);
        String vpToken = credential + kbJwt;

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(vpToken, context));
        assertEquals(VpErrorCode.INVALID_KEY_BINDING, ex.getCode());
    }

    @Test
    void wrongAudienceThrowsInvalidKeyBinding() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 1000, NOW + 100_000);
        String kbJwt = KbJwtSigner.sign(holder, NONCE, "wrong-client", credential, NOW);
        String vpToken = credential + kbJwt;

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(vpToken, context));
        assertEquals(VpErrorCode.INVALID_KEY_BINDING, ex.getCode());
    }

    @Test
    void sdHashOfDifferentPresentationThrowsInvalidKeyBinding() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 1000, NOW + 100_000);
        // sd_hash computed over a different presentation than "credential"
        String kbJwt = KbJwtSigner.sign(holder, NONCE, CLIENT_ID, "some-other-presentation~", NOW);
        String vpToken = credential + kbJwt;

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(vpToken, context));
        assertEquals(VpErrorCode.INVALID_KEY_BINDING, ex.getCode());
    }

    @Test
    void kbJwtSignedByForeignKeyThrowsInvalidKeyBinding() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();
        KeyPair foreignKey = issuer.newHolderKeyPair();

        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 1000, NOW + 100_000);
        // KB-JWT signed by a key other than the one in cnf.jwk
        String kbJwt = KbJwtSigner.sign(foreignKey, NONCE, CLIENT_ID, credential, NOW);
        String vpToken = credential + kbJwt;

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(vpToken, context));
        assertEquals(VpErrorCode.INVALID_KEY_BINDING, ex.getCode());
    }

    @Test
    void staleKbJwtIatThrowsInvalidKeyBinding() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 1000, NOW + 100_000);
        // nonce, aud and sd_hash are all correct; only iat is outside the +/-300s window.
        String kbJwt = KbJwtSigner.sign(holder, NONCE, CLIENT_ID, credential, NOW - 10_000);
        String vpToken = credential + kbJwt;

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(vpToken, context));
        assertEquals(VpErrorCode.INVALID_KEY_BINDING, ex.getCode());
    }

    @Test
    void futureKbJwtIatThrowsInvalidKeyBinding() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 1000, NOW + 100_000);
        String kbJwt = KbJwtSigner.sign(holder, NONCE, CLIENT_ID, credential, NOW + 10_000);
        String vpToken = credential + kbJwt;

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(vpToken, context));
        assertEquals(VpErrorCode.INVALID_KEY_BINDING, ex.getCode());
    }

    // ---- Link 6: temporal validity -------------------------------------------

    @Test
    void expiredCredentialThrowsCredentialExpired() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 100_000, NOW - 100);
        String vpToken = withKbJwt(credential, holder, NOW);

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(vpToken, context));
        assertEquals(VpErrorCode.CREDENTIAL_EXPIRED, ex.getCode());
    }

    @Test
    void futureIatThrowsCredentialNotYetValid() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        long futureIat = NOW + 10_000; // well beyond the 60s skew
        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), futureIat, futureIat + 100_000);
        String vpToken = withKbJwt(credential, holder, NOW);

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(vpToken, context));
        assertEquals(VpErrorCode.CREDENTIAL_NOT_YET_VALID, ex.getCode());
    }

    // ---- Link 7: DCQL conformance --------------------------------------------

    @Test
    void vctNotRequestedThrowsQueryNotSatisfied() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String credential = issuer.issue("urn:eudi:other:1", pidClaims(), holder.getPublic(),
            NOW - 1000, NOW + 100_000);
        String vpToken = withKbJwt(credential, holder, NOW);

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(vpToken, context));
        assertEquals(VpErrorCode.QUERY_NOT_SATISFIED, ex.getCode());
    }

    @Test
    void requestedClaimNotDisclosedThrowsQueryNotSatisfied() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        Map<String, Object> onlyGivenName = new LinkedHashMap<>();
        onlyGivenName.put("given_name", "Marie");
        // age_over_18, which the DCQL query asks for, is never disclosed

        String credential = issuer.issue(VCT, onlyGivenName, holder.getPublic(), NOW - 1000, NOW + 100_000);
        String vpToken = withKbJwt(credential, holder, NOW);

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(vpToken, context));
        assertEquals(VpErrorCode.QUERY_NOT_SATISFIED, ex.getCode());
    }

    // ---- Link 7, by response key: conformance to the designated query --------

    private static final String UNIFIED_QUERY_JSON = """
        {"credentials":[
          {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}},
          {"id":"own","format":"dc+sd-jwt","meta":{"vct_values":["urn:pn:account-holder:1"]}}]}""";

    /** A valid PID with its own fresh trust chain; only the query the context key designates
     *  varies between tests. */
    private static final class PidPresentation {
        final TestTrustChain chain;
        final String vpToken;

        PidPresentation(TestTrustChain chain, String vpToken) {
            this.chain = chain;
            this.vpToken = vpToken;
        }
    }

    private static PidPresentation pidPresentation() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 1000, NOW + 100_000);
        String vpToken = withKbJwt(credential, holder, NOW);
        return new PidPresentation(chain, vpToken);
    }

    @Test
    void aPresentationLabelledUnderAnotherQueryIsRefused() throws Exception {
        // The key is declarative: a PID labelled "own" must not get through the "own" door. This
        // is what makes it impossible to choose an identity regime by lying about the label.
        PidPresentation pid = pidPresentation();
        PresentationRequestContext context = new PresentationRequestContext(
            NONCE, CLIENT_ID, DcqlQuery.fromJson(UNIFIED_QUERY_JSON),
            TrustPolicy.acceptingAll(new TrustStore(List.of(pid.chain.caCert))), "own");

        VpVerificationException e = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(pid.vpToken, context));
        assertEquals(VpErrorCode.QUERY_NOT_SATISFIED, e.getCode());
    }

    @Test
    void aPresentationUnderItsOwnQueryIsAccepted() throws Exception {
        PidPresentation pid = pidPresentation();
        PresentationRequestContext context = new PresentationRequestContext(
            NONCE, CLIENT_ID, DcqlQuery.fromJson(UNIFIED_QUERY_JSON),
            TrustPolicy.acceptingAll(new TrustStore(List.of(pid.chain.caCert))), "pid");

        assertEquals("urn:eudi:pid:1", new SdJwtVpVerifier(CLOCK).verify(pid.vpToken, context).getVct());
    }

    @Test
    void anUnresolvableQueryIdIsRefused() throws Exception {
        PidPresentation pid = pidPresentation();
        PresentationRequestContext context = new PresentationRequestContext(
            NONCE, CLIENT_ID, DcqlQuery.fromJson(UNIFIED_QUERY_JSON),
            TrustPolicy.acceptingAll(new TrustStore(List.of(pid.chain.caCert))), "fantome");

        assertEquals(VpErrorCode.QUERY_NOT_SATISFIED, assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(pid.vpToken, context)).getCode());
    }

    // ---- Link 3a: is the issuer entitled to THIS card type? ------------------

    @Test
    void anIssuerRefusedByThePolicyStopsVerification() throws Exception {
        PidPresentation pid = pidPresentation();
        PresentationRequestContext context = new PresentationRequestContext(
            NONCE, CLIENT_ID, DcqlQuery.fromJson(PID_QUERY_JSON),
            new TrustPolicy(new TrustStore(List.of(pid.chain.caCert)),
                (vct, anchor) -> IssuerDecision.REFUSED), "pid");

        VpVerificationException e = assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(pid.vpToken, context));
        assertEquals(VpErrorCode.ISSUER_NOT_AUTHORIZED, e.getCode(),
            "a trusted-but-unentitled issuer must be distinguishable from an unknown one");
    }

    @Test
    void aPinnedTypeSignedUnderAnotherAnchorIsRefused() throws Exception {
        PidPresentation pid = pidPresentation();
        // The chain that signed this presentation is pid.chain.caCert; pin a different one.
        TrustPolicy policy = new TrustPolicy(
            new TrustStore(List.of(pid.chain.caCert)),
            new OwnVctIssuerAuthorization(VCT, List.of(pid.chain.rogueCaCert)));
        PresentationRequestContext context = new PresentationRequestContext(
            NONCE, CLIENT_ID, DcqlQuery.fromJson(PID_QUERY_JSON), policy, "pid");

        assertEquals(VpErrorCode.ISSUER_NOT_AUTHORIZED, assertThrows(VpVerificationException.class,
            () -> new SdJwtVpVerifier(CLOCK).verify(pid.vpToken, context)).getCode());
    }

    @Test
    void aPinnedTypeSignedUnderTheRightAnchorIsAccepted() throws Exception {
        PidPresentation pid = pidPresentation();
        TrustPolicy policy = new TrustPolicy(
            new TrustStore(List.of(pid.chain.caCert)),
            new OwnVctIssuerAuthorization(VCT, List.of(pid.chain.caCert)));
        PresentationRequestContext context = new PresentationRequestContext(
            NONCE, CLIENT_ID, DcqlQuery.fromJson(PID_QUERY_JSON), policy, "pid");

        assertEquals(VCT, new SdJwtVpVerifier(CLOCK).verify(pid.vpToken, context).getVct());
    }

    // ---- Result: the credential's expiry --------------------------------------

    @Test
    void verifiedPresentationCarriesTheCredentialExpiry() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        long exp = NOW + 100_000;
        String credential = issuer.issue(VCT, pidClaims(), holder.getPublic(), NOW - 1000, exp);
        String vpToken = withKbJwt(credential, holder, NOW);

        PresentationRequestContext context = contextWith(new TrustStore(List.of(chain.caCert)));

        VerifiedPresentation result = new SdJwtVpVerifier(CLOCK).verify(vpToken, context);

        assertEquals(exp, result.getExpiresAt(),
            "the credential's exp must surface: it is what decides card renewal");
        assertFalse(result.getClaims().containsKey("exp"),
            "exp stays filtered out of the business claims: it has its own accessor");
    }

    // ---- Factory / ServiceLoader ----------------------------------------------

    @Test
    void factoryIsDiscoverableViaServiceLoaderWithExpectedId() {
        boolean found = false;
        for (VpVerifierFactory factory : ServiceLoader.load(VpVerifierFactory.class)) {
            if (factory instanceof SdJwtVpVerifierFactory) {
                found = true;
                assertEquals("dc+sd-jwt", factory.getId());
            }
        }
        assertTrue(found, "SdJwtVpVerifierFactory must be discoverable via ServiceLoader");
    }
}
