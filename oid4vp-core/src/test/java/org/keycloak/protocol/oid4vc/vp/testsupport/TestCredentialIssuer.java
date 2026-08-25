package org.keycloak.protocol.oid4vc.vp.testsupport;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Map;

/**
 * Forges test SD-JWT VCs ({@code dc+sd-jwt}), ES256-signed by a {@link TestTrustChain}'s issuer key,
 * with the issuer certificate in the {@code x5c} JOSE header.
 *
 * <p>Every entry of the {@code claims} map becomes an SD-JWT {@code [salt, name, value]}
 * disclosure; only the disclosure digests appear in the signed payload, under {@code _sd}. No
 * KB-JWT is appended — that is the wallet's job.</p>
 */
public final class TestCredentialIssuer {

    private static final Base64.Encoder B64URL_NOPAD = Base64.getUrlEncoder().withoutPadding();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final TestTrustChain chain;
    private final SecureRandom random = new SecureRandom();

    public TestCredentialIssuer(TestTrustChain chain) {
        this.chain = chain;
    }

    /** An EC P-256 key pair standing in for the holder's key, carried in the issued credential's
     *  {@code cnf.jwk}. */
    public KeyPair newHolderKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate holder key pair", e);
        }
    }

    /**
     * Issues an ES256-signed SD-JWT VC, shaped as
     * {@code <issuer-jwt>~<disclosure1>~<disclosure2>~...~} (un {@code ~} final,
     * pas de KB-JWT).
     *
     * @param vct       the credential type (the {@code vct} claim)
     * @param claims    claims to disclose selectively; each becomes a
     *                  {@code [salt, name, value]} disclosure
     * @param holderKey the holder's public key, carried in {@code cnf.jwk}
     * @param iat       the {@code iat} claim, epoch seconds
     * @param exp       the {@code exp} claim, epoch seconds
     */
    public String issue(String vct, Map<String, Object> claims, PublicKey holderKey, long iat, long exp) {
        return issueSignedBy(vct, claims, holderKey, iat, exp, chain.issuerKeyPair, chain.issuerCert);
    }

    /**
     * Like {@link #issue}, but signed by a CHOSEN key and certificate.
     *
     * <p>This mounts the attack issuer pinning closes: a perfectly legitimate third-party issuer,
     * whose chain climbs to an approved anchor, issues a card bearing OUR {@code vct}. Everything is
     * cryptographically sound; only the entitlement is missing.</p>
     */
    public String issueSignedBy(String vct, Map<String, Object> claims, PublicKey holderKey,
                                 long iat, long exp, KeyPair signingPair, X509Certificate leafCert) {
        try {
            StringBuilder disclosuresPart = new StringBuilder();
            ArrayNode sdDigests = MAPPER.createArrayNode();

            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                String disclosure = buildDisclosure(entry.getKey(), entry.getValue());
                disclosuresPart.append(disclosure).append('~');
                sdDigests.add(digest(disclosure));
            }

            ObjectNode payload = MAPPER.createObjectNode();
            payload.put("iss", "https://test-issuer.example.org");
            payload.put("vct", vct);
            payload.set("cnf", cnfJwk(holderKey));
            payload.put("iat", iat);
            payload.put("exp", exp);
            payload.set("_sd", sdDigests);
            payload.put("_sd_alg", "sha-256");

            String issuerJwt = signJwt(payload, signingPair, leafCert);

            return issuerJwt + "~" + disclosuresPart;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to issue test SD-JWT VC", e);
        }
    }

    private String buildDisclosure(String name, Object value) throws Exception {
        ArrayNode disclosureArray = MAPPER.createArrayNode();
        disclosureArray.add(randomSalt());
        disclosureArray.add(name);
        disclosureArray.addPOJO(value);
        byte[] json = MAPPER.writeValueAsBytes(disclosureArray);
        return B64URL_NOPAD.encodeToString(json);
    }

    private String randomSalt() {
        byte[] saltBytes = new byte[16];
        random.nextBytes(saltBytes);
        return B64URL_NOPAD.encodeToString(saltBytes);
    }

    private String digest(String disclosureB64Url) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(disclosureB64Url.getBytes(StandardCharsets.US_ASCII));
        return B64URL_NOPAD.encodeToString(hash);
    }

    private ObjectNode cnfJwk(PublicKey holderKey) {
        ObjectNode cnf = MAPPER.createObjectNode();
        cnf.set("jwk", EcJwk.publicJwk(holderKey));
        return cnf;
    }

    private String signJwt(ObjectNode payload, KeyPair signingPair, X509Certificate leafCert) throws Exception {
        ObjectNode header = MAPPER.createObjectNode();
        header.put("alg", "ES256");
        header.put("typ", "dc+sd-jwt");
        ArrayNode x5c = MAPPER.createArrayNode();
        x5c.add(Base64.getEncoder().encodeToString(leafCert.getEncoded()));
        header.set("x5c", x5c);

        String headerB64 = B64URL_NOPAD.encodeToString(MAPPER.writeValueAsBytes(header));
        String payloadB64 = B64URL_NOPAD.encodeToString(MAPPER.writeValueAsBytes(payload));
        String signingInput = headerB64 + "." + payloadB64;

        Signature signature = Signature.getInstance("SHA256withECDSAinP1363Format");
        signature.initSign(signingPair.getPrivate());
        signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        byte[] sig = signature.sign();

        return signingInput + "." + B64URL_NOPAD.encodeToString(sig);
    }
}
