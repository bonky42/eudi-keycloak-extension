package org.keycloak.protocol.oid4vc.vp.login.protocol;

import org.keycloak.protocol.oid4vc.vp.model.DcqlQuery;
import org.jboss.logging.Logger;
import org.keycloak.protocol.oid4vc.vp.trust.TrustStore;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Typed reading of the raw key/value configuration of an OID4VP {@code IdentityProviderModel}:
 * trust anchors, signing key and certificate, DCQL query, matching claim, and transaction TTL.
 */
public final class Oid4vpConfig {

    public static final String TRUST_ANCHORS_PEM = "trustAnchorsPem";
    public static final String OWN_ISSUER_ANCHORS_PEM = "ownIssuerAnchorsPem";
    public static final String SIGNING_KEY_PEM = "signingKeyPem";
    public static final String SIGNING_CERT_PEM = "signingCertPem";
    public static final String DCQL_QUERY_JSON = "dcqlQueryJson";
    public static final String MATCHING_CLAIM = "matchingClaim";
    public static final String TTL_SECONDS = "ttlSeconds";
    public static final String SUBJECT_CLAIM = "subjectClaim";
    public static final String SUBJECT_POLICY = "subjectPolicy";
    public static final String OWN_VCT = "ownVct";
    public static final String REISSUE_BEFORE_SECONDS = "reissueBeforeSeconds";
    public static final String OWN_CREDENTIAL_CONFIG_ID = "ownCredentialConfigId";
    /** A {@code vct=claim,vct=claim} table ({@link VctTable} idiom): which claim carries the
     *  stable subject for each credential type. Read by {@code ClaimTableIdentityResolver}; it has
     *  no admin console property yet. */
    public static final String SUBJECT_CLAIM_BY_VCT = "subjectClaimByVct";

    private static final int DEFAULT_TTL_SECONDS = 120;
    private static final String DEFAULT_SUBJECT_CLAIM = "sub";
    private static final int DEFAULT_REISSUE_BEFORE_SECONDS = 2_592_000;   // 30 days
    /** The only valid value for {@link #SUBJECT_POLICY}; exposed so the admin-console config
     *  property (LIST_TYPE) and this default can never drift apart. */
    public static final String SUBJECT_POLICY_REJECT = "REJECT";

    private final Map<String, String> config;

    public Oid4vpConfig(Map<String, String> config) {
        this.config = config;
    }

    private static final Logger LOG = Logger.getLogger(Oid4vpConfig.class);

    /**
     * Anchors entitled to sign {@link #ownVct()}. Empty when unconfigured — and unconfigured
     * refuses, see {@code OwnVctIssuerAuthorization}.
     *
     * <p>A bundle rather than one certificate, so that rotating the issuing authority can overlap
     * instead of invalidating every card in circulation at once.</p>
     *
     * <p>Deliberately does <b>not</b> throw on a misconfiguration. An accessor that throws during a
     * login turns an administrator's typo into an error page — this project has already been bitten
     * by exactly that. A pinned anchor absent from {@link #TRUST_ANCHORS_PEM} simply never matches a
     * validated chain, so the behaviour fails closed on its own; the log below exists to say why,
     * because "every own-credential login is refused" is otherwise a puzzling symptom.</p>
     */
    public List<X509Certificate> ownIssuerAnchors() {
        String pem = config.get(OWN_ISSUER_ANCHORS_PEM);
        if (pem == null || pem.isBlank()) {
            return List.of();
        }
        List<X509Certificate> pinned;
        try {
            pinned = TrustStore.fromPem(pem).getAnchors();
        } catch (GeneralSecurityException e) {
            LOG.errorf(e, "%s is not a valid PEM bundle; no credential of vct=%s will be accepted",
                OWN_ISSUER_ANCHORS_PEM, config.get(OWN_VCT));
            return List.of();
        }
        for (X509Certificate anchor : pinned) {
            if (!trustStore().getAnchors().contains(anchor)) {
                LOG.errorf("%s contains a certificate absent from %s (subject=%s). A chain can never "
                        + "validate against it, so every credential of vct=%s will be refused. Add it "
                        + "to %s, or correct the pin.",
                    OWN_ISSUER_ANCHORS_PEM, TRUST_ANCHORS_PEM, anchor.getSubjectX500Principal(),
                    config.get(OWN_VCT), TRUST_ANCHORS_PEM);
            }
        }
        return pinned;
    }

    public TrustStore trustStore() {
        try {
            return TrustStore.fromPem(config.get(TRUST_ANCHORS_PEM));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid " + TRUST_ANCHORS_PEM, e);
        }
    }

    public KeyPair signingKey() {
        PrivateKey privateKey = parsePrivateKey(config.get(SIGNING_KEY_PEM));
        return new KeyPair(signingCert().getPublicKey(), privateKey);
    }

    public X509Certificate signingCert() {
        return parseCertificate(config.get(SIGNING_CERT_PEM));
    }

    public DcqlQuery dcqlQuery() {
        return DcqlQuery.fromJson(config.get(DCQL_QUERY_JSON));
    }

    public String matchingClaim() {
        return config.get(MATCHING_CLAIM);
    }

    public int ttlSeconds() {
        String raw = config.get(TTL_SECONDS);
        if (raw == null || raw.isBlank()) {
            return DEFAULT_TTL_SECONDS;
        }
        return Integer.parseInt(raw.trim());
    }

    public String subjectClaim() {
        String raw = config.get(SUBJECT_CLAIM);
        if (raw == null || raw.isBlank()) {
            return DEFAULT_SUBJECT_CLAIM;
        }
        return raw.trim();
    }

    public String subjectPolicy() {
        String raw = config.get(SUBJECT_POLICY);
        if (raw == null || raw.isBlank()) {
            return SUBJECT_POLICY_REJECT;
        }
        return raw.trim();
    }

    /** The {@code vct} of the card THIS Keycloak issues, or {@code null} when issuance is not
     *  configured — in which case every issuance path is inert. */
    public String ownVct() {
        String raw = config.get(OWN_VCT);
        return (raw == null || raw.isBlank()) ? null : raw.trim();
    }

    /** How many seconds before the presented card expires to offer a fresh one. 30 days by
     *  default. */
    public int reissueBeforeSeconds() {
        String raw = config.get(REISSUE_BEFORE_SECONDS);
        if (raw == null || raw.isBlank()) {
            return DEFAULT_REISSUE_BEFORE_SECONDS;
        }
        return Integer.parseInt(raw.trim());
    }

    /** The configuration id of the credential this Keycloak issues: the credential scope's
     *  {@code vc.credential_configuration_id} attribute. Used both to find the holder's entitlement
     *  and to parameterise the offer action. */
    public String ownCredentialConfigId() {
        String raw = config.get(OWN_CREDENTIAL_CONFIG_ID);
        return (raw == null || raw.isBlank()) ? null : raw.trim();
    }

    /** A {@code vct=claim} table declaring WHICH claim carries the subject for each credential
     *  type. A {@code vct} absent from it falls back to {@link #subjectClaim()}. It never decides
     *  the identity regime: the verbatim one stays derived from {@link #ownVct()}. */
    public String subjectClaimByVct() {
        String raw = config.get(SUBJECT_CLAIM_BY_VCT);
        return (raw == null || raw.isBlank()) ? null : raw.trim();
    }

    private static X509Certificate parseCertificate(String pem) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid PEM certificate", e);
        }
    }

    private static PrivateKey parsePrivateKey(String pem) {
        try {
            String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(base64);
            KeyFactory factory = KeyFactory.getInstance("EC");
            return factory.generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid PEM private key", e);
        }
    }
}
