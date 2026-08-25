package org.keycloak.protocol.oid4vc.vp.trust;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A set of trust anchors (root CAs), and PKIX validation of an x5c chain (leaf first) up to one of
 * them.
 *
 * <p>Revocation (CRL/OCSP) is explicitly disabled: it is deliberately out of scope here and is
 * tracked as its own roadmap item.</p>
 */
public final class TrustStore {

    private final List<X509Certificate> anchors;

    public TrustStore(List<X509Certificate> anchors) {
        this.anchors = List.copyOf(anchors);
    }

    /** The configured anchors, unmodifiable. */
    public List<X509Certificate> getAnchors() {
        return List.copyOf(anchors);
    }

    /**
     * Builds a {@link TrustStore} from a PEM bundle holding one or more trust anchors: a
     * concatenation of {@code -----BEGIN CERTIFICATE-----} ... {@code -----END CERTIFICATE-----}
     * blocks.
     */
    public static TrustStore fromPem(String pemBundle) throws GeneralSecurityException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(pemBundle.getBytes(StandardCharsets.UTF_8));
        Collection<? extends java.security.cert.Certificate> certs = factory.generateCertificates(in);

        List<X509Certificate> anchors = new ArrayList<>();
        for (java.security.cert.Certificate cert : certs) {
            anchors.add((X509Certificate) cert);
        }
        return new TrustStore(anchors);
    }

    /**
     * Validates that the x5c chain (leaf first) chains up to one of the anchors.
     *
     * @return the anchor that validated it
     * @throws GeneralSecurityException if the chain is empty, or chains to no known anchor
     */
    public X509Certificate validateChain(List<X509Certificate> x5cChain) throws GeneralSecurityException {
        if (x5cChain == null || x5cChain.isEmpty()) {
            throw new CertPathValidatorException("x5c chain must not be empty");
        }

        Set<TrustAnchor> trustAnchors = new HashSet<>();
        for (X509Certificate anchor : anchors) {
            trustAnchors.add(new TrustAnchor(anchor, null));
        }

        // PKIX refuses a path that itself contains a trust anchor, so every certificate equal to
        // an anchor is removed from the chain first.
        List<X509Certificate> pathCerts = new ArrayList<>();
        for (X509Certificate cert : x5cChain) {
            if (!anchors.contains(cert)) {
                pathCerts.add(cert);
            }
        }

        if (pathCerts.isEmpty()) {
            // The chain held nothing but anchors (leaf == anchor, for instance): there is no path
            // left for PKIX to validate, but we already know it is a trusted anchor.
            X509Certificate leaf = x5cChain.get(0);
            if (anchors.contains(leaf)) {
                return leaf;
            }
            throw new CertPathValidatorException("x5c chain resolved to no path certificates");
        }

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        CertPath certPath = factory.generateCertPath(pathCerts);

        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(false);

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        java.security.cert.PKIXCertPathValidatorResult result =
            (java.security.cert.PKIXCertPathValidatorResult) validator.validate(certPath, params);

        return result.getTrustAnchor().getTrustedCert();
    }
}
