package org.keycloak.protocol.oid4vc.vp.login.keys;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * PEM decoding for the verifier's signing material.
 */
final class VerifierPem {

    private VerifierPem() {
    }

    static X509Certificate certificate(String pem) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new IllegalArgumentException("Invalid PEM certificate", e);
        }
    }

    static PrivateKey privateKey(String pem) {
        try {
            String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new IllegalArgumentException("Invalid PEM private key", e);
        }
    }
}
