package org.keycloak.protocol.oid4vc.vp.testsupport;

import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.CertificateUtils;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

/**
 * Generates a self-signed EC P-256 CA and an issuer certificate signed by it, plus a second,
 * independent "rogue" CA for {@code TrustStore}'s negative tests.
 *
 * <p>The constructor declares no checked exception: any generation error is wrapped in an
 * {@link IllegalStateException}.</p>
 */
public final class TestTrustChain {

    public final KeyPair caKeyPair;
    public final X509Certificate caCert;

    public final KeyPair issuerKeyPair;
    public final X509Certificate issuerCert;

    /** A leaf DISTINCT from {@link #issuerCert}: this one signs the CARDS Keycloak issues, where
     *  {@code issuerCert} signs the verifier's Request Objects. Same CA, separate uses — a
     *  compromise of one is not a compromise of the other. */
    public final KeyPair cardIssuerKeyPair;
    public final X509Certificate cardIssuerCert;

    public final KeyPair rogueCaKeyPair;
    public final X509Certificate rogueCaCert;

    /** A second authority, this one APPROVED — not to be confused with {@link #rogueCaCert}, which
     *  is deliberately outside the store and tests {@code UNTRUSTED_ISSUER}. This one goes into the
     *  store: it stands for the legitimate third-party issuer a trust registry will add one day,
     *  which is exactly the event that arms the gap pinning closes. */
    public final KeyPair thirdPartyCaKeyPair;
    public final X509Certificate thirdPartyCaCert;
    public final KeyPair thirdPartyIssuerKeyPair;
    public final X509Certificate thirdPartyIssuerCert;

    public TestTrustChain() {
        try {
            if (!CryptoIntegration.isInitialised()) {
                CryptoIntegration.init(TestTrustChain.class.getClassLoader());
            }

            this.caKeyPair = generateEcKeyPair();
            this.caCert = CertificateUtils.generateV1SelfSignedCertificate(caKeyPair, "oid4vp-test-ca");

            this.issuerKeyPair = generateEcKeyPair();
            this.issuerCert = CertificateUtils.generateV3Certificate(
                issuerKeyPair, caKeyPair.getPrivate(), caCert, "oid4vp-test-issuer");

            this.cardIssuerKeyPair = generateEcKeyPair();
            this.cardIssuerCert = CertificateUtils.generateV3Certificate(
                cardIssuerKeyPair, caKeyPair.getPrivate(), caCert, "oid4vp-test-card-issuer");

            this.rogueCaKeyPair = generateEcKeyPair();
            this.rogueCaCert = CertificateUtils.generateV1SelfSignedCertificate(rogueCaKeyPair, "oid4vp-test-rogue-ca");

            this.thirdPartyCaKeyPair = generateEcKeyPair();
            this.thirdPartyCaCert = CertificateUtils.generateV1SelfSignedCertificate(
                thirdPartyCaKeyPair, "oid4vp-test-third-party-ca");

            this.thirdPartyIssuerKeyPair = generateEcKeyPair();
            this.thirdPartyIssuerCert = CertificateUtils.generateV3Certificate(
                thirdPartyIssuerKeyPair, thirdPartyCaKeyPair.getPrivate(), thirdPartyCaCert,
                "oid4vp-test-third-party-issuer");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate test trust chain", e);
        }
    }

    /**
     * Writes the card-issuing key into a temporary PKCS12 keystore under {@code alias}, with the
     * COMPLETE chain: leaf THEN CA.
     *
     * <p>The complete chain is essential. Keycloak's SD-JWT signer builds the {@code x5c} header
     * from the signing key's chain, discarding self-signed certificates carrying
     * {@code basicConstraints}. A keystore holding only a self-signed leaf therefore produces NO
     * {@code x5c} at all, and our verifier refuses the card as {@code UNTRUSTED_ISSUER}.</p>
     *
     * @return the PKCS12 file's path, to copy into the Keycloak container
     */
    public Path writeCardIssuerKeystore(String alias, String password) {
        try {
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(null, null);
            keystore.setKeyEntry(alias, cardIssuerKeyPair.getPrivate(), password.toCharArray(),
                new Certificate[] { cardIssuerCert, caCert });

            Path file = Files.createTempFile(alias, ".p12");
            try (OutputStream out = Files.newOutputStream(file)) {
                keystore.store(out, password.toCharArray());
            }
            return file;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to write card issuer keystore", e);
        }
    }

    private static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }
}
