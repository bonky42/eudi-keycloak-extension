package org.keycloak.protocol.oid4vc.vp.login.keys;

import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.List;

/**
 * A realm key provider for the OID4VP verifier's signing material.
 *
 * <p><b>Why this exists.</b> Keycloak 26.7 declares ten key providers and not one of them imports
 * an EC key: two import RSA, seven generate, and {@code java-keystore} reads a file. The verifier's
 * key can only be imported — the EUDI registry generates the pair itself and takes no CSR — so
 * there was nowhere in a realm to put it, and it lived in the identity provider's configuration
 * instead, where {@code StripSecretsUtils.stripBroker} masks {@code clientSecret} and nothing else.
 *
 * <p><b>What moving it buys.</b> A component goes through {@code stripComponent}, which receives a
 * {@code KeycloakSession} and therefore can consult the {@code secret} flag declared below. The
 * masking then holds everywhere the representation goes — the admin API, and admin events, where
 * an unmasked value is written to the database and forwarded to every event listener.
 *
 * <p><b>Why the Keys screen needs nothing from us.</b> {@code KeyProvidersPicker} lists whatever
 * {@code componentTypes} contains and {@code KeyProviderForm} renders it with
 * {@code DynamicComponents}. That is the exact opposite of the identity provider screens, whose
 * settings components are chosen from a list of provider ids compiled into the console's bundle —
 * which is why this repository carries a rebuilt console for one page and nothing for this one.
 */
public class Oid4vpVerifierKeyProviderFactory implements KeyProviderFactory<Oid4vpVerifierKeyProvider> {

    public static final String ID = "oid4vp-verifier-key";
    public static final String PRIVATE_KEY_PEM = "privateKeyPem";
    public static final String CERTIFICATE_PEM = "certificatePem";

    /** P-256 in bits. {@code SdJwtVpVerifier} hard-codes this curve; so does the EUDI registry. */
    private static final int P256_FIELD_SIZE = 256;

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = List.of(
        Attributes.PRIORITY_PROPERTY,
        Attributes.ENABLED_PROPERTY,
        Attributes.ACTIVE_PROPERTY,
        privateKeyProperty(),
        new ProviderConfigProperty(
            CERTIFICATE_PEM,
            "Certificate (PEM)",
            "The X.509 certificate this key signs with. It travels as the Request Object's x5c and "
                + "the verifier's client_id is the SHA-256 of its DER, so it is what a wallet "
                + "checks us against.",
            ProviderConfigProperty.TEXT_TYPE,
            null));

    private static ProviderConfigProperty privateKeyProperty() {
        ProviderConfigProperty property = new ProviderConfigProperty(
            PRIVATE_KEY_PEM,
            "Private Key (PEM)",
            "PKCS#8 EC private key on P-256. Write-only: the server masks it on the way out.",
            ProviderConfigProperty.TEXT_TYPE,
            null);
        property.setSecret(true);
        return property;
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getHelpText() {
        return "Imports the OID4VP verifier's signing key and certificate, as issued by a relying "
            + "party registration service. Passive by default: the key signs Request Objects and "
            + "should not be drawn on to sign anything else this realm issues.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public Oid4vpVerifierKeyProvider create(KeycloakSession session, ComponentModel model) {
        return new Oid4vpVerifierKeyProvider(model);
    }

    /**
     * Everything that can be established before the material is ever used is established here.
     *
     * <p>This is the reason the identity provider does not need a rule of its own: what it
     * references has already been checked, once, by the component that holds it. A configuration
     * refused here never becomes a Request Object that a wallet rejects for reasons naming none of
     * this.
     */
    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model)
        throws ComponentValidationException {

        String keyPem = model.get(PRIVATE_KEY_PEM);
        String certPem = model.get(CERTIFICATE_PEM);
        if (keyPem == null || keyPem.isBlank()) {
            throw new ComponentValidationException("A private key is required");
        }
        if (certPem == null || certPem.isBlank()) {
            throw new ComponentValidationException("A certificate is required");
        }

        PrivateKey privateKey = parse(() -> VerifierPem.privateKey(keyPem), "private key");
        X509Certificate certificate = parse(() -> VerifierPem.certificate(certPem), "certificate");

        if (!(privateKey instanceof ECPrivateKey ec)
            || ec.getParams().getCurve().getField().getFieldSize() != P256_FIELD_SIZE) {
            throw new ComponentValidationException(
                "The private key must be an EC key on P-256: it signs the Request Object with "
                    + "ES256, and nothing else is accepted on that path");
        }

        // Signing a probe and verifying it against the certificate is the only check that settles
        // it: an EC private key does not carry its public half, so the two can only be compared by
        // using them. Mismatched, they produce a request signed by one identity and announcing
        // another, and the wallet answers with a trust failure that names neither.
        if (!signsFor(privateKey, certificate)) {
            throw new ComponentValidationException(
                "The private key does not match the certificate: the request would be signed by "
                    + "one identity and announce another");
        }
    }

    private static boolean signsFor(PrivateKey privateKey, X509Certificate certificate) {
        try {
            byte[] probe = "oid4vp-verifier-key".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(privateKey);
            signer.update(probe);
            byte[] signature = signer.sign();

            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(probe);
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    private static <T> T parse(java.util.function.Supplier<T> supplier, String what) {
        try {
            return supplier.get();
        } catch (RuntimeException e) {
            throw new ComponentValidationException("The " + what + " is not readable as PEM", e);
        }
    }
}
