package org.keycloak.protocol.oid4vc.vp.login.keys;

import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.vp.login.protocol.Oid4vpConfig;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * The key and certificate this verifier signs its Request Objects with, wherever they live.
 *
 * <p><b>Two homes, for now.</b> Named a realm key component, this reads that; named nothing, it
 * falls back to the PEM pair pasted into the identity provider's configuration. The fallback is
 * deliberate and temporary — it is what lets the reference be introduced without breaking a single
 * realm that already works. Removing it is its own change.
 *
 * <p><b>Why a component id and not a kid.</b> A {@code kid} names one piece of material; replace the
 * key and it changes, and the provider would point at something gone. The component outlives its
 * contents, which is what a configured reference should do.
 *
 * <p><b>Why {@code getKeysStream} and not {@code getKey}.</b> {@code getKey(realm, kid, use, alg)}
 * selects among what Keycloak considers eligible, and whether it filters on ACTIVE is not something
 * to depend on: these keys are deliberately PASSIVE, so that they are never drawn on to sign
 * anything but this. Reading the whole set and filtering on the provider id sidesteps the question.
 *
 * <p><b>Why the lookup arrives as a supplier.</b> So the rules above can be exercised against real
 * {@link KeyWrapper}s without a server. Same separation as the admin resource: what can be decided
 * from values alone is decided from values alone.
 */
public record VerifierSigningMaterial(KeyPair keyPair, X509Certificate certificate) {

    public static VerifierSigningMaterial resolve(KeycloakSession session, RealmModel realm,
                                                  Oid4vpConfig config) {
        return resolve(config, () -> session.keys().getKeysStream(realm));
    }

    /**
     * The same resolution, against any source of realm keys. Public because it is the seam: it lets
     * the rules be exercised — and used — without a session.
     */
    public static VerifierSigningMaterial resolve(Oid4vpConfig config,
                                                  Supplier<Stream<KeyWrapper>> realmKeys) {
        String ref = config.signingKeyRef();
        if (ref == null) {
            return new VerifierSigningMaterial(config.signingKey(), config.signingCert());
        }
        return fromRealmKey(ref, realmKeys.get());
    }

    private static VerifierSigningMaterial fromRealmKey(String ref, Stream<KeyWrapper> realmKeys) {
        KeyWrapper key = realmKeys
            .filter(candidate -> ref.equals(candidate.getProviderId()))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException(
                // Named, because the ordinary cause is a key component deleted while a provider
                // still points at it. Falling back to whatever PEM is lying around would sign
                // requests under an identity nobody chose.
                "No signing key '" + ref + "' in this realm: the identity provider names a key "
                    + "component that is not there"));

        X509Certificate certificate = key.getCertificate();
        if (certificate == null) {
            throw new IllegalArgumentException(
                "The signing key '" + ref + "' carries no certificate: it travels as the request's "
                    + "x5c and the verifier's client_id is derived from it, so a key without one "
                    + "cannot sign for this provider");
        }
        if (!(key.getPrivateKey() instanceof PrivateKey privateKey)) {
            throw new IllegalArgumentException(
                "The signing key '" + ref + "' exposes no private key to sign with");
        }
        // The public half comes from the certificate rather than from the wrapper, for the same
        // reason Oid4vpConfig does it: the certificate is what the wallet checks, so it is what
        // defines the pair.
        return new VerifierSigningMaterial(
            new KeyPair(certificate.getPublicKey(), privateKey), certificate);
    }
}
