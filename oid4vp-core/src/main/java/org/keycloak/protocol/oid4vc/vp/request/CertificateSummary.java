package org.keycloak.protocol.oid4vc.vp.request;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;

/**
 * What a verifier's signing certificate says about itself, in a form a screen can show.
 *
 * <p>This exists because the one field that matters most cannot be read off the certificate by eye.
 * The {@code client_id} a wallet is told is the SHA-256 of the DER, and it is what the wallet
 * compares the {@code x5c} against; a console that computed it separately could drift from what the
 * request actually announces. Here it comes from {@link VerifierClientId}, the same call the
 * request object makes, so the two cannot disagree.</p>
 *
 * <p>The rest — who the certificate names, who signed it, how long it lasts — is legible in the PEM
 * for anyone willing to run {@code openssl x509 -text}. That is precisely the point: an
 * administrator pasting a certificate into a form should not have to.</p>
 *
 * <p><b>Validity is answered about a given instant</b> rather than about "now". Not for testing
 * convenience: it keeps this a pure function of its arguments, so the value a screen shows and the
 * value a test asserts are produced the same way.</p>
 *
 * <p><b>The two dates are ISO-8601 strings, not {@code Instant}s.</b> This record is serialised to
 * JSON, and an {@code Instant} comes out as a floating-point epoch whose exact shape depends on how
 * the mapper happens to be configured — {@code 1788851296.0}, measured against a running 26.7.2. A
 * value whose format a reader has to guess is not a summary.</p>
 */
public record CertificateSummary(String subject, String issuer, String serialNumber,
                                 String notBefore, String notAfter, String clientId,
                                 String keyType, String curve,
                                 boolean notYetValid, boolean expired) {

    /** P-256 in bits, the only curve this verifier signs on. */
    private static final int P256_FIELD_SIZE = 256;

    public static CertificateSummary of(X509Certificate certificate, Instant at) {
        Instant notBefore = certificate.getNotBefore().toInstant();
        Instant notAfter = certificate.getNotAfter().toInstant();
        PublicKey publicKey = certificate.getPublicKey();

        return new CertificateSummary(
            certificate.getSubjectX500Principal().getName(),
            certificate.getIssuerX500Principal().getName(),
            certificate.getSerialNumber().toString(16),
            notBefore.toString(),
            notAfter.toString(),
            VerifierClientId.x509Hash(certificate),
            publicKey.getAlgorithm(),
            curveOf(publicKey),
            at.isBefore(notBefore),
            at.isAfter(notAfter));
    }

    /**
     * Named rather than measured in bits, because that is how the name appears everywhere a reader
     * would compare it: in a JWK, in the profile text, on the registry's own pages.
     */
    private static String curveOf(PublicKey publicKey) {
        if (!(publicKey instanceof ECPublicKey ec)) {
            return null;
        }
        int fieldSize = ec.getParams().getCurve().getField().getFieldSize();
        return fieldSize == P256_FIELD_SIZE ? "P-256" : "P-" + fieldSize;
    }

    /** Usable at the instant this summary was taken about — neither too early nor too late. */
    public boolean validNow() {
        return !notYetValid && !expired;
    }
}
