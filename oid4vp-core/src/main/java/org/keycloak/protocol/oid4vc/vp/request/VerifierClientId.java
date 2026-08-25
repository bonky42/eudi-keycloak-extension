package org.keycloak.protocol.oid4vc.vp.request;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Derives the verifier's {@code client_id} from its signing certificate, following OID4VP's
 * {@code x509_hash} scheme: the SHA-256 digest of the DER, base64url without padding.
 *
 * <p>The certificate passed here must be <b>the very one</b> {@link RequestObjectBuilder} puts at
 * the head of {@code x5c}: that is what lets the wallet compare the announced identifier against
 * the certificate that signed the request. A {@code client_id} drawn from anywhere else — the
 * hostname, for instance — would break that link.
 */
public final class VerifierClientId {

    private static final String SCHEME = "x509_hash:";

    private VerifierClientId() {
    }

    /**
     * @param signerCert the Request Object's signing certificate (the {@code x5c[0]})
     * @return the {@code client_id}, as {@code x509_hash:<fingerprint>}
     */
    public static String x509Hash(X509Certificate signerCert) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(signerCert.getEncoded());
            return SCHEME + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to derive client_id from signer certificate", e);
        }
    }
}
