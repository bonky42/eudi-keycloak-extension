package org.keycloak.protocol.oid4vc.vp.verifier;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * ES256/JOSE signing and verification (P-256 curve, IEEE P1363 signature format), shared by the
 * production components that produce or consume ES256-signed compact JWTs:
 * {@link org.keycloak.protocol.oid4vc.vp.verifier.sdjwt.SdJwtVpVerifier} (verification) and
 * {@link org.keycloak.protocol.oid4vc.vp.request.RequestObjectBuilder} (signing).
 * <p>
 * Note: the {@code TestCredentialIssuer} test support still implements its own ES256 signing (same
 * convention, separate code); it can be migrated onto this helper later with no functional impact.
 */
public final class EcJose {

    private static final String ALGORITHM = "SHA256withECDSAinP1363Format";
    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();
    private static final Base64.Encoder B64URL_NOPAD = Base64.getUrlEncoder().withoutPadding();

    private EcJose() {
    }

    /**
     * Signs {@code signingInput} (typically {@code <header_b64>.<payload_b64>}) with {@code key},
     * and returns the signature encoded as base64url without padding.
     */
    public static String sign(PrivateKey key, String signingInput) {
        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initSign(key);
            signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return B64URL_NOPAD.encodeToString(signature.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to sign ES256 JOSE input", e);
        }
    }

    /**
     * Checks that {@code signatureB64Url} (base64url, with or without padding) is a valid ES256
     * signature of {@code signingInput} by {@code key}.
     */
    public static boolean verify(PublicKey key, String signingInput, String signatureB64Url)
        throws GeneralSecurityException {
        byte[] signatureBytes = B64URL.decode(signatureB64Url);
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initVerify(key);
        signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signature.verify(signatureBytes);
    }
}
