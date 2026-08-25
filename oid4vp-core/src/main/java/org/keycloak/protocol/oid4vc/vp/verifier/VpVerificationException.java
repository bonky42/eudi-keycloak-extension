package org.keycloak.protocol.oid4vc.vp.verifier;

/**
 * The checked exception raised when a verifiable presentation cannot be validated. It carries a
 * normalised {@link VpErrorCode}, so the caller can tell the causes apart without parsing the
 * message.
 */
public class VpVerificationException extends Exception {

    private final VpErrorCode code;

    public VpVerificationException(VpErrorCode code, String detail) {
        super(detail);
        this.code = code;
    }

    public VpErrorCode getCode() {
        return code;
    }
}
