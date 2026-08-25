package org.keycloak.protocol.oid4vc.vp.verifier;

import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;
import org.keycloak.provider.Provider;

/**
 * The SPI provider that verifies a vp_token for one credential format, {@code dc+sd-jwt} for
 * instance. One factory is registered per format under {@link VpVerifierSpi}, each factory's
 * provider id being the format identifier.
 */
public interface VpVerifier extends Provider {

    VerifiedPresentation verify(String vpToken, PresentationRequestContext context)
        throws VpVerificationException;
}
