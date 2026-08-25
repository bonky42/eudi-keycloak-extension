package org.keycloak.protocol.oid4vc.vp.verifier.sdjwt;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerifier;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerifierFactory;

/**
 * The Keycloak factory for {@link SdJwtVpVerifier}, registered under the provider id
 * {@code dc+sd-jwt}, which is the SD-JWT VC credential format identifier.
 */
public final class SdJwtVpVerifierFactory implements VpVerifierFactory {

    public static final String PROVIDER_ID = "dc+sd-jwt";

    @Override
    public VpVerifier create(KeycloakSession session) {
        return new SdJwtVpVerifier();
    }

    @Override
    public void init(Config.Scope config) {
        // no configuration
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // nothing to do
    }

    @Override
    public void close() {
        // nothing to release
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
