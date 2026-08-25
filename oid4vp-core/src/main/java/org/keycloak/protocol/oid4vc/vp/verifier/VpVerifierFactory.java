package org.keycloak.protocol.oid4vc.vp.verifier;

import org.keycloak.provider.ProviderFactory;

/**
 * The standard Keycloak factory for {@link VpVerifier}. Each implementation's provider id is the
 * identifier of the credential format it verifies, for example {@code "dc+sd-jwt"}.
 */
public interface VpVerifierFactory extends ProviderFactory<VpVerifier> {
}
