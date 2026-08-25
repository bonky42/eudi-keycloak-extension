package org.keycloak.protocol.oid4vc.vp.verifier;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * Declares the {@code oid4vp-verifier} Keycloak SPI: one {@link VpVerifier} per supported credential
 * format (dc+sd-jwt, for instance), registered through {@link VpVerifierFactory}.
 */
public class VpVerifierSpi implements Spi {

    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return "oid4vp-verifier";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return VpVerifier.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return VpVerifierFactory.class;
    }
}
