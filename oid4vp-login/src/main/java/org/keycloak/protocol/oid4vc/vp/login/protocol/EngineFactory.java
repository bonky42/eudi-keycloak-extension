package org.keycloak.protocol.oid4vc.vp.login.protocol;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.protocol.oid4vc.vp.engine.PresentationEngine;
import org.keycloak.protocol.oid4vc.vp.login.keys.VerifierSigningMaterial;
import org.keycloak.protocol.oid4vc.vp.request.RequestObjectBuilder;
import org.keycloak.protocol.oid4vc.vp.store.SingleUseTransactionStore;
import org.keycloak.protocol.oid4vc.vp.trust.OwnVctIssuerAuthorization;
import org.keycloak.protocol.oid4vc.vp.trust.TrustPolicy;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerifier;
import org.keycloak.provider.ProviderFactory;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;

/**
 * Assembles a real {@link PresentationEngine} from a live {@link KeycloakSession} and an
 * {@link Oid4vpConfig}: a transaction store backed by the session's {@link SingleUseObjectProvider},
 * {@link VpVerifier}s resolved through the {@code VpVerifierFactory} SPI and keyed by
 * {@code getId()} (the credential format, {@code "dc+sd-jwt"} for instance), trust anchors and
 * signing key and certificate taken from the configuration, and the system clock.
 */
public final class EngineFactory {

    private EngineFactory() {
    }

    /**
     * @param session         the current Keycloak session, used to resolve the
     *                        {@link SingleUseObjectProvider} and the SPI-registered
     *                        {@code VpVerifierFactory} instances
     * @param config          typed reading of the OID4VP identity provider's configuration
     * @param signing         the key and certificate to sign Request Objects with, already resolved
     * @param clientId        the verifier's identifier (the Request Object's {@code client_id})
     * @param responseUriBase where the {@code vp_token} is posted back ({@code response_uri})
     */
    public static PresentationEngine build(KeycloakSession session, Oid4vpConfig config,
                                            VerifierSigningMaterial signing,
                                            String clientId, String responseUriBase) {
        SingleUseTransactionStore store = new SingleUseTransactionStore(
            session.getProvider(SingleUseObjectProvider.class));

        Map<String, VpVerifier> verifiers = new HashMap<>();
        session.getKeycloakSessionFactory().getProviderFactoriesStream(VpVerifier.class)
            .forEach(factory -> verifiers.put(factory.getId(), create(factory, session)));

        TrustPolicy trustPolicy = new TrustPolicy(
            config.trustStore(),
            new OwnVctIssuerAuthorization(config.ownVct(), config.ownIssuerAnchors()));
        RequestObjectBuilder requestBuilder = new RequestObjectBuilder(
            signing.keyPair(), signing.certificate(), Clock.systemUTC());

        return new PresentationEngine(store, requestBuilder, verifiers, trustPolicy,
            clientId, responseUriBase, Clock.systemUTC());
    }

    @SuppressWarnings("unchecked")
    private static VpVerifier create(ProviderFactory<?> factory, KeycloakSession session) {
        return ((ProviderFactory<VpVerifier>) factory).create(session);
    }
}
