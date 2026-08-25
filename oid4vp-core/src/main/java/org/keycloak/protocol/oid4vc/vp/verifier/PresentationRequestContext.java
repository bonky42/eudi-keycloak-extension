package org.keycloak.protocol.oid4vc.vp.verifier;

import org.keycloak.protocol.oid4vc.vp.model.DcqlQuery;
import org.keycloak.protocol.oid4vc.vp.trust.TrustPolicy;

/**
 * The immutable context of a presentation request: what a {@link VpVerifier} needs in order to
 * check a vp_token against the request that provoked it — the anti-replay nonce, the asking client,
 * the DCQL query, and the trust policy (which anchors are accepted, and who is entitled to sign
 * what).
 */
public final class PresentationRequestContext {

    private final String nonce;
    private final String clientId;
    private final DcqlQuery dcqlQuery;
    private final TrustPolicy trustPolicy;
    private final String credentialQueryId;

    public PresentationRequestContext(String nonce, String clientId, DcqlQuery dcqlQuery,
                                       TrustPolicy trustPolicy, String credentialQueryId) {
        this.nonce = nonce;
        this.clientId = clientId;
        this.dcqlQuery = dcqlQuery;
        this.trustPolicy = trustPolicy;
        this.credentialQueryId = credentialQueryId;
    }

    public String getNonce() {
        return nonce;
    }

    public String getClientId() {
        return clientId;
    }

    public DcqlQuery getDcqlQuery() {
        return dcqlQuery;
    }

    public TrustPolicy getTrustPolicy() {
        return trustPolicy;
    }

    /** The {@code id} of the credential query the wallet filed this presentation under — the key
     *  in the {@code vp_token} object, OID4VP 1.0 section 8.1. Link 7 checks conformance to THAT
     *  query, and to no other. */
    public String getCredentialQueryId() {
        return credentialQueryId;
    }
}
