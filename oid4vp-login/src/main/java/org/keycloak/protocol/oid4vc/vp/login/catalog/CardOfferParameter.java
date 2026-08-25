package org.keycloak.protocol.oid4vc.vp.login.catalog;

import org.keycloak.representations.idm.oid4vc.VerifiableCredentialOfferActionConfig;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * Builds the {@code kc_action_parameter} value that accompanies
 * {@code kc_action=verifiable_credential_offer} on {@code /auth}.
 *
 * <p><b>The encoding is not reproduced by hand.</b> {@code asEncodedParameter()} serialises the
 * bean to JSON then Base64Url, and {@code VerifiableCredentialOfferAction} reads it back through
 * the mirror method {@code decodeConfig}. Reimplementing that transformation would let us drift
 * silently from one Keycloak release to the next for no gain: the action would reject the parameter
 * as "in incorrect format", after the detour through the login page — that is, far from the code at
 * fault.</p>
 *
 * <p><b>Both fields are required, not optional.</b> This is the last place their absence can still
 * be seen:</p>
 * <ul>
 *   <li>without {@code clientId}, the pre-authorized code carried by the offer references no client
 *       and the token endpoint fails with "invalid_request / No client model for: null" — the
 *       holder scans a QR code that leads nowhere (found end to end);</li>
 *   <li>without {@code credentialConfigurationId}, the action fails with "Credential configuration
 *       ID was missing".</li>
 * </ul>
 * <p>Either way the error surfaces only AFTER authentication, in a context where nothing points
 * back to the caller. Failing here, early and loudly, is what makes the defect visible.</p>
 */
public final class CardOfferParameter {

    private CardOfferParameter() {
    }

    /**
     * @param credentialConfigurationId the credential scope's {@code vc.credential_configuration_id}
     *                                  attribute, never the scope name
     * @return the payload to glue to {@code kc_action} after a colon
     * @throws IllegalArgumentException if it is missing
     */
    public static String encode(String credentialConfigurationId, String clientId) {
        if (credentialConfigurationId == null || credentialConfigurationId.isBlank()) {
            throw new IllegalArgumentException("credentialConfigurationId is required: without it "
                + "the verifiable_credential_offer action fails with 'Credential configuration ID "
                + "was missing'");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("clientId is required for a pre-authorized offer: "
                + "without it the code references no client and the token endpoint fails with "
                + "'No client model for: null'");
        }
        VerifiableCredentialOfferActionConfig config = new VerifiableCredentialOfferActionConfig();
        config.setCredentialConfigurationId(credentialConfigurationId);
        config.setClientId(clientId);
        // PRE-AUTHORIZED, unlike the stock console, which sends false.
        //
        // The stock choice makes the wallet open a browser, authenticate a SECOND time, and come
        // back through its own deep link (`eu.europa.ec.euidi://authorization`). That leg buys
        // nothing here: issuance fails at the same place either way, because the EUDI wallet always
        // builds a configuration-based credential request while OID4VCI 1.0 §8.2 requires an
        // identifier-based one as soon as the token response carries `authorization_details` —
        // which Keycloak returns in BOTH flows. See eudi-lib-android-wallet-core issue #353 and
        // the fix proposed in PR #369, open since 2026-06-30.
        //
        // So the only thing the stock choice changes is one more authentication for the holder, and
        // a deep link that has to be registered as a redirect URI on the client. Both are dropped.
        config.setPreAuthorized(Boolean.TRUE);

        try {
            return config.asEncodedParameter();
        } catch (IOException e) {
            // Serialising a three-field bean can only fail on a broken Keycloak contract: that is a
            // programming defect, not an operational condition to recover from. We refuse to
            // disguise it as "no offer available".
            throw new UncheckedIOException("cannot encode verifiable_credential_offer parameter", e);
        }
    }
}
