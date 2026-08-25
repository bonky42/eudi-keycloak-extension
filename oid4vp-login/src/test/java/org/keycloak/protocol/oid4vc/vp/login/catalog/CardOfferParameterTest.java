package org.keycloak.protocol.oid4vc.vp.login.catalog;

import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.oid4vc.VerifiableCredentialOfferActionConfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Pins the payload the {@code verifiable_credential_offer} action receives.
 *
 * <p><b>The shape is copied from Keycloak's own console, not inferred.</b> On 2026-08-17 the stock
 * "Issue to Wallet" button was observed producing exactly:</p>
 *
 * <pre>{"credentialConfigurationId":"eudi-pid","preAuthorized":false}</pre>
 *
 * <p>No client id, and {@code preAuthorized} false. Our earlier payload carried a client id and
 * {@code preAuthorized} true, and the action answered {@code missing_credential_config}. When the
 * product ships a working caller of its own undocumented action, that caller is the specification.</p>
 *
 * <p>The encoding itself is never reproduced by hand: {@code asEncodedParameter()} serialises to
 * JSON then Base64Url, and {@code decodeConfig} is its mirror. Asserting the ROUND TRIP rather than
 * the string keeps us from breaking on their serialisation.</p>
 */
class CardOfferParameterTest {

    private static final String CONFIG_ID = "eudi-pid";
    private static final String CLIENT_ID = "account-console";

    @Test
    void encodedParameterIsReadableBackByKeycloaksOwnDecoder() throws Exception {
        String encoded = CardOfferParameter.encode(CONFIG_ID, CLIENT_ID);

        VerifiableCredentialOfferActionConfig decoded =
            VerifiableCredentialOfferActionConfig.decodeConfig(encoded);

        assertNotNull(decoded, "the parameter must read back through Keycloak's own decoder");
        assertEquals(CONFIG_ID, decoded.getCredentialConfigurationId());
    }

    @Test
    void offerIsPreAuthorizedSoTheHolderAuthenticatesOnlyOnce() throws Exception {
        String encoded = CardOfferParameter.encode(CONFIG_ID, CLIENT_ID);

        VerifiableCredentialOfferActionConfig decoded =
            VerifiableCredentialOfferActionConfig.decodeConfig(encoded);

        assertEquals(Boolean.TRUE, decoded.getPreAuthorized(),
            "the stock console sends false, which makes the wallet open a browser and authenticate "
                + "a SECOND time, then come back through its own deep link. That leg buys nothing: "
                + "issuance fails at the same place either way (upstream wallet-core #353), so the "
                + "only thing it changes is one more authentication for the holder");
    }

    @Test
    void clientIdIsSentBecauseAPreAuthorizedCodeMustBindToOne() throws Exception {
        String encoded = CardOfferParameter.encode(CONFIG_ID, CLIENT_ID);

        VerifiableCredentialOfferActionConfig decoded =
            VerifiableCredentialOfferActionConfig.decodeConfig(encoded);

        assertEquals(CLIENT_ID, decoded.getClientId(),
            "without it the pre-authorized code references no client and the token endpoint fails "
                + "with 'No client model for: null' (end-to-end finding, task 9)");
    }

    @Test
    void missingClientIsRefusedRatherThanProducingAQrThatLeadsNowhere() {
        assertThrows(IllegalArgumentException.class,
            () -> CardOfferParameter.encode(CONFIG_ID, null),
            "a pre-authorized offer without a client fails only at the token endpoint, far from here");
    }

    @Test
    void missingCredentialConfigurationIsRefusedRatherThanSentEmpty() {
        assertThrows(IllegalArgumentException.class,
            () -> CardOfferParameter.encode(null, CLIENT_ID),
            "without a credential configuration the action fails with 'Credential configuration ID "
                + "was missing', after the detour through the login page — failing here is the only "
                + "way that becomes visible");
    }
}
