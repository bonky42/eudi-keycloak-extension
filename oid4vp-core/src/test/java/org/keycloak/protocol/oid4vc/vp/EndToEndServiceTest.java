package org.keycloak.protocol.oid4vc.vp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.protocol.oid4vc.vp.engine.PresentationEngine;
import org.keycloak.protocol.oid4vc.vp.model.DcqlQuery;
import org.keycloak.protocol.oid4vc.vp.model.PresentationTransaction;
import org.keycloak.protocol.oid4vc.vp.model.TransactionStatus;
import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;
import org.keycloak.protocol.oid4vc.vp.request.RequestObjectBuilder;
import org.keycloak.protocol.oid4vc.vp.store.SingleUseTransactionStore;
import org.keycloak.protocol.oid4vc.vp.testsupport.InMemorySingleUseObjects;
import org.keycloak.protocol.oid4vc.vp.testsupport.SimulatedWallet;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestCredentialIssuer;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;
import org.keycloak.protocol.oid4vc.vp.trust.TrustPolicy;
import org.keycloak.protocol.oid4vc.vp.trust.TrustStore;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerifier;
import org.keycloak.protocol.oid4vc.vp.verifier.sdjwt.SdJwtVpVerifier;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Assembles the FULL real engine (real store, real
 * {@link RequestObjectBuilder}, real {@link SdJwtVpVerifier}) and drives it
 * end to end through a {@link SimulatedWallet} — happy path plus one negative
 * test per adversarial {@link SimulatedWallet.Tamper} mode.
 */
class EndToEndServiceTest {

    private static final long NOW = 2_000_000_000L;
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC);
    private static final String CLIENT_ID = "x509_san_dns:kc.example.org";
    private static final String RESPONSE_URI = "https://kc.example.org/oid4vp/response";
    private static final String FORMAT = "dc+sd-jwt";

    private static final String PID_QUERY_JSON = """
        {
          "credentials": [
            {
              "id": "pid",
              "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eudi:pid:1"] },
              "claims": [
                { "path": ["given_name"] },
                { "path": ["age_over_18"] }
              ]
            }
          ]
        }""";

    private static DcqlQuery pidQuery() {
        return DcqlQuery.fromJson(PID_QUERY_JSON);
    }

    private static final String OWN_VCT = "urn:pn:account-holder:1";

    private static final String UNIFIED_QUERY_JSON = """
        {
          "credentials": [
            { "id": "pid", "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eudi:pid:1"] },
              "claims": [ { "path": ["given_name"] }, { "path": ["age_over_18"] } ] },
            { "id": "own", "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:pn:account-holder:1"] },
              "claims": [ { "path": ["sub"] } ] }
          ],
          "credential_sets": [
            { "required": false, "options": [ ["pid"] ] },
            { "required": false, "options": [ ["own"] ] }
          ]
        }""";

    private static DcqlQuery unifiedQuery() {
        return DcqlQuery.fromJson(UNIFIED_QUERY_JSON);
    }

    private static PresentationEngine newEngine(TestTrustChain chain) {
        SingleUseTransactionStore store = new SingleUseTransactionStore(new InMemorySingleUseObjects());
        RequestObjectBuilder requestBuilder = new RequestObjectBuilder(chain.issuerKeyPair, chain.issuerCert, CLOCK);
        Map<String, VpVerifier> verifiers = Map.of(FORMAT, new SdJwtVpVerifier(CLOCK));
        TrustStore trustStore = new TrustStore(List.of(chain.caCert));
        return new PresentationEngine(store, requestBuilder, verifiers, TrustPolicy.acceptingAll(trustStore), CLIENT_ID, RESPONSE_URI, CLOCK);
    }

    // ---- happy path -----------------------------------------------------------

    @Test
    void happyPathEndToEndCompletesWithClaims() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        PresentationEngine engine = newEngine(chain);
        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain));

        PresentationTransaction tx = engine.createTransaction(pidQuery(), 120);
        String requestObject = engine.getRequestObject(tx.getId());

        String vpToken = wallet.respondTo(requestObject, SimulatedWallet.Tamper.NONE);
        assertNotNull(vpToken);

        engine.processWalletResponse(tx.getId(), vpToken, wallet.lastState(), FORMAT);

        PresentationTransaction result = engine.pollAndConsumeIfTerminal(tx.getId());
        assertEquals(TransactionStatus.COMPLETED, result.getStatus());
        assertEquals("Marie", result.getPresentations().get(0).getClaims().get("given_name"));
        assertEquals(Boolean.TRUE, result.getPresentations().get(0).getClaims().get("age_over_18"));

        assertNull(engine.pollAndConsumeIfTerminal(tx.getId()), "second poll must consume the terminal transaction");
    }

    // ---- user denies (wallet-side error) ---------------------------------------

    @Test
    void userDeniesEndToEndFailsWithWalletError() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        PresentationEngine engine = newEngine(chain);
        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain));

        PresentationTransaction tx = engine.createTransaction(pidQuery(), 120);
        String requestObject = engine.getRequestObject(tx.getId());

        String vpToken = wallet.respondTo(requestObject, SimulatedWallet.Tamper.USER_DENIES);
        assertNull(vpToken, "USER_DENIES must return null instead of a vp_token");

        engine.failFromWallet(tx.getId(), "access_denied");

        PresentationTransaction result = engine.pollAndConsumeIfTerminal(tx.getId());
        assertEquals(TransactionStatus.FAILED, result.getStatus());
        assertEquals("WALLET_ERROR", result.getErrorCode());
    }

    // ---- adversarial modes, one negative test per Tamper (except NONE/USER_DENIES) --

    static Stream<Arguments> tamperModesExpectingVerificationFailure() {
        return Stream.of(
            Arguments.of(SimulatedWallet.Tamper.WRONG_NONCE, "INVALID_KEY_BINDING"),
            Arguments.of(SimulatedWallet.Tamper.WRONG_AUD, "INVALID_KEY_BINDING"),
            Arguments.of(SimulatedWallet.Tamper.REPLAY_OTHER_PRESENTATION, "INVALID_KEY_BINDING"),
            Arguments.of(SimulatedWallet.Tamper.FOREIGN_HOLDER_KEY, "INVALID_KEY_BINDING"),
            Arguments.of(SimulatedWallet.Tamper.TAMPERED_DISCLOSURE, "DISCLOSURE_MISMATCH")
        );
    }

    @ParameterizedTest(name = "{0} -> {1}")
    @MethodSource("tamperModesExpectingVerificationFailure")
    void tamperedResponseEndToEndFailsWithExpectedErrorCode(SimulatedWallet.Tamper tamper, String expectedErrorCode)
        throws Exception {
        TestTrustChain chain = new TestTrustChain();
        PresentationEngine engine = newEngine(chain);
        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain));

        PresentationTransaction tx = engine.createTransaction(pidQuery(), 120);
        String requestObject = engine.getRequestObject(tx.getId());

        String vpToken = wallet.respondTo(requestObject, tamper);
        assertNotNull(vpToken);

        engine.processWalletResponse(tx.getId(), vpToken, wallet.lastState(), FORMAT);

        PresentationTransaction result = engine.pollAndConsumeIfTerminal(tx.getId());
        assertEquals(TransactionStatus.FAILED, result.getStatus());
        assertEquals(expectedErrorCode, result.getErrorCode());
    }

    // ---- level 2 wiring: the unified two-set query, end to end ----------------

    @Test
    void bothCardsTraverseTheWholeStack() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        PresentationEngine engine = newEngine(chain);
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        SimulatedWallet wallet = new SimulatedWallet(issuer,
            Map.of("sub", "PID-1", "given_name", "Marie", "age_over_18", true));
        wallet.receive(OWN_VCT, issuer.issue(OWN_VCT, Map.of("sub", "FED-1"),
            wallet.holderKeyPair().getPublic(), NOW - 1000, NOW + 100_000));

        PresentationTransaction tx = engine.createTransaction(unifiedQuery(), 120);
        engine.processWalletResponse(tx.getId(),
            wallet.respondTo(engine.getRequestObject(tx.getId()), SimulatedWallet.Tamper.NONE),
            wallet.lastState(), FORMAT);

        PresentationTransaction result = engine.pollAndConsumeIfTerminal(tx.getId());
        assertEquals(TransactionStatus.COMPLETED, result.getStatus());
        assertEquals(List.of("urn:eudi:pid:1", OWN_VCT),
            result.getPresentations().stream().map(VerifiedPresentation::getVct).toList());
    }

    @Test
    void anExpiredCardIsDiscardedButThePidStillLogsIn() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        PresentationEngine engine = newEngine(chain);
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        SimulatedWallet wallet = new SimulatedWallet(issuer,
            Map.of("sub", "PID-2", "given_name", "Marie", "age_over_18", true));
        wallet.receive(OWN_VCT, issuer.issue(OWN_VCT, Map.of("sub", "FED-2"),
            wallet.holderKeyPair().getPublic(), NOW - 100_000, NOW - 10));   // expired

        PresentationTransaction tx = engine.createTransaction(unifiedQuery(), 120);
        engine.processWalletResponse(tx.getId(),
            wallet.respondTo(engine.getRequestObject(tx.getId()), SimulatedWallet.Tamper.NONE),
            wallet.lastState(), FORMAT);

        PresentationTransaction result = engine.pollAndConsumeIfTerminal(tx.getId());
        assertEquals(TransactionStatus.COMPLETED, result.getStatus());
        assertEquals(List.of("urn:eudi:pid:1"),
            result.getPresentations().stream().map(VerifiedPresentation::getVct).toList());
    }

    @Test
    void aMislabelledPresentationFailsTheWholeTransaction() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        PresentationEngine engine = newEngine(chain);
        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain));

        PresentationTransaction tx = engine.createTransaction(unifiedQuery(), 120);
        engine.processWalletResponse(tx.getId(),
            wallet.respondTo(engine.getRequestObject(tx.getId()),
                SimulatedWallet.Tamper.MISLABELLED_KEY),
            wallet.lastState(), FORMAT);

        PresentationTransaction result = engine.pollAndConsumeIfTerminal(tx.getId());
        assertEquals(TransactionStatus.FAILED, result.getStatus());
        assertEquals("QUERY_NOT_SATISFIED", result.getErrorCode(),
            "lying about the label must gain nothing: conformance is checked against the query "
                + "the key designates");
    }
}
