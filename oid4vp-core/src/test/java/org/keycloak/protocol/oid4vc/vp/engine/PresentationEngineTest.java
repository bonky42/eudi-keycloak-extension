package org.keycloak.protocol.oid4vc.vp.engine;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.model.DcqlQuery;
import org.keycloak.protocol.oid4vc.vp.model.PresentationTransaction;
import org.keycloak.protocol.oid4vc.vp.model.TransactionStatus;
import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;
import org.keycloak.protocol.oid4vc.vp.request.RequestObjectBuilder;
import org.keycloak.protocol.oid4vc.vp.store.SingleUseTransactionStore;
import org.keycloak.protocol.oid4vc.vp.testsupport.InMemorySingleUseObjects;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestJwe;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;
import org.keycloak.protocol.oid4vc.vp.trust.TrustPolicy;
import org.keycloak.protocol.oid4vc.vp.trust.TrustStore;
import org.keycloak.protocol.oid4vc.vp.verifier.PresentationRequestContext;
import org.keycloak.protocol.oid4vc.vp.verifier.VpErrorCode;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerificationException;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerifier;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Verifies {@link PresentationEngine}'s orchestration of the transaction
 * lifecycle: creation, Request Object issuance, wallet-response routing to
 * format verifiers, wallet-side error reporting, and single-use terminal
 * polling. Uses an in-memory {@link SingleUseTransactionStore}, a real
 * {@link RequestObjectBuilder} backed by a {@link TestTrustChain}, and
 * controllable stub {@link VpVerifier} implementations (fixed result /
 * thrown error code) rather than the real SD-JWT verifier.
 */
class PresentationEngineTest {

    private static final long NOW = 2_000_000_000L;
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC);
    private static final String CLIENT_ID = "test-client-app";
    private static final String RESPONSE_URI = "https://verifier.example.org/direct_post";
    private static final String FORMAT = "dc+sd-jwt";

    private static final String PID_VCT = "urn:eudi:pid:1";
    private static final String OWN_VCT = "urn:pn:account-holder:1";

    private static final String PID_QUERY_JSON = """
        {
          "credentials": [
            {
              "id": "pid",
              "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eudi:pid:1"] },
              "claims": [ { "path": ["given_name"] } ]
            }
          ]
        }""";

    /** The unified DCQL: one PID query and one for our own card, both {@code dc+sd-jwt}. */
    private static final String UNIFIED_QUERY_JSON = """
        {
          "credentials": [
            {
              "id": "pid",
              "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eudi:pid:1"] },
              "claims": [ { "path": ["given_name"] } ]
            },
            {
              "id": "own",
              "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:pn:account-holder:1"] },
              "claims": [ { "path": ["sub"] } ]
            }
          ]
        }""";

    private DcqlQuery pidQuery() {
        return DcqlQuery.fromJson(PID_QUERY_JSON);
    }

    private static VerifiedPresentation verified(String vct) {
        return new VerifiedPresentation(Map.of("sub", "S-1"), "https://issuer.example", "CN=ca",
            vct, 2_000_000_500L);
    }

    /** A two-argument stub verification, lighter to write as a lambda than an anonymous
     *  {@link VpVerifier}, which also carries {@code close()} and so is not a functional interface.
     *  {@link #engineWithVerifier} wraps it in a real one. */
    @FunctionalInterface
    private interface StubVerification {
        VerifiedPresentation verify(String presentation, PresentationRequestContext context)
            throws VpVerificationException;
    }

    /** Engine, transaction id and state for the multi-presentation tests; filled by
     *  {@link #engineWithVerifier}. */
    private PresentationEngine engine;
    private String txId;
    private String state;

    /** Rebuilds {@link #engine} with {@code verification} under {@link #FORMAT}, creates a
     *  transaction on the unified DCQL, and records {@link #txId} and {@link #state}. */
    private void engineWithVerifier(StubVerification verification) {
        VpVerifier verifier = new VpVerifier() {
            @Override
            public VerifiedPresentation verify(String vpToken, PresentationRequestContext context)
                throws VpVerificationException {
                return verification.verify(vpToken, context);
            }

            @Override
            public void close() {
            }
        };
        engine = newEngine(newStore(), Map.of(FORMAT, verifier));
        PresentationTransaction tx = engine.createTransaction(DcqlQuery.fromJson(UNIFIED_QUERY_JSON), 300);
        txId = tx.getId();
        state = tx.getState();
    }

    /**
     * The {@code response_uri} we publish must be the URL a wallet can actually POST to — the
     * per-transaction one, not the endpoint base.
     *
     * <p>Found by a real wallet on 2026-08-13, not by this suite: the integration tests build the
     * POST target themselves as {@code base + "/response/" + txId}, so they proved the handler
     * works while never checking the address we advertise. The official EUDI reference wallet can
     * only follow what we publish; it POSTed to the base, got HTTP 404, and reported that the
     * verifier had rejected its response. No verifier code ran at all, which is why nothing was
     * logged.
     */
    @Test
    void theAdvertisedResponseUriPointsAtTheTransactionsOwnEndpoint() throws Exception {
        PresentationEngine engine = newEngine(newStore(), Map.of());
        PresentationTransaction tx = engine.createTransaction(DcqlQuery.fromJson(PID_QUERY_JSON), 300);

        String requestObject = engine.getRequestObject(tx.getId());
        String payload = new String(Base64.getUrlDecoder().decode(requestObject.split("\\.", -1)[1]));

        assertTrue(payload.contains("\"response_uri\":\"" + RESPONSE_URI + "/response/" + tx.getId() + "\""),
            "a wallet can only POST where we tell it to; publishing the endpoint base instead of "
                + "the transaction's own response URL makes every real presentation 404. Payload was: "
                + payload);
    }

    private SingleUseTransactionStore newStore() {
        return new SingleUseTransactionStore(new InMemorySingleUseObjects());
    }

    private RequestObjectBuilder newRequestBuilder() {
        TestTrustChain chain = new TestTrustChain();
        return new RequestObjectBuilder(chain.issuerKeyPair, chain.issuerCert, CLOCK);
    }

    private PresentationEngine newEngine(SingleUseTransactionStore store, Map<String, VpVerifier> verifiers) {
        return new PresentationEngine(store, newRequestBuilder(), verifiers,
            TrustPolicy.acceptingAll(new TrustStore(List.of())), CLIENT_ID, RESPONSE_URI, CLOCK);
    }

    // ---- stub verifiers -------------------------------------------------

    private static final class FixedResultVerifier implements VpVerifier {
        private final VerifiedPresentation result;

        FixedResultVerifier(VerifiedPresentation result) {
            this.result = result;
        }

        @Override
        public VerifiedPresentation verify(String vpToken, PresentationRequestContext context) {
            return result;
        }

        @Override
        public void close() {
        }
    }

    private static final class ThrowingVerifier implements VpVerifier {
        private final VpErrorCode code;

        ThrowingVerifier(VpErrorCode code) {
            this.code = code;
        }

        @Override
        public VerifiedPresentation verify(String vpToken, PresentationRequestContext context)
            throws VpVerificationException {
            throw new VpVerificationException(code, "stub failure");
        }

        @Override
        public void close() {
        }
    }

    /** A verifier whose {@code verify} must never be invoked; used to prove that a guard clause
     *  short-circuits before routing to format verification. */
    private static final class UnreachableVerifier implements VpVerifier {
        @Override
        public VerifiedPresentation verify(String vpToken, PresentationRequestContext context) {
            throw new AssertionError("verifier must not be reached when the DCQL declares no credential query");
        }

        @Override
        public void close() {
        }
    }

    /** Captures the lifespan passed to the underlying single-use store's put(). */
    private static final class RecordingSingleUseObjects extends InMemorySingleUseObjects {
        long lastLifespanSeconds = -1;

        @Override
        public void put(String key, long lifespanSeconds, Map<String, String> notes) {
            this.lastLifespanSeconds = lifespanSeconds;
            super.put(key, lifespanSeconds, notes);
        }
    }

    // ---- createTransaction ------------------------------------------------

    @Test
    void createTransactionStoresPendingWithDistinctIdsAndPassesTtlToStore() {
        RecordingSingleUseObjects singleUse = new RecordingSingleUseObjects();
        SingleUseTransactionStore store = new SingleUseTransactionStore(singleUse);
        PresentationEngine engine = newEngine(store, Map.of());

        PresentationTransaction tx1 = engine.createTransaction(pidQuery(), 300);
        PresentationTransaction tx2 = engine.createTransaction(pidQuery(), 300);

        assertEquals(TransactionStatus.PENDING, tx1.getStatus());
        assertNotNull(tx1.getId());
        assertNotNull(tx1.getNonce());
        assertNotNull(tx1.getState());

        assertNotEquals(tx1.getId(), tx2.getId());
        assertNotEquals(tx1.getNonce(), tx2.getNonce());
        assertNotEquals(tx1.getState(), tx2.getState());

        assertEquals(300L, singleUse.lastLifespanSeconds);
    }

    // ---- getRequestObject ---------------------------------------------------

    @Test
    void getRequestObjectOnUnknownIdThrowsTransactionNotFound() {
        PresentationEngine engine = newEngine(newStore(), Map.of());

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> engine.getRequestObject("nope"));
        assertEquals(VpErrorCode.TRANSACTION_NOT_FOUND, ex.getCode());
    }

    @Test
    void getRequestObjectOnTransactionMissingEncryptionKeyFailsClosedAndTyped() {
        SingleUseTransactionStore store = newStore();
        PresentationEngine engine = newEngine(store, Map.of());

        // Simulates a transaction minted by a node predating the response-encryption feature:
        // present, PENDING, but with no responseEnc* fields — put directly in the store rather
        // than via createTransaction, which always mints the key.
        PresentationTransaction tx = new PresentationTransaction();
        tx.setId("tx-no-enc-key");
        tx.setNonce("nonce");
        tx.setState("state");
        tx.setDcqlQueryJson(PID_QUERY_JSON);
        tx.setStatus(TransactionStatus.PENDING);
        tx.setCreatedAt(NOW);
        store.put(tx, 300);

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> engine.getRequestObject("tx-no-enc-key"));
        assertEquals(VpErrorCode.TRANSACTION_MISSING_ENCRYPTION_KEY, ex.getCode(),
            "a transaction with no response-encryption key must fail closed with a typed code, "
                + "never an unchecked exception");
    }

    @Test
    void getRequestObjectOnRealTransactionReturnsSignedJwt() throws Exception {
        PresentationEngine engine = newEngine(newStore(), Map.of());
        PresentationTransaction tx = engine.createTransaction(pidQuery(), 300);

        String jwt = engine.getRequestObject(tx.getId());

        assertNotNull(jwt);
        assertEquals(3, jwt.split("\\.", -1).length);
    }

    // ---- processWalletResponse -----------------------------------------------

    @Test
    void processWalletResponseHappyPathCompletesWithClaims() {
        SingleUseTransactionStore store = newStore();
        VpVerifier verifier = new FixedResultVerifier(
            new VerifiedPresentation(Map.of("given_name", "Alice"), "issuer", "anchor", "urn:eudi:pid:1"));
        PresentationEngine engine = newEngine(store, Map.of(FORMAT, verifier));

        PresentationTransaction tx = engine.createTransaction(pidQuery(), 300);
        engine.processWalletResponse(tx.getId(), "{\"pid\":[\"dummy-vp-token\"]}", tx.getState(), FORMAT);

        PresentationTransaction stored = store.get(tx.getId());
        assertEquals(TransactionStatus.COMPLETED, stored.getStatus());
        assertEquals("Alice", stored.getPresentations().get(0).getClaims().get("given_name"));
    }

    @Test
    void processWalletResponseHappyPathPersistsIssuerVctAndTrustAnchor() {
        SingleUseTransactionStore store = newStore();
        VpVerifier verifier = new FixedResultVerifier(
            new VerifiedPresentation(Map.of("given_name", "Alice"),
                "https://issuer.example.org", "did:example:trust-anchor", "urn:eudi:pid:1"));
        PresentationEngine engine = newEngine(store, Map.of(FORMAT, verifier));

        PresentationTransaction tx = engine.createTransaction(pidQuery(), 300);
        engine.processWalletResponse(tx.getId(), "{\"pid\":[\"dummy-vp-token\"]}", tx.getState(), FORMAT);

        PresentationTransaction stored = store.get(tx.getId());
        assertEquals(TransactionStatus.COMPLETED, stored.getStatus());
        VerifiedPresentation vp = stored.getPresentations().get(0);
        assertEquals("https://issuer.example.org", vp.getIssuer());
        assertEquals("urn:eudi:pid:1", vp.getVct());
        assertEquals("did:example:trust-anchor", vp.getTrustAnchorSubject());
    }

    @Test
    void processWalletResponseWithWrongStateFailsWithParsingError() {
        SingleUseTransactionStore store = newStore();
        PresentationEngine engine = newEngine(store, Map.of());
        PresentationTransaction tx = engine.createTransaction(pidQuery(), 300);

        engine.processWalletResponse(tx.getId(), "dummy-vp-token", "totally-wrong-state", FORMAT);

        PresentationTransaction stored = store.get(tx.getId());
        assertEquals(TransactionStatus.FAILED, stored.getStatus());
        assertEquals(VpErrorCode.PARSING_ERROR.name(), stored.getErrorCode());
    }

    @Test
    void processWalletResponseWithUnknownFormatFails() {
        SingleUseTransactionStore store = newStore();
        PresentationEngine engine = newEngine(store, Map.of()); // no verifier registered for FORMAT
        PresentationTransaction tx = engine.createTransaction(pidQuery(), 300);

        engine.processWalletResponse(tx.getId(), "dummy-vp-token", tx.getState(), FORMAT);

        PresentationTransaction stored = store.get(tx.getId());
        assertEquals(TransactionStatus.FAILED, stored.getStatus());
        assertEquals(VpErrorCode.PARSING_ERROR.name(), stored.getErrorCode());
    }

    @Test
    void processWalletResponseWithEmptyCredentialQueryListFailsGracefullyInsteadOfThrowing() {
        // Regression pin: the concern here was designating the credential query by indexing into
        // getCredentials(); that indexing is now gone
        // entirely, deriving the query id from each vp_token response key instead, so it can no
        // longer crash on an empty/null credentials list. To actually EXERCISE that empty list
        // (rather than being short-circuited earlier by a non-JSON vp_token, which would make this
        // pass identically for any DCQL), the vp_token here is a syntactically valid envelope: its
        // key 'pid' is looked up via DcqlQuery.credentialById against the empty `credentials`
        // array, which correctly returns null (no crash) — VpTokenResponse.parse then refuses the
        // undeclared key with UNKNOWN_RESPONSE_KEY, gracefully and without ever reaching the
        // verifier. The invariant this test protects is unchanged: this must never throw out of
        // processWalletResponse, and the verifier must never be reached.
        SingleUseTransactionStore store = newStore();
        PresentationEngine engine = newEngine(store, Map.of(FORMAT, new UnreachableVerifier()));
        PresentationTransaction tx = engine.createTransaction(DcqlQuery.fromJson("""
            {"credentials":[]}"""), 300);

        engine.processWalletResponse(tx.getId(), "{\"pid\":[\"x\"]}", tx.getState(), FORMAT);

        PresentationTransaction stored = store.get(tx.getId());
        assertEquals(TransactionStatus.FAILED, stored.getStatus());
        assertEquals(VpErrorCode.UNKNOWN_RESPONSE_KEY.name(), stored.getErrorCode());
    }

    @Test
    void processWalletResponseWhenVerifierThrowsMarksFailedWithMatchingErrorCode() {
        SingleUseTransactionStore store = newStore();
        VpVerifier verifier = new ThrowingVerifier(VpErrorCode.UNTRUSTED_ISSUER);
        PresentationEngine engine = newEngine(store, Map.of(FORMAT, verifier));
        PresentationTransaction tx = engine.createTransaction(pidQuery(), 300);

        engine.processWalletResponse(tx.getId(), "{\"pid\":[\"dummy-vp-token\"]}", tx.getState(), FORMAT);

        PresentationTransaction stored = store.get(tx.getId());
        assertEquals(TransactionStatus.FAILED, stored.getStatus());
        assertEquals("UNTRUSTED_ISSUER", stored.getErrorCode());
    }

    @Test
    void secondProcessWalletResponseOnCompletedTransactionIsNoOp() {
        SingleUseTransactionStore store = newStore();
        VpVerifier verifier = new FixedResultVerifier(
            new VerifiedPresentation(Map.of("given_name", "Alice"), "issuer", "anchor", "urn:eudi:pid:1"));
        PresentationEngine engine = newEngine(store, Map.of(FORMAT, verifier));
        PresentationTransaction tx = engine.createTransaction(pidQuery(), 300);

        engine.processWalletResponse(tx.getId(), "{\"pid\":[\"dummy-vp-token\"]}", tx.getState(), FORMAT);
        assertEquals(TransactionStatus.COMPLETED, store.get(tx.getId()).getStatus());

        // Second call, even with garbage state/format, must not change an already-terminal tx.
        engine.processWalletResponse(tx.getId(), "other-vp-token", "garbage-state", "unknown-format");

        PresentationTransaction stored = store.get(tx.getId());
        assertEquals(TransactionStatus.COMPLETED, stored.getStatus());
        assertEquals("Alice", stored.getPresentations().get(0).getClaims().get("given_name"));
    }

    // ---- processWalletResponse: many presentations, two failure regimes ----------

    @Test
    void twoVerifiedPresentationsAreBothKept() {
        // stub verifier: the vct returned depends on the designated key
        engineWithVerifier((presentation, context) ->
            verified(context.getCredentialQueryId().equals("own") ? OWN_VCT : PID_VCT));

        engine.processWalletResponse(txId, "{\"pid\":[\"a~kb\"],\"own\":[\"b~kb\"]}", state, FORMAT);

        PresentationTransaction result = engine.pollAndConsumeIfTerminal(txId);
        assertEquals(TransactionStatus.COMPLETED, result.getStatus());
        assertEquals(List.of(PID_VCT, OWN_VCT),
            result.getPresentations().stream().map(VerifiedPresentation::getVct).toList());
    }

    @Test
    void anExpiredPresentationIsDiscardedAndTheOthersProceed() {
        engineWithVerifier((presentation, context) -> {
            if (context.getCredentialQueryId().equals("own")) {
                throw new VpVerificationException(VpErrorCode.CREDENTIAL_EXPIRED, "card expired");
            }
            return verified(PID_VCT);
        });

        engine.processWalletResponse(txId, "{\"pid\":[\"a~kb\"],\"own\":[\"b~kb\"]}", state, FORMAT);

        PresentationTransaction result = engine.pollAndConsumeIfTerminal(txId);
        assertEquals(TransactionStatus.COMPLETED, result.getStatus(),
            "expiry is an expected lifecycle event: it is PRECISELY the case renewal must serve, "
                + "and must not cost the login");
        assertEquals(List.of(PID_VCT),
            result.getPresentations().stream().map(VerifiedPresentation::getVct).toList());
    }

    @Test
    void anyOtherVerificationFailureKillsTheWholeTransaction() {
        engineWithVerifier((presentation, context) -> {
            if (context.getCredentialQueryId().equals("own")) {
                throw new VpVerificationException(VpErrorCode.INVALID_SIGNATURE, "forgery");
            }
            return verified(PID_VCT);
        });

        engine.processWalletResponse(txId, "{\"pid\":[\"a~kb\"],\"own\":[\"b~kb\"]}", state, FORMAT);

        PresentationTransaction result = engine.pollAndConsumeIfTerminal(txId);
        assertEquals(TransactionStatus.FAILED, result.getStatus(),
            "accepting the rest of a response containing a forgery would mean ignoring what we "
                + "did not understand");
        assertEquals("INVALID_SIGNATURE", result.getErrorCode());
        assertNull(result.getPresentations(),
            "the 'pid' presentation, verified before the 'own' forgery, must NOT survive on the "
                + "transaction: a FAILED must never carry a partial acceptance of the response");
    }

    @Test
    void everythingExpiredFailsAsExpired() {
        engineWithVerifier((presentation, context) -> {
            throw new VpVerificationException(VpErrorCode.CREDENTIAL_EXPIRED, "expired");
        });

        engine.processWalletResponse(txId, "{\"own\":[\"b~kb\"]}", state, FORMAT);

        assertEquals("CREDENTIAL_EXPIRED", engine.pollAndConsumeIfTerminal(txId).getErrorCode());
    }

    @Test
    void anEmptyVpTokenFailsAsUnsatisfied() {
        engineWithVerifier((presentation, context) -> verified(PID_VCT));

        engine.processWalletResponse(txId, "{}", state, FORMAT);

        PresentationTransaction result = engine.pollAndConsumeIfTerminal(txId);
        assertEquals(TransactionStatus.FAILED, result.getStatus());
        assertEquals("QUERY_NOT_SATISFIED", result.getErrorCode(),
            "a wallet that returns nothing cannot authenticate");
    }

    @Test
    void anUnknownKeyFailsTheTransaction() {
        engineWithVerifier((presentation, context) -> verified(PID_VCT));

        engine.processWalletResponse(txId, "{\"inconnue\":[\"a~kb\"]}", state, FORMAT);

        assertEquals("UNKNOWN_RESPONSE_KEY", engine.pollAndConsumeIfTerminal(txId).getErrorCode());
    }

    // ---- pollAndConsumeIfTerminal -----------------------------------------------

    @Test
    void pollDoesNotConsumePendingButConsumesTerminal() {
        SingleUseTransactionStore store = newStore();
        VpVerifier verifier = new FixedResultVerifier(
            new VerifiedPresentation(Map.of("given_name", "Alice"), "issuer", "anchor", "urn:eudi:pid:1"));
        PresentationEngine engine = newEngine(store, Map.of(FORMAT, verifier));
        PresentationTransaction tx = engine.createTransaction(pidQuery(), 300);

        PresentationTransaction poll1 = engine.pollAndConsumeIfTerminal(tx.getId());
        assertEquals(TransactionStatus.PENDING, poll1.getStatus());
        PresentationTransaction poll2 = engine.pollAndConsumeIfTerminal(tx.getId());
        assertEquals(TransactionStatus.PENDING, poll2.getStatus()); // still there, not consumed

        engine.processWalletResponse(tx.getId(), "{\"pid\":[\"dummy-vp-token\"]}", tx.getState(), FORMAT);

        PresentationTransaction poll3 = engine.pollAndConsumeIfTerminal(tx.getId());
        assertEquals(TransactionStatus.COMPLETED, poll3.getStatus());
        assertEquals("Alice", poll3.getPresentations().get(0).getClaims().get("given_name"));

        assertNull(engine.pollAndConsumeIfTerminal(tx.getId()), "second poll after terminal must consume");
    }

    // ---- peek ---------------------------------------------------------------

    @Test
    void peekReturnsNullForUnknownTransaction() {
        PresentationEngine engine = newEngine(newStore(), Map.of());

        assertNull(engine.peek("nope"));
    }

    @Test
    void peekDoesNotConsumePendingTransaction() {
        SingleUseTransactionStore store = newStore();
        PresentationEngine engine = newEngine(store, Map.of());
        PresentationTransaction tx = engine.createTransaction(pidQuery(), 300);

        PresentationTransaction peek1 = engine.peek(tx.getId());
        assertEquals(TransactionStatus.PENDING, peek1.getStatus());
        PresentationTransaction peek2 = engine.peek(tx.getId());
        assertEquals(TransactionStatus.PENDING, peek2.getStatus());

        // still readable via the normal store accessor: peek truly never consumed it.
        assertNotNull(store.get(tx.getId()));
    }

    @Test
    void peekDoesNotConsumeTerminalTransaction() {
        SingleUseTransactionStore store = newStore();
        VpVerifier verifier = new FixedResultVerifier(
            new VerifiedPresentation(Map.of("given_name", "Alice"), "issuer", "anchor", "urn:eudi:pid:1"));
        PresentationEngine engine = newEngine(store, Map.of(FORMAT, verifier));
        PresentationTransaction tx = engine.createTransaction(pidQuery(), 300);
        engine.processWalletResponse(tx.getId(), "{\"pid\":[\"dummy-vp-token\"]}", tx.getState(), FORMAT);

        PresentationTransaction peek1 = engine.peek(tx.getId());
        assertEquals(TransactionStatus.COMPLETED, peek1.getStatus());
        PresentationTransaction peek2 = engine.peek(tx.getId());
        assertEquals(TransactionStatus.COMPLETED, peek2.getStatus());
        assertEquals("Alice", peek2.getPresentations().get(0).getClaims().get("given_name"));

        // pollAndConsumeIfTerminal can still consume it afterwards: peek left it intact.
        PresentationTransaction polled = engine.pollAndConsumeIfTerminal(tx.getId());
        assertEquals(TransactionStatus.COMPLETED, polled.getStatus());
        assertNull(engine.pollAndConsumeIfTerminal(tx.getId()), "consumption still happens exactly once, via poll");
    }

    // ---- failFromWallet ---------------------------------------------------------

    @Test
    void failFromWalletMarksFailedWithWalletErrorReadableOnce() {
        SingleUseTransactionStore store = newStore();
        PresentationEngine engine = newEngine(store, Map.of());
        PresentationTransaction tx = engine.createTransaction(pidQuery(), 300);

        engine.failFromWallet(tx.getId(), "access_denied");

        PresentationTransaction stored = store.get(tx.getId());
        assertEquals(TransactionStatus.FAILED, stored.getStatus());
        assertEquals("WALLET_ERROR", stored.getErrorCode());

        PresentationTransaction polled = engine.pollAndConsumeIfTerminal(tx.getId());
        assertEquals("WALLET_ERROR", polled.getErrorCode());
        assertNull(engine.pollAndConsumeIfTerminal(tx.getId()), "second poll must consume the failed tx");
    }

    // ---- response encryption key -------------------------------------------------

    @Test
    void everyTransactionGetsItsOwnEncryptionKey() {
        PresentationEngine engine = newEngine(newStore(), Map.of());

        PresentationTransaction first = engine.createTransaction(DcqlQuery.fromJson(PID_QUERY_JSON), 300);
        PresentationTransaction second = engine.createTransaction(DcqlQuery.fromJson(PID_QUERY_JSON), 300);

        assertNotNull(first.getResponseEncPrivateKey());
        assertNotEquals(first.getResponseEncKid(), second.getResponseEncKid(),
            "the profile requires an ephemeral key specific to each Authorization Request; "
                + "sharing one across transactions would let a single compromise open every "
                + "past response");
        assertNotEquals(first.getResponseEncPrivateKey(), second.getResponseEncPrivateKey());
    }

    @Test
    void theEncryptionKeySurvivesStorageAndRetrieval() {
        PresentationEngine engine = newEngine(newStore(), Map.of());
        PresentationTransaction created = engine.createTransaction(DcqlQuery.fromJson(PID_QUERY_JSON), 300);

        PresentationTransaction reloaded = engine.peek(created.getId());

        assertEquals(created.getResponseEncKid(), reloaded.getResponseEncKid());
        assertEquals(created.responseEncryptionKey().privateKey(),
            reloaded.responseEncryptionKey().privateKey());
    }

    // ---- processEncryptedWalletResponse -------------------------------------------------

    @Test
    void aClearTextVpTokenIsRefused() {
        PresentationEngine engine = newEngine(newStore(), Map.of());
        PresentationTransaction tx = engine.createTransaction(DcqlQuery.fromJson(PID_QUERY_JSON), 300);

        engine.processEncryptedWalletResponse(tx.getId(), "{\"vp_token\":{}}", "dc+sd-jwt");

        PresentationTransaction after = engine.peek(tx.getId());
        assertEquals(TransactionStatus.FAILED, after.getStatus());
        assertEquals(VpErrorCode.RESPONSE_DECRYPTION_FAILED.name(), after.getErrorCode(),
            "the switch to direct_post.jwt is hard: a clear-text post must not be a way around it");
    }

    @Test
    void aResponseSealedToAnotherKeyIsRefused() throws Exception {
        PresentationEngine engine = newEngine(newStore(), Map.of());
        PresentationTransaction mine = engine.createTransaction(DcqlQuery.fromJson(PID_QUERY_JSON), 300);
        PresentationTransaction other = engine.createTransaction(DcqlQuery.fromJson(PID_QUERY_JSON), 300);

        // sealed for `other`, posted to `mine`
        String jwe = TestJwe.seal(other.responseEncryptionKey().publicJwk(), "A256GCM",
            "{\"vp_token\":{},\"state\":\"" + mine.getState() + "\"}");

        engine.processEncryptedWalletResponse(mine.getId(), jwe, "dc+sd-jwt");

        assertEquals(VpErrorCode.RESPONSE_DECRYPTION_FAILED.name(),
            engine.peek(mine.getId()).getErrorCode());
    }

    @Test
    void aGarbageResponsePostedAfterCompletionDoesNotFlipTheTransactionToFailed() {
        // Regression pin: processEncryptedWalletResponse used to be missing the entry guard its
        // siblings (processWalletResponse, failFromWallet) both have. Without it, a second POST
        // carrying an undecryptable body — arriving after the transaction already went COMPLETED,
        // but before the browser consumes it via complete/{tx} — would reach failTransaction and
        // turn a successful login into a FAILED one. The tx id is observable (it's in the
        // request_uri carried by the QR), so this is reachable by more than an on-path attacker.
        SingleUseTransactionStore store = newStore();
        VpVerifier verifier = new FixedResultVerifier(
            new VerifiedPresentation(Map.of("given_name", "Alice"), "issuer", "anchor", "urn:eudi:pid:1"));
        PresentationEngine engine = newEngine(store, Map.of(FORMAT, verifier));
        PresentationTransaction tx = engine.createTransaction(pidQuery(), 300);

        engine.processWalletResponse(tx.getId(), "{\"pid\":[\"dummy-vp-token\"]}", tx.getState(), FORMAT);
        assertEquals(TransactionStatus.COMPLETED, store.get(tx.getId()).getStatus());

        engine.processEncryptedWalletResponse(tx.getId(), "not-a-jwe", FORMAT);

        PresentationTransaction after = store.get(tx.getId());
        assertEquals(TransactionStatus.COMPLETED, after.getStatus(),
            "a second, undecryptable POST to an already-COMPLETED transaction must never flip a "
                + "successful login to FAILED");
        assertNull(after.getErrorCode(), "errorCode must remain unset on the completed transaction");
        assertEquals("Alice", after.getPresentations().get(0).getClaims().get("given_name"),
            "the claims from the successful completion must survive untouched");
    }

    @Test
    void aTransactionMissingEncryptionKeyFailsClosedWhenProcessingAnEncryptedResponse() {
        // Mirrors getRequestObjectOnTransactionMissingEncryptionKeyFailsClosedAndTyped: a
        // transaction minted by a node predating the response-encryption feature is present and
        // PENDING (so it clears the entry guard above), but carries no responseEnc* fields.
        // responseEncryptionKey() would throw an unchecked IllegalStateException if called on it,
        // so this must be caught before that call, not left to crash the wallet-facing endpoint.
        SingleUseTransactionStore store = newStore();
        PresentationEngine engine = newEngine(store, Map.of());

        PresentationTransaction tx = new PresentationTransaction();
        tx.setId("tx-no-enc-key");
        tx.setNonce("nonce");
        tx.setState("state");
        tx.setDcqlQueryJson(PID_QUERY_JSON);
        tx.setStatus(TransactionStatus.PENDING);
        tx.setCreatedAt(NOW);
        store.put(tx, 300);

        engine.processEncryptedWalletResponse("tx-no-enc-key", "irrelevant", "dc+sd-jwt");

        PresentationTransaction after = store.get("tx-no-enc-key");
        assertEquals(TransactionStatus.FAILED, after.getStatus());
        assertEquals(VpErrorCode.TRANSACTION_MISSING_ENCRYPTION_KEY.name(), after.getErrorCode(),
            "a transaction with no response-encryption key must fail closed with a typed code, "
                + "never an unchecked exception escaping the wallet-facing endpoint");
    }

    @Test
    void corruptEncryptionKeyMaterialFailsClosedInsteadOfThrowingUnchecked() {
        // Unlike aTransactionMissingEncryptionKeyFailsClosedWhenProcessingAnEncryptedResponse
        // above (responseEnc* fields absent), this transaction HAS non-null responseEnc* fields,
        // but they are not valid key material (e.g. store corruption). tx.responseEncryptionKey()
        // is called inside processEncryptedWalletResponse's try block; ResponseEncryptionKey.restore
        // wraps the resulting JCA failure in an unchecked IllegalStateException, which must not
        // escape onto the wallet-facing HTTP thread as an unhandled 500.
        SingleUseTransactionStore store = newStore();
        PresentationEngine engine = newEngine(store, Map.of());

        PresentationTransaction tx = new PresentationTransaction();
        tx.setId("tx-corrupt-enc-key");
        tx.setNonce("nonce");
        tx.setState("state");
        tx.setDcqlQueryJson(PID_QUERY_JSON);
        tx.setStatus(TransactionStatus.PENDING);
        tx.setCreatedAt(NOW);
        tx.setResponseEncKid("kid");
        // valid base64, but not a PKCS8/X509-encoded EC key: KeyFactory rejects it.
        String garbage = Base64.getEncoder().encodeToString("not a real DER-encoded key".getBytes());
        tx.setResponseEncPrivateKey(garbage);
        tx.setResponseEncPublicKey(garbage);
        store.put(tx, 300);

        engine.processEncryptedWalletResponse("tx-corrupt-enc-key", "irrelevant", "dc+sd-jwt");

        PresentationTransaction after = store.get("tx-corrupt-enc-key");
        assertEquals(TransactionStatus.FAILED, after.getStatus());
        assertEquals(VpErrorCode.RESPONSE_DECRYPTION_FAILED.name(), after.getErrorCode(),
            "corrupt (non-null but malformed) key material must fail closed with a typed code, "
                + "never an unchecked IllegalStateException escaping the wallet-facing endpoint");
    }

    @Test
    void anErrorInsideTheDecryptedBodyRoutesToWalletError() {
        // processEncryptedWalletResponse routes a decrypted `error` member to failFromWallet
        // (WALLET_ERROR), the same as the clear-text `error` form parameter handled by
        // Oid4vpEndpoints. Previously untested: this pins that the encrypted path does the same.
        PresentationEngine engine = newEngine(newStore(), Map.of());
        PresentationTransaction tx = engine.createTransaction(DcqlQuery.fromJson(PID_QUERY_JSON), 300);

        String sealed = TestJwe.seal(tx.responseEncryptionKey().publicJwk(), "A256GCM",
            "{\"error\":\"access_denied\",\"state\":\"" + tx.getState() + "\"}");

        engine.processEncryptedWalletResponse(tx.getId(), sealed, "dc+sd-jwt");

        PresentationTransaction after = engine.peek(tx.getId());
        assertEquals(TransactionStatus.FAILED, after.getStatus());
        assertEquals(VpErrorCode.WALLET_ERROR.name(), after.getErrorCode(),
            "a decrypted body carrying `error` must be routed to failFromWallet (WALLET_ERROR), "
                + "not treated as an ordinary vp_token");
    }
}
