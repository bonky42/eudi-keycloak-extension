package org.keycloak.protocol.oid4vc.vp.login.protocol;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.model.PresentationTransaction;
import org.keycloak.protocol.oid4vc.vp.model.TransactionStatus;
import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class StatusDtoTest {

    @Test
    void ofNullTransactionReturnsExpired() {
        StatusDto dto = StatusDto.of(null);
        assertEquals("expired", dto.status);
    }

    @Test
    void ofPendingTransactionReturnsPending() {
        PresentationTransaction tx = new PresentationTransaction();
        tx.setStatus(TransactionStatus.PENDING);
        StatusDto dto = StatusDto.of(tx);
        assertEquals("pending", dto.status);
    }

    @Test
    void ofCompletedTransactionReturnsCompleted() {
        PresentationTransaction tx = new PresentationTransaction();
        tx.setStatus(TransactionStatus.COMPLETED);
        tx.setPresentations(List.of(new VerifiedPresentation(Map.of("claim", "value"),
            "https://issuer.example", "CN=ca", "urn:eudi:pid:1", 2_000_000_500L)));
        tx.setErrorCode("some_error");
        StatusDto dto = StatusDto.of(tx);
        assertEquals("completed", dto.status);
    }

    @Test
    void ofFailedTransactionReturnsFailed() {
        PresentationTransaction tx = new PresentationTransaction();
        tx.setStatus(TransactionStatus.FAILED);
        tx.setErrorCode("invalid_request");
        StatusDto dto = StatusDto.of(tx);
        assertEquals("failed", dto.status);
    }

    @Test
    void ofExpiredTransactionReturnsExpired() {
        PresentationTransaction tx = new PresentationTransaction();
        tx.setStatus(TransactionStatus.EXPIRED);
        StatusDto dto = StatusDto.of(tx);
        assertEquals("expired", dto.status);
    }

    @Test
    void toJsonContainsOnlyStatus() {
        StatusDto dto = new StatusDto("pending");
        String json = dto.toJson();

        assertTrue(json.contains("\"status\""), "JSON should contain status field");
        assertTrue(json.contains("pending"), "JSON should contain pending value");
        assertFalse(json.contains("claims"), "JSON should NOT contain claims field");
        assertFalse(json.contains("error"), "JSON should NOT contain error field");
    }

    @Test
    void toJsonForCompletedWithClaimsExcludesClaimsAndError() {
        // The payload has to be real: it is precisely what the test checks does NOT leak. Without
        // it, the assertions below would hold for any StatusDto.of, including one filtering
        // nothing.
        PresentationTransaction tx = new PresentationTransaction();
        tx.setStatus(TransactionStatus.COMPLETED);
        tx.setPresentations(List.of(new VerifiedPresentation(Map.of("sub", "user123"),
            "https://issuer.example", "CN=ca", "urn:eudi:pid:1", 2_000_000_500L)));
        tx.setErrorCode("some_code");

        StatusDto dto = StatusDto.of(tx);
        String json = dto.toJson();

        assertTrue(json.contains("\"status\""), "JSON should contain status field");
        assertTrue(json.contains("completed"), "JSON should contain completed value");
        assertFalse(json.contains("claims"), "JSON should NOT contain claims");
        assertFalse(json.contains("error"), "JSON should NOT contain error");
        assertFalse(json.contains("verified"), "JSON should NOT contain verifiedClaims");
        // Checks leakage at the VALUE level, not the field name: even if StatusDto one day exposed
        // this claim under a name containing neither "claims" nor "verified", its value must appear
        // nowhere.
        assertFalse(json.contains("user123"), "JSON should NOT leak the transaction's verified claim value");
    }

    @Test
    void roundTripJsonSerialization() {
        StatusDto original = new StatusDto("failed");
        String json = original.toJson();
        StatusDto restored = StatusDto.fromJson(json);

        assertEquals(original.status, restored.status);
    }
}
