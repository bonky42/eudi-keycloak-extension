package org.keycloak.protocol.oid4vc.vp.login.endpoints;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.verifier.VpErrorCode;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit-tests the one piece of pure logic in {@link Oid4vpEndpoints}: the mapping from
 * {@link VpErrorCode} to HTTP status used by {@code request/{tx}}. The rest of the resource
 * is a thin JAX-RS adapter over {@link org.keycloak.protocol.oid4vc.vp.engine.PresentationEngine}
 * and is exercised over real HTTP by the Testcontainers end-to-end tests rather
 * than by a mock-heavy unit test here — see the class Javadoc for the rationale.
 */
class Oid4vpEndpointsTest {

    @Test
    void transactionNotFoundMapsToNotFound() {
        assertEquals(Response.Status.NOT_FOUND, Oid4vpEndpoints.statusFor(VpErrorCode.TRANSACTION_NOT_FOUND));
    }

    @Test
    void anyOtherCodeMapsToInternalServerError() {
        for (VpErrorCode code : VpErrorCode.values()) {
            if (code == VpErrorCode.TRANSACTION_NOT_FOUND) {
                continue;
            }
            assertEquals(Response.Status.INTERNAL_SERVER_ERROR, Oid4vpEndpoints.statusFor(code),
                "unexpected mapping for " + code);
        }
    }
}
