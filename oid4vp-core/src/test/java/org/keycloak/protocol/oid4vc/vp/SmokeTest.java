package org.keycloak.protocol.oid4vc.vp;

import org.junit.jupiter.api.Test;
import org.keycloak.jose.jws.JWSInput;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class SmokeTest {
    @Test
    void keycloakCoreOnClasspath() {
        assertNotNull(JWSInput.class.getName());
    }
}
