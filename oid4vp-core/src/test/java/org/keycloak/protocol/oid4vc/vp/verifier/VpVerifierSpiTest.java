package org.keycloak.protocol.oid4vc.vp.verifier;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VpVerifierSpiTest {

    @Test
    void spiExposesExpectedNameAndProviderClass() {
        VpVerifierSpi spi = new VpVerifierSpi();
        assertEquals("oid4vp-verifier", spi.getName());
        assertEquals(VpVerifier.class, spi.getProviderClass());
        assertEquals(VpVerifierFactory.class, spi.getProviderFactoryClass());
        assertEquals(false, spi.isInternal());
    }

    @Test
    void verificationExceptionCarriesItsErrorCode() {
        VpVerificationException ex = new VpVerificationException(VpErrorCode.PARSING_ERROR, "x");
        assertEquals(VpErrorCode.PARSING_ERROR, ex.getCode());
        assertEquals("x", ex.getMessage());
    }

    @Test
    void servicesFileDeclaresVpVerifierSpi() throws IOException {
        InputStream in = getClass().getResourceAsStream("/META-INF/services/org.keycloak.provider.Spi");
        assertNotNull(in, "META-INF/services/org.keycloak.provider.Spi must be on the classpath");
        String content;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            content = reader.lines().collect(Collectors.joining("\n"));
        }
        assertTrue(content.contains("org.keycloak.protocol.oid4vc.vp.verifier.VpVerifierSpi"),
            "services file must declare VpVerifierSpi, was: " + content);
    }
}
