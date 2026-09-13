package org.keycloak.protocol.oid4vc.vp.login.admin;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Oid4vpAdminResourceProviderFactoryTest {

    private static final String SERVICES_RESOURCE =
        "META-INF/services/org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory";

    /**
     * The id is the path segment: this factory answers under
     * {@code /admin/realms/{realm}/oid4vp/...}. Renaming it moves the endpoint.
     */
    @Test
    void theIdIsThePathSegmentTheConsoleWillCall() {
        assertEquals("oid4vp", new Oid4vpAdminResourceProviderFactory().getId());
    }

    @Test
    void itServesTheSigningCertificateResource() {
        Object resource = new Oid4vpAdminResourceProviderFactory()
            .create(null)
            .getResource(null, null, null, null);

        assertTrue(resource instanceof SigningCertificateResource,
            "the admin extension must expose the certificate summary, got: " + resource);
    }

    @Test
    void theFactoryIsRegisteredUnderTheAdminExtensionSpi() throws Exception {
        Enumeration<URL> resources =
            Thread.currentThread().getContextClassLoader().getResources(SERVICES_RESOURCE);
        boolean found = false;
        while (resources.hasMoreElements()) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                resources.nextElement().openStream(), StandardCharsets.UTF_8))) {
                found |= reader.lines().anyMatch(line ->
                    line.trim().equals(Oid4vpAdminResourceProviderFactory.class.getName()));
            }
        }
        assertTrue(found, "without this line the endpoint answers 404 and nothing says why: "
            + SERVICES_RESOURCE);
    }
}
