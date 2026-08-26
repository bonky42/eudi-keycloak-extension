package org.keycloak.protocol.oid4vc.vp.login.it;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.net.http.*;
import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
class KeycloakContainerSmokeIT {

    @Container
    static final GenericContainer<?> KC = new GenericContainer<>(
            DockerImageName.parse("quay.io/keycloak/keycloak:26.7.2"))
        .withExposedPorts(8080)
        .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
        .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
        .withCommand("start-dev")
        .waitingFor(Wait.forHttp("/realms/master").forPort(8080).forStatusCode(200));

    @Test
    void keycloakStartsAndServesMasterRealm() throws Exception {
        String base = "http://" + KC.getHost() + ":" + KC.getMappedPort(8080);
        HttpResponse<String> r = HttpClient.newHttpClient().send(
            HttpRequest.newBuilder(URI.create(base + "/realms/master")).build(),
            HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode());
    }
}
