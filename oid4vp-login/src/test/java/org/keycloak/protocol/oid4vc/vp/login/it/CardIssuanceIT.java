package org.keycloak.protocol.oid4vc.vp.login.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.keycloak.protocol.oid4vc.vp.login.protocol.ClaimsToContext;
import org.keycloak.protocol.oid4vc.vp.model.DcqlQuery;
import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;
import org.keycloak.protocol.oid4vc.vp.testsupport.KbJwtSigner;
import org.keycloak.protocol.oid4vc.vp.testsupport.Oid4vciClient;
import org.keycloak.protocol.oid4vc.vp.testsupport.SimulatedWallet;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestCredentialIssuer;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;
import org.keycloak.protocol.oid4vc.vp.trust.TrustPolicy;
import org.keycloak.protocol.oid4vc.vp.trust.TrustStore;
import org.keycloak.protocol.oid4vc.vp.verifier.PresentationRequestContext;
import org.keycloak.protocol.oid4vc.vp.verifier.sdjwt.SdJwtVpVerifier;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.ToStringConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Keycloak issues a card that OUR OWN verifier accepts. That closes the "we issue what we can
 * verify" loop, and is the only way to confirm the signing key's configuration (a usable x5c
 * chain), the algorithm (ES256) and holder binding (a cnf drawn from the OID4VCI proof).
 *
 * <p>Self-contained: it repeats {@code WalletLoginE2eIT}'s HTTP helpers rather than introduce a
 * class hierarchy between two tests that share only a container.</p>
 *
 * <p>Beyond what login needs, the imported realm carries the
 * {@code verifiableCredentialsEnabled} switch, a java-keystore {@code KeyProvider} loading the
 * issuance key (leaf plus CA, without which Keycloak emits no {@code x5c} header at all) and the
 * {@code oid4vci.enabled} client attribute. The credential scope itself is created through the
 * admin API — see {@link #createCredentialScope}.</p>
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CardIssuanceIT {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String REALM = "oid4vp-test";
    private static final String CLIENT_ID = "test-app";
    private static final String CLIENT_SECRET = "test-app-secret";

    private static final String VCT = "urn:pn:account-holder:1";
    private static final String CONFIG_ID = "account-holder";
    /** The account's federated identifier: READ from the attribute, never derived. */
    private static final String FEDID = "https://test-issuer.example.org:PID-CARD-0001";
    /** Reuses the production constant: a typo here would silently produce a card with no subject,
     *  and no test would catch it. */
    private static final String FEDID_ATTRIBUTE = ClaimsToContext.FEDID_ATTRIBUTE;

    private static final String CARD_USERNAME = "card-holder";
    private static final String CARD_EMAIL = "card@example.org";
    private static final String CARD_PASSWORD = "card-secret";

    /** A second account, for the pinned-PASSIVE-key scenario. */
    private static final String PASSIVE_USERNAME = "passive-holder";
    private static final String PASSIVE_EMAIL = "passive@example.org";
    private static final String PASSIVE_FEDID = "https://test-issuer.example.org:PID-CARD-0002";

    /** A third account, for the entitlement-revocation scenario: the first two share ordered
     *  state and must not be reused here. */
    private static final String REVOKE_USERNAME = "revoke-holder";
    private static final String REVOKE_EMAIL = "revoke@example.org";
    private static final String REVOKE_FEDID = "https://test-issuer.example.org:PID-CARD-0003";

    /** The CARD's lifetime (the SD-JWT's exp), set by `vc.refresh_interval_in_seconds`. Well
     *  inside the issuing certificate's own validity. */
    private static final long CARD_LIFETIME_SECONDS = 2592000L;
    /** The horizon of the ENTITLEMENT to obtain cards (`vc.expiry_in_seconds`). */
    private static final long ENTITLEMENT_SECONDS = 7776000L;

    /** Alias and password of the issuance keystore: they MUST match the {@code oid4vp-card-issuer}
     *  key provider declared in {@code realm-oid4vp-test.json}. */
    private static final String KEYSTORE_PASSWORD = "changeit";
    private static final String KEYSTORE_ALIAS = "card-issuer";
    /** Imposed by Keycloak: a realm keystore must live under
     *  {@code ${kc.home.dir}/data/{realm}/}, or the server refuses to start. */
    private static final String KEYSTORE_PATH = "/opt/keycloak/data/oid4vp-test/card-issuer.p12";

    /** The DCQL asks for {@code sub} explicitly. Our verifier compares requested paths against the
     *  disclosures ALONE, and the {@code sub} produced by {@code oid4vc-subject-id-mapper} is indeed
     *  selectively disclosable: it is not among the default {@code visible_claims}
     *  ({@code id,iat,nbf,exp,jti}). */
    private static final String DCQL_QUERY_JSON = """
        {"credentials":[{"id":"own","format":"dc+sd-jwt",\
        "meta":{"vct_values":["urn:pn:account-holder:1"]},\
        "claims":[{"path":["sub"]}]}]}""";

    private static TestTrustChain chain;
    private static GenericContainer<?> keycloak;
    private static String baseUrl;
    private static final ToStringConsumer KC_LOGS = new ToStringConsumer();

    @BeforeAll
    static void startKeycloak() throws Exception {
        chain = new TestTrustChain();
        Path realmFile = writeRealmImport(chain);
        Path keystoreFile = chain.writeCardIssuerKeystore(KEYSTORE_ALIAS, KEYSTORE_PASSWORD);

        Path moduleDir = Paths.get(System.getProperty("user.dir"));
        Path loginJar = moduleDir.resolve("target/oid4vp-login-0.1.0-SNAPSHOT.jar");
        Path coreJar = moduleDir.resolve("../oid4vp-core/target/oid4vp-core-0.1.0-SNAPSHOT.jar").normalize();
        assertTrue(Files.isRegularFile(loginJar), "provider JAR absent (lancer via `verify`, pas `test`): " + loginJar);
        assertTrue(Files.isRegularFile(coreJar), "provider JAR absent (lancer via `verify`, pas `test`): " + coreJar);

        keycloak = new GenericContainer<>(DockerImageName.parse("quay.io/keycloak/keycloak:26.7.0"))
            .withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCopyFileToContainer(MountableFile.forHostPath(coreJar.toString()),
                "/opt/keycloak/providers/oid4vp-core.jar")
            .withCopyFileToContainer(MountableFile.forHostPath(loginJar.toString()),
                "/opt/keycloak/providers/oid4vp-login.jar")
            // mode 0644: temporary files are created 0600 by root, while the container runs as
            // "keycloak" (uid 1000) and must be able to read them.
            .withCopyFileToContainer(MountableFile.forHostPath(realmFile.toString(), 0644),
                "/opt/keycloak/data/import/realm-oid4vp-test.json")
            .withCopyFileToContainer(MountableFile.forHostPath(keystoreFile.toString(), 0644),
                KEYSTORE_PATH)
            .withCommand("start-dev", "--import-realm",
                "--features=oid4vc-vci,oid4vc-vci-preauth-code,oid4vc-vci-rest-credential-offer")
            .withLogConsumer(KC_LOGS)
            .waitingFor(Wait.forHttp("/realms/" + REALM).forPort(8080).forStatusCode(200)
                .withStartupTimeout(Duration.ofMinutes(3)));
        try {
            keycloak.start();
        } catch (RuntimeException e) {
            dumpLogs();
            throw e;
        }

        baseUrl = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);

        HttpClient http = HttpClient.newHttpClient();
        String bearer = adminBearer(http);
        // Keycloak 26 refuses "unmanaged" attributes by default; without this switch, oid4vp.fedid
        // would not be persisted onto accounts.
        enableUnmanagedAttributes(http, bearer);
        createCredentialScope(http, bearer);

        // The first thing to check when this fails: is the issuance key loaded from the keystore,
        // with its certificate?
        JsonNode keys = realmKeys(http, bearer);
        assertNotNull(keys.path("active").get("ES256"),
            "the ES256 issuance key must be loaded from the keystore, keys=" + keys);
        System.out.println("[CardIssuanceIT] issuer-metadata="
            + get(http, baseUrl + "/realms/" + REALM + "/.well-known/openid-credential-issuer", null).body());
    }

    @AfterAll
    static void stopKeycloak() {
        dumpLogs();
        if (keycloak != null) {
            keycloak.stop();
        }
    }

    private static void dumpLogs() {
        String content;
        try {
            content = keycloak != null ? keycloak.getLogs() : KC_LOGS.toUtf8String();
        } catch (Exception e) {
            content = KC_LOGS.toUtf8String();
        }
        try {
            Files.writeString(Paths.get(System.getProperty("user.dir"), "target", "kc-runtime.log"), content);
        } catch (Exception ignored) {
            // best effort
        }
    }

    /**
     * A real Keycloak issues a card of our vct, and our own {@link SdJwtVpVerifier} validates it
     * through the same seven links as any third-party card.
     *
     * <p>It also proves the card's {@code sub} is the federated identifier READ from the account,
     * never derived, and records what the issued-card registry keeps about it.</p>
     */
    @Test
    @Order(1)
    void keycloakIssuesACardOurOwnVerifierAccepts() throws Exception {
        HttpClient http = HttpClient.newHttpClient();
        String bearer = adminBearer(http);

        // 1) Un utilisateur porteur de l'attribut qui alimentera le `sub` de la carte.
        String userId = createUser(http, bearer, CARD_USERNAME, CARD_EMAIL,
            Map.of(FEDID_ATTRIBUTE, FEDID));

        // 2) Grant the credential to the holder first.
        grantCredential(http, bearer, userId, CONFIG_ID);

        // 3) A pre-authorized offer created by the user, then received by the wallet.
        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain), Map.of());
        String card = fetchCard(http, wallet, CARD_USERNAME);
        wallet.receive(VCT, card);
        assertTrue(wallet.holds(VCT), "the wallet must hold the card it received");
        JsonNode header = decodeIssuerHeader(card);
        System.out.println("[CardIssuanceIT] issuer-jwt header: alg=" + header.path("alg").asText()
            + " typ=" + header.path("typ").asText() + " kid=" + header.path("kid").asText()
            + " x5c.size=" + header.path("x5c").size());
        assertEquals(2, header.path("x5c").size(),
            "the x5c must carry the complete chain, leaf plus CA: without it our trust link would "
                + "refuse the card");

        // 4) The decisive check: does our own engine accept this card?
        VerifiedPresentation verified = verifyWithOurOwnEngine(card, wallet);

        assertEquals(VCT, verified.getVct());
        assertEquals(FEDID, String.valueOf(verified.getClaims().get("sub")),
            "the card's sub MUST be the federated identifier read from the account, never derived");
        assertTrue(verified.getClaims().containsKey("jti"),
            "a jti is required: it is what will identify the card for revocation");

        // 5) The card's lifetime comes from `vc.refresh_interval_in_seconds`, not
        //    `vc.expiry_in_seconds`, which bounds the ENTITLEMENT instead. iat/exp are reserved
        //    claims VerifiedPresentation does not re-expose, so they are read off the raw JWT.
        JsonNode payload = decodeIssuerPayload(card);
        assertEquals(CARD_LIFETIME_SECONDS, payload.get("exp").asLong() - payload.get("iat").asLong(),
            "the card's exp must come from vc.refresh_interval_in_seconds");

        // 6) The issued-card registry fills itself at issuance, but its identifier is its OWN: the
        //    card's `jti` is a separate UUID drawn by SdJwtCredentialBuilder. Revoking by `jti` is
        //    therefore impossible.
        JsonNode issued = issuedCredentials(http, bearer, userId);
        System.out.println("[CardIssuanceIT] issued-credentials=" + issued);
        assertEquals(1, issued.size(), "an issued card must be recorded, response=" + issued);
        JsonNode record = issued.get(0);
        assertEquals(CONFIG_ID, record.path("credentialType").asText(),
            "the registry indexes by the credential scope's NAME, not by the vct, response=" + issued);
        assertEquals(ENTITLEMENT_SECONDS * 1000L,
            record.path("expiresAt").asLong() - record.path("issuedAt").asLong(),
            "the registry's horizon comes from vc.expiry_in_seconds, response=" + issued);
        assertNotEquals(String.valueOf(verified.getClaims().get("jti")), record.path("id").asText(),
            "the registry identifier is NOT the card's jti, response=" + issued);
    }

    /**
     * Is a PASSIVE key usable for issuance once the credential scope pins it through
     * {@code vc.signing_key_id}? What is at stake is separation of use: if it is, the issuance key
     * never appears in the token-signing JWKS.
     *
     * <p>Keycloak draws the {@code kid} when it loads the keystore, so it cannot be written into
     * the realm in advance. It is read here, pinned onto the scope, and the provider is then moved
     * to PASSIVE before a card is issued for a SECOND account and validated by the same engine.</p>
     */
    @Test
    @Order(2)
    void aPassiveKeyPinnedByKidStillIssuesVerifiableCards() throws Exception {
        HttpClient http = HttpClient.newHttpClient();
        String bearer = adminBearer(http);

        String kid = activeKidForAlgorithm(http, bearer, "ES256");
        assertNotNull(kid, "the ES256 issuance key must be active before pinning");
        pinSigningKeyId(http, bearer, kid);
        setCardIssuerKeyActive(http, bearer, false);

        assertEquals("PASSIVE", statusOfKey(http, bearer, kid),
            "the provider must have moved to PASSIVE (active=false, enabled=true)");

        String userId = createUser(http, bearer, PASSIVE_USERNAME, PASSIVE_EMAIL,
            Map.of(FEDID_ATTRIBUTE, PASSIVE_FEDID));
        grantCredential(http, bearer, userId, CONFIG_ID);

        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain), Map.of());
        String card = fetchCard(http, wallet, PASSIVE_USERNAME);

        assertEquals(kid, decodeIssuerHeader(card).path("kid").asText(),
            "the card must be signed by the pinned key");
        VerifiedPresentation verified = verifyWithOurOwnEngine(card, wallet);
        assertEquals(PASSIVE_FEDID, String.valueOf(verified.getClaims().get("sub")),
            "a pinned PASSIVE key must produce a card our verifier accepts");
    }

    /**
     * The entitlement ({@code UserVerifiableCredential}) governs issuance, and an administrator
     * deleting it cuts the holder off at once — revocation in bulk, an administration path too
     * important to be verified by reading code.
     *
     * <p>The account is DEDICATED to this scenario: the two tests above share ordered state, pinned
     * key then PASSIVE, which must be neither disturbed nor reused.</p>
     *
     * <p>It proves, in order: without the entitlement issuance is REFUSED, so granting is required
     * and not merely sufficient; with it the card is issued and our engine accepts it; deleting the
     * entitlement ALSO empties the issued-card registry; no further issuance is possible; and the
     * operation is not idempotent, answering 404 the second time.</p>
     */
    @Test
    @Order(3)
    void revokingTheEntitlementCutsIssuanceOffForThatHolder() throws Exception {
        HttpClient http = HttpClient.newHttpClient();
        String bearer = adminBearer(http);

        String userId = createUser(http, bearer, REVOKE_USERNAME, REVOKE_EMAIL,
            Map.of(FEDID_ATTRIBUTE, REVOKE_FEDID));

        // 1) WITHOUT the grant: the refusal comes at offer creation.
        assertNoEntitlementRefusal(http, "before any grant");

        // 2) WITH the grant: the card is issued, and our engine accepts it.
        grantCredential(http, bearer, userId, CONFIG_ID);
        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain), Map.of());
        String card = fetchCard(http, wallet, REVOKE_USERNAME);
        assertEquals(REVOKE_FEDID, String.valueOf(verifyWithOurOwnEngine(card, wallet)
            .getClaims().get("sub")));
        assertEquals(1, issuedCredentials(http, bearer, userId).size(),
            "the issued card must be recorded before revocation");

        // 3) The revocation: deleting the entitlement, named by the credential scope's NAME.
        HttpResponse<String> revoked = exchange(http,
            HttpRequest.newBuilder(URI.create(vcResource(userId) + "/credentials/" + enc(CONFIG_ID)))
                .header("Authorization", "Bearer " + bearer).DELETE());
        assertEquals(204, revoked.statusCode(),
            "DELETE .../vc/credentials/{credentialScopeName} attendu (204), corps="
                + snippet(revoked.body()));

        assertEquals(0, entitlements(http, bearer, userId).size(),
            "the entitlement must be gone from the account");
        // The bulk effect: deleting the entitlement also purges already issued cards.
        assertEquals(0, issuedCredentials(http, bearer, userId).size(),
            "revoking the entitlement must empty this holder's issued-card registry");

        // 4) No further issuance is possible, which is what the identity provider relies on.
        assertNoEntitlementRefusal(http, "after revoking the entitlement");

        // 5) Not idempotent: the second call finds no entitlement to delete.
        HttpResponse<String> again = exchange(http,
            HttpRequest.newBuilder(URI.create(vcResource(userId) + "/credentials/" + enc(CONFIG_ID)))
                .header("Authorization", "Bearer " + bearer).DELETE());
        assertEquals(404, again.statusCode(),
            "revoking twice must answer 404, body=" + snippet(again.body()));
    }

    /**
     * The revocation scenario's shared assertion: with no entitlement, the offer request is
     * refused by a {@code 400 invalid_credential_offer_request} naming the user and configuration.
     */
    private static void assertNoEntitlementRefusal(HttpClient http, String phase) throws Exception {
        HttpResponse<String> offer = requestCredentialOffer(http, userToken(http, REVOKE_USERNAME),
            CONFIG_ID);
        assertEquals(400, offer.statusCode(),
            "with no entitlement (" + phase + "), the offer must be refused, body=" + snippet(offer.body()));
        JsonNode error = MAPPER.readTree(offer.body());
        assertEquals("invalid_credential_offer_request", error.path("error").asText(),
            "expected error (" + phase + "), body=" + snippet(offer.body()));
        assertTrue(error.path("error_description").asText().contains(
                "does not have verifiable credential '" + CONFIG_ID + "'"),
            "the refusal must name the missing entitlement (" + phase + "), body=" + snippet(offer.body()));
    }

    // ---- reusable issuance flow -------------------------------------------------

    /** Creates a pre-authorized offer for the current user and collects the card. */
    private static String fetchCard(HttpClient http, SimulatedWallet wallet, String username)
        throws Exception {
        String offerUri = createCredentialOffer(http, userToken(http, username), CONFIG_ID);
        String card = new Oid4vciClient(http).fetchCredential(offerUri, wallet.holderKeyPair());
        assertNotNull(card, "a card must be issued");
        return card;
    }

    /** Presents the card to OUR engine, with a fresh KB-JWT signed by the holder's key. */
    private static VerifiedPresentation verifyWithOurOwnEngine(String card, SimulatedWallet wallet)
        throws Exception {
        String kbJwt = KbJwtSigner.sign(wallet.holderKeyPair(), "NONCE-1", "AUD-1", card,
            System.currentTimeMillis() / 1000);
        PresentationRequestContext context = new PresentationRequestContext(
            "NONCE-1", "AUD-1",
            DcqlQuery.fromJson(DCQL_QUERY_JSON),
            TrustPolicy.acceptingAll(TrustStore.fromPem(pemCert(chain.caCert))),
            "own");
        return new SdJwtVpVerifier().verify(card + kbJwt, context);
    }

    /** The issuer JWT's header, from an SD-JWT VC. */
    private static JsonNode decodeIssuerHeader(String sdJwtVc) throws Exception {
        String issuerJwt = sdJwtVc.split("~", 2)[0];
        return MAPPER.readTree(Base64.getUrlDecoder().decode(issuerJwt.split("\\.")[0]));
    }

    /** Le payload de l'issuer-JWT d'un SD-JWT VC (1er segment avant le premier {@code ~}). */
    private static JsonNode decodeIssuerPayload(String sdJwtVc) throws Exception {
        String issuerJwt = sdJwtVc.split("~", 2)[0];
        byte[] json = Base64.getUrlDecoder().decode(issuerJwt.split("\\.")[1]);
        return MAPPER.readTree(json);
    }

    // ---- scenario steps ---------------------------------------------------------

    /**
     * Creates our vct's credential scope and attaches it to {@code test-app} as an OPTIONAL scope.
     *
     * <p>Deliberately done through the admin API rather than in the realm template: declaring a
     * {@code clientScopes} array at import REPLACES Keycloak's built-in scopes
     * ({@code profile}, {@code email}, {@code roles}…), ce qui priverait de leurs claims tous les
     * tokens du realm — realm que {@code WalletLoginE2eIT} partage avec cet IT.</p>
     */
    private static void createCredentialScope(HttpClient http, String bearer) throws Exception {
        String scopeJson = """
            {
              "name": "%s",
              "description": "The account-holder card this Keycloak issues",
              "protocol": "oid4vc",
              "attributes": {
                "vc.credential_configuration_id": "%s",
                "vc.verifiable_credential_type": "%s",
                "vc.format": "dc+sd-jwt",
                "vc.credential_signing_alg": "ES256",
                "vc.expiry_in_seconds": "%d",
                "vc.refresh_interval_in_seconds": "%d",
                "vc.binding_required": "true",
                "vc.binding_required_proof_types": "jwt",
                "vc.cryptographic_binding_methods_supported": "jwk",
                "vc.include_in_metadata": "true",
                "include.in.token.scope": "true",
                "display.on.consent.screen": "false"
              },
              "protocolMappers": [
                {
                  "name": "card-subject",
                  "protocol": "oid4vc",
                  "protocolMapper": "oid4vc-subject-id-mapper",
                  "consentRequired": false,
                  "config": { "userAttribute": "%s", "claim.name": "id" }
                }
              ]
            }"""
            .formatted(CONFIG_ID, CONFIG_ID, VCT, ENTITLEMENT_SECONDS, CARD_LIFETIME_SECONDS,
                FEDID_ATTRIBUTE);
        HttpResponse<String> created = exchange(http,
            HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + REALM + "/client-scopes"))
                .header("Authorization", "Bearer " + bearer)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(scopeJson)));
        assertEquals(201, created.statusCode(),
            "expected the credential scope to be created (201), body=" + snippet(created.body()));

        String scopeId = findClientScope(http, bearer, CONFIG_ID).get("id").asText();
        HttpResponse<String> attached = exchange(http,
            HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + REALM
                    + "/clients/" + clientUuid(http, bearer) + "/optional-client-scopes/" + scopeId))
                .header("Authorization", "Bearer " + bearer)
                .PUT(HttpRequest.BodyPublishers.noBody()));
        assertTrue(attached.statusCode() >= 200 && attached.statusCode() < 300,
            "expected the scope to attach to " + CLIENT_ID + " (2xx), status=" + attached.statusCode()
                + " corps=" + snippet(attached.body()));
    }

    /** L'identifiant interne du client {@code test-app}. */
    private static String clientUuid(HttpClient http, String bearer) throws Exception {
        HttpResponse<String> r = get(http, baseUrl + "/admin/realms/" + REALM
            + "/clients?clientId=" + enc(CLIENT_ID), bearer);
        assertEquals(200, r.statusCode(), "expected GET clients (200), body=" + snippet(r.body()));
        JsonNode clients = MAPPER.readTree(r.body());
        assertEquals(1, clients.size(), "client " + CLIENT_ID + " must exist, response=" + r.body());
        return clients.get(0).get("id").asText();
    }

    /** Octroi du droit d'obtenir la carte (le registre {@code UserVerifiableCredential}). */
    private static void grantCredential(HttpClient http, String bearer, String userId, String configId)
        throws Exception {
        String body = """
            {"credentialScopeName":"%s","credentialConfigurationId":"%s"}"""
            .formatted(configId, configId);
        HttpResponse<String> r = exchange(http,
            HttpRequest.newBuilder(URI.create(vcResource(userId) + "/credentials"))
                .header("Authorization", "Bearer " + bearer)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)));
        assertTrue(r.statusCode() >= 200 && r.statusCode() < 300,
            "expected the credential grant (2xx), status=" + r.statusCode() + " body=" + snippet(r.body()));
    }

    /** This account's ENTITLEMENTS to obtain cards ({@code UserVerifiableCredential}). */
    private static JsonNode entitlements(HttpClient http, String bearer, String userId)
        throws Exception {
        HttpResponse<String> r = get(http, vcResource(userId) + "/credentials", bearer);
        assertEquals(200, r.statusCode(), "GET vc/credentials attendu (200), corps=" + snippet(r.body()));
        return MAPPER.readTree(r.body());
    }

    /** The cards actually issued for this account ({@code IssuedVerifiableCredential}). */
    private static JsonNode issuedCredentials(HttpClient http, String bearer, String userId) throws Exception {
        HttpResponse<String> r = exchange(http,
            HttpRequest.newBuilder(URI.create(vcResource(userId) + "/issued-credentials"))
                .header("Authorization", "Bearer " + bearer)
                .header("Accept", "application/json").GET());
        assertEquals(200, r.statusCode(), "GET issued-credentials attendu (200), corps=" + snippet(r.body()));
        return MAPPER.readTree(r.body());
    }

    private static String vcResource(String userId) {
        return baseUrl + "/admin/realms/" + REALM + "/users/" + userId + "/vc";
    }

    /**
     * Creates a pre-authorized offer for the authenticated user and returns the
     * {@code credential_offer_uri} the wallet will resolve.
     */
    private static String createCredentialOffer(HttpClient http, String userBearer, String configId)
        throws Exception {
        HttpResponse<String> r = requestCredentialOffer(http, userBearer, configId);
        assertEquals(200, r.statusCode(),
            "expected the offer to be created (200), body=" + snippet(r.body()));
        JsonNode offer = MAPPER.readTree(r.body());
        return offer.get("issuer").asText() + "/" + offer.get("nonce").asText();
    }

    /** The RAW {@code create-credential-offer} response: the revocation scenario needs its
     *  failures too, which are its proof. */
    private static HttpResponse<String> requestCredentialOffer(HttpClient http, String userBearer,
                                                               String configId) throws Exception {
        return get(http, baseUrl + "/realms/" + REALM + "/protocol/oid4vc/create-credential-offer"
            + "?credential_configuration_id=" + enc(configId) + "&pre_authorized=true&type=uri",
            userBearer);
    }

    /** The holder's access token, including the credential scope, by direct grant. */
    private static String userToken(HttpClient http, String username) throws Exception {
        JsonNode token = formPost(http, baseUrl + "/realms/" + REALM + "/protocol/openid-connect/token",
            "grant_type=password&scope=" + enc("openid " + CONFIG_ID)
                + "&client_id=" + CLIENT_ID
                + "&client_secret=" + enc(CLIENT_SECRET)
                + "&username=" + enc(username)
                + "&password=" + enc(CARD_PASSWORD));
        return token.get("access_token").asText();
    }

    /** Creates a user with a password and attributes, and returns their Keycloak id. */
    private static String createUser(HttpClient http, String bearer, String username, String email,
                                     Map<String, String> attributes) throws Exception {
        ObjectNode user = MAPPER.createObjectNode();
        user.put("username", username);
        user.put("email", email);
        user.put("enabled", true);
        user.put("emailVerified", true);
        // A complete profile and no required action: otherwise the direct grant fails with
        // "Account is not fully set up", VERIFY_PROFILE wanting a form.
        user.put("firstName", "Carte");
        user.put("lastName", "Titulaire");
        user.putArray("requiredActions");
        ObjectNode attrs = user.putObject("attributes");
        attributes.forEach((key, value) -> attrs.putArray(key).add(value));
        ObjectNode credential = user.putArray("credentials").addObject();
        credential.put("type", "password");
        credential.put("value", CARD_PASSWORD);
        credential.put("temporary", false);

        HttpResponse<String> created = exchange(http,
            HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + REALM + "/users"))
                .header("Authorization", "Bearer " + bearer)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(user))));
        assertEquals(201, created.statusCode(),
            "expected the user to be created (201), body=" + snippet(created.body()));

        HttpResponse<String> found = exchange(http,
            HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + REALM
                    + "/users?username=" + enc(username) + "&exact=true"))
                .header("Authorization", "Bearer " + bearer).GET());
        assertEquals(200, found.statusCode(), "expected the user lookup to answer 200");
        JsonNode users = MAPPER.readTree(found.body());
        assertEquals(1, users.size(), "exactly one user created, response=" + found.body());
        return users.get(0).get("id").asText();
    }

    /** The {@code kid} of the realm's ACTIVE key for this algorithm, or {@code null}. */
    private static String activeKidForAlgorithm(HttpClient http, String bearer, String algorithm)
        throws Exception {
        JsonNode kid = realmKeys(http, bearer).path("active").get(algorithm);
        return kid != null ? kid.asText() : null;
    }

    /** The status ({@code ACTIVE}/{@code PASSIVE}/{@code DISABLED}) of the key with this {@code kid}. */
    private static String statusOfKey(HttpClient http, String bearer, String kid) throws Exception {
        for (JsonNode key : realmKeys(http, bearer).path("keys")) {
            if (kid.equals(key.path("kid").asText())) {
                return key.path("status").asText();
            }
        }
        return null;
    }

    /** Pins the credential scope's signing key by its {@code kid}. */
    private static void pinSigningKeyId(HttpClient http, String bearer, String kid) throws Exception {
        ObjectNode scope = (ObjectNode) findClientScope(http, bearer, CONFIG_ID);
        ((ObjectNode) scope.get("attributes")).put("vc.signing_key_id", kid);
        HttpResponse<String> r = exchange(http,
            HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + REALM
                    + "/client-scopes/" + scope.get("id").asText()))
                .header("Authorization", "Bearer " + bearer)
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(scope))));
        assertTrue(r.statusCode() >= 200 && r.statusCode() < 300,
            "expected vc.signing_key_id to be pinned (2xx), status=" + r.statusCode()
                + " corps=" + snippet(r.body()));
    }

    private static JsonNode findClientScope(HttpClient http, String bearer, String name) throws Exception {
        HttpResponse<String> r = get(http, baseUrl + "/admin/realms/" + REALM + "/client-scopes", bearer);
        assertEquals(200, r.statusCode(), "GET client-scopes attendu (200), corps=" + snippet(r.body()));
        for (JsonNode scope : MAPPER.readTree(r.body())) {
            if (name.equals(scope.path("name").asText())) {
                return scope;
            }
        }
        throw new IllegalStateException("client scope not found: " + name);
    }

    /** Moves the issuance key provider between ACTIVE and PASSIVE; {@code enabled} stays true. */
    private static void setCardIssuerKeyActive(HttpClient http, String bearer, boolean active)
        throws Exception {
        HttpResponse<String> list = get(http, baseUrl + "/admin/realms/" + REALM
            + "/components?type=org.keycloak.keys.KeyProvider", bearer);
        assertEquals(200, list.statusCode(), "GET components attendu (200), corps=" + snippet(list.body()));

        for (JsonNode component : MAPPER.readTree(list.body())) {
            if (!"oid4vp-card-issuer".equals(component.path("name").asText())) {
                continue;
            }
            ObjectNode updated = (ObjectNode) component;
            ((ObjectNode) updated.get("config")).putArray("active").add(Boolean.toString(active));
            HttpResponse<String> r = exchange(http,
                HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + REALM
                        + "/components/" + updated.get("id").asText()))
                    .header("Authorization", "Bearer " + bearer)
                    .header("Content-Type", "application/json")
                    .PUT(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(updated))));
            assertTrue(r.statusCode() >= 200 && r.statusCode() < 300,
                "expected the key provider update (2xx), status=" + r.statusCode()
                    + " corps=" + snippet(r.body()));
            return;
        }
        throw new IllegalStateException("key provider oid4vp-card-issuer not found");
    }

    /** The realm's key inventory, used to read the issuance key's {@code kid} and status. */
    private static JsonNode realmKeys(HttpClient http, String bearer) throws Exception {
        HttpResponse<String> r = exchange(http,
            HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + REALM + "/keys"))
                .header("Authorization", "Bearer " + bearer)
                .header("Accept", "application/json").GET());
        assertEquals(200, r.statusCode(), "GET keys attendu (200), corps=" + snippet(r.body()));
        return MAPPER.readTree(r.body());
    }

    private static void enableUnmanagedAttributes(HttpClient http, String bearer) throws Exception {
        String profileUrl = baseUrl + "/admin/realms/" + REALM + "/users/profile";
        HttpResponse<String> r = get(http, profileUrl, bearer);
        assertEquals(200, r.statusCode(), "GET users/profile: " + snippet(r.body()));

        ObjectNode profile = (ObjectNode) MAPPER.readTree(r.body());
        profile.put("unmanagedAttributePolicy", "ENABLED");

        HttpResponse<String> put = exchange(http, HttpRequest.newBuilder(URI.create(profileUrl))
            .header("Authorization", "Bearer " + bearer)
            .header("Content-Type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(profile))));
        assertEquals(200, put.statusCode(), "PUT users/profile: " + put.statusCode() + " " + snippet(put.body()));
    }

    // ---- helpers HTTP -----------------------------------------------------------

    /** An admin access token (master realm, admin-cli) for the administration API. */
    private static String adminBearer(HttpClient http) throws Exception {
        JsonNode token = formPost(http, baseUrl + "/realms/master/protocol/openid-connect/token",
            "grant_type=password&client_id=admin-cli&username=admin&password=admin");
        return token.get("access_token").asText();
    }

    private static HttpResponse<String> get(HttpClient http, String url, String bearer) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
            .header("Accept", "application/json").GET();
        if (bearer != null) {
            builder.header("Authorization", "Bearer " + bearer);
        }
        return exchange(http, builder);
    }

    private static JsonNode formPost(HttpClient http, String url, String body) throws Exception {
        HttpResponse<String> r = exchange(http, HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body)));
        assertEquals(200, r.statusCode(), "POST " + url + " -> " + r.statusCode() + " : " + snippet(r.body()));
        return MAPPER.readTree(r.body());
    }

    private static HttpResponse<String> exchange(HttpClient http, HttpRequest.Builder builder) throws Exception {
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    // ---- realm construction -----------------------------------------------------

    /** This container ENABLES issuance: it creates the {@code account-holder} credential scope and
     *  exercises issuance, so the identity provider must know our {@code vct} and its offer
     *  configuration. See {@code WalletLoginE2eIT.writeRealmImport} for why each test declares this
     *  rather than the shared template hard-coding it. */
    private static Path writeRealmImport(TestTrustChain chain) throws Exception {
        String template;
        try (InputStream in = CardIssuanceIT.class.getResourceAsStream("/realm-oid4vp-test.json")) {
            template = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        String realm = template
            .replace("@@CLIENT_SECRET@@", CLIENT_SECRET)
            .replace("@@TRUST_ANCHORS_PEM@@", jsonValue(pemCert(chain.caCert)))
            .replace("@@OWN_ISSUER_ANCHORS_PEM@@", jsonValue(pemCert(chain.caCert)))
            .replace("@@SIGNING_KEY_PEM@@", jsonValue(pemPkcs8(chain.issuerKeyPair.getPrivate().getEncoded())))
            .replace("@@SIGNING_CERT_PEM@@", jsonValue(pemCert(chain.issuerCert)))
            .replace("@@OWN_VCT@@", VCT)
            .replace("@@OWN_CREDENTIAL_CONFIG_ID@@", CONFIG_ID)
            .replace("@@DCQL_QUERY_JSON@@", jsonValue(DCQL_QUERY_JSON));

        Path file = Files.createTempFile("realm-oid4vp-card", ".json");
        Files.writeString(file, realm, StandardCharsets.UTF_8);
        return file;
    }

    /** Escapes a value for insertion into a JSON string, without the outer quotes. */
    private static String jsonValue(String raw) throws Exception {
        String quoted = MAPPER.writeValueAsString(raw);
        return quoted.substring(1, quoted.length() - 1);
    }

    private static String pemCert(X509Certificate cert) throws Exception {
        return pem("CERTIFICATE", cert.getEncoded());
    }

    private static String pemPkcs8(byte[] der) {
        return pem("PRIVATE KEY", der);
    }

    private static String pem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String snippet(String s) {
        if (s == null) {
            return "<null>";
        }
        return s.length() > 500 ? s.substring(0, 500) + "..." : s;
    }
}
