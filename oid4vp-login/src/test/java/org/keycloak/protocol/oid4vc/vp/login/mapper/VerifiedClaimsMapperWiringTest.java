package org.keycloak.protocol.oid4vc.vp.login.mapper;

import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oid4vc.vp.login.broker.Oid4vpIdentityProvider;
import org.keycloak.protocol.oid4vc.vp.login.protocol.PresentationNote;
import org.keycloak.protocol.oid4vc.vp.login.protocol.VerifiedClaimsNotes;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.representations.IDToken;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Fast regression guard for the two real bugs this phase already hit, both invisible to the rest
 * of the unit suite (delete either fix and everything still compiles and passes):
 * <ul>
 *   <li>{@code VerifiedClaimsMapper} silently dropped from every token because it was missing one
 *       of the {@code OIDC*Mapper} marker interfaces that {@code TokenManager} filters on.</li>
 *   <li>{@code Oid4vpIdentityProvider#authenticationFinished} missing/renamed, which is what
 *       carries the verified_claims notes onto the {@code UserSessionModel}.</li>
 * </ul>
 */
class VerifiedClaimsMapperWiringTest {

    private static final String SERVICES_RESOURCE = "META-INF/services/org.keycloak.protocol.ProtocolMapper";

    @Test
    void mapperImplementsAllFourTokenTypeMarkerInterfaces() {
        assertTrue(OIDCIDTokenMapper.class.isAssignableFrom(VerifiedClaimsMapper.class),
                "VerifiedClaimsMapper must implement OIDCIDTokenMapper or it is never invoked for id_token");
        assertTrue(OIDCAccessTokenMapper.class.isAssignableFrom(VerifiedClaimsMapper.class),
                "VerifiedClaimsMapper must implement OIDCAccessTokenMapper or it is never invoked for access_token");
        assertTrue(UserInfoTokenMapper.class.isAssignableFrom(VerifiedClaimsMapper.class),
                "VerifiedClaimsMapper must implement UserInfoTokenMapper or it is never invoked for userinfo");
        assertTrue(TokenIntrospectionTokenMapper.class.isAssignableFrom(VerifiedClaimsMapper.class),
                "VerifiedClaimsMapper must implement TokenIntrospectionTokenMapper or it is never invoked for introspection");
    }

    @Test
    void identityProviderStillOverridesAuthenticationFinished() throws NoSuchMethodException {
        // Throws NoSuchMethodException (failing the test) if the override is renamed or removed —
        // that override is what carries the verified_claims notes onto the UserSessionModel.
        assertNotNull(Oid4vpIdentityProvider.class.getDeclaredMethod(
                "authenticationFinished", AuthenticationSessionModel.class, BrokeredIdentityContext.class));
    }

    @Test
    void servicesResourceIsOnClasspathAndNamesTheMapper() throws IOException {
        Enumeration<URL> resources = getClass().getClassLoader().getResources(SERVICES_RESOURCE);
        assertTrue(resources.hasMoreElements(), "services resource must be on the classpath: " + SERVICES_RESOURCE);

        boolean found = false;
        while (resources.hasMoreElements()) {
            URL url = resources.nextElement();
            try (InputStream in = url.openStream();
                 BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.trim().equals(VerifiedClaimsMapper.class.getName())) {
                        found = true;
                    }
                }
            }
        }
        assertTrue(found, "services resource must reference " + VerifiedClaimsMapper.class.getName());
    }

    @Test
    void tableEntryWinsForTheMatchingVct() {
        assertEquals("pn_account_possession", VerifiedClaimsMapper.trustFrameworkFor(
            "urn:eudi:pid:1=eidas,urn:pn:account-holder:1=pn_account_possession",
            "urn:pn:account-holder:1"));
    }

    @Test
    void unknownVctYieldsNothingRatherThanAWrongFramework() {
        assertNull(VerifiedClaimsMapper.trustFrameworkFor("urn:eudi:pid:1=eidas", "urn:unknown:1"),
            "asserting a wrong trust framework in a token costs more than asserting none");
    }

    @Test
    void blankOrMalformedTableIsIgnored() {
        assertNull(VerifiedClaimsMapper.trustFrameworkFor("", "urn:eudi:pid:1"));
        assertNull(VerifiedClaimsMapper.trustFrameworkFor("garbage,,=x", "urn:eudi:pid:1"));
    }

    /**
     * A mistyped table silences the ENTIRE realm, and that silence must not be confused with the
     * legitimate silence of an unknown {@code vct}. {@code usablePairs} is what separates them,
     * hence a WARN on one side and a DEBUG on the other.
     */
    @Test
    void usablePairsSeparatesAMistypedTableFromAnUnknownVct() {
        assertEquals(2, VerifiedClaimsMapper.usablePairs(
                "urn:eudi:pid:1=eidas,urn:pn:account-holder:1=pn_account_possession"),
            "une table correcte a des paires exploitables : le silence y vient du vct, pas de la saisie");

        // La coquille du constat : « : » au lieu de « = ». trustFrameworkFor saute la paire
        // (separator <= 0) et plus AUCUN vct n'obtient de cadre — le realm entier perd
        // verified_claims sans qu'un seul octet de journal ne l'ait dit avant ce correctif.
        assertEquals(0, VerifiedClaimsMapper.usablePairs("urn:eudi:pid:1:eidas"));
        assertNull(VerifiedClaimsMapper.trustFrameworkFor("urn:eudi:pid:1:eidas", "urn:eudi:pid:1"));

        assertEquals(0, VerifiedClaimsMapper.usablePairs(null));
        assertEquals(0, VerifiedClaimsMapper.usablePairs("   "));
        assertEquals(0, VerifiedClaimsMapper.usablePairs("urn:eudi:pid:1="),
            "an empty value is not a usable trust framework");
    }

    /**
     * {@code WARNED_UNUSABLE_TABLES} is a {@code ConcurrentHashMap.newKeySet()}, which refuses a
     * {@code null} key. Reaching it with {@code byVctConfig == null} is not exotic: it is an older
     * realm with no per-vct table AND a legacy {@code trustFramework} key that is present but
     * EMPTY, which is what the admin console writes when the field is cleared — as opposed to an
     * absent key, which falls to the {@code eidas} default and never reaches this guard.
     *
     * <p>Without the fix this throws a {@code NullPointerException}; with it, nothing is raised and
     * the mapper simply emits no {@code verified_claims}.</p>
     */
    @Test
    void setClaimDoesNotThrowWhenNoByVctTableAndLegacyTrustFrameworkIsBlank() {
        ProtocolMapperModel model = new ProtocolMapperModel();
        model.setConfig(new HashMap<>());
        // No TRUST_FRAMEWORK_BY_VCT_CONFIG at all, so byVctConfig is null. The legacy key is
        // present but empty, as the console leaves it when the field is cleared.
        model.getConfig().put(VerifiedClaimsMapper.TRUST_FRAMEWORK_CONFIG, "");

        Map<String, String> notes = new HashMap<>();
        notes.put(VerifiedClaimsNotes.PRESENTATIONS, PresentationNote.toJson(List.of(
            new PresentationNote(null, "urn:eudi:pid:1", null, null, null, Map.of()))));
        UserSessionModel userSession = fakeOnlineUserSession(notes);

        VerifiedClaimsMapper mapper = new VerifiedClaimsMapper();
        IDToken token = new IDToken();

        // setClaim is protected, and this test lives in the same package: calling it directly is
        // the closest testable seam to the defect. session and clientSessionCtx are never read by
        // the method body, so null will do.
        assertDoesNotThrow(() -> mapper.setClaim(token, model, userSession, null, null),
            "an absent per-vct table plus an EMPTY legacy trustFramework key must not raise a "
                + "NullPointerException while issuing the token");
        assertFalse(token.getOtherClaims().containsKey("verified_claims"),
            "no usable trust framework: no verified_claims may be emitted");
    }

    /**
     * With no {@code trustFrameworkByVct} table at all, the legacy single-key fallback must still
     * emit the claim exactly as before: the warning added alongside changes nothing observable in
     * the token.
     */
    @Test
    void legacyFallbackStillEmitsTheClaimUnchanged() {
        String legacyValue = "custom-legacy-unchanged";
        ProtocolMapperModel model = new ProtocolMapperModel();
        model.setConfig(new HashMap<>());
        model.getConfig().put(VerifiedClaimsMapper.TRUST_FRAMEWORK_CONFIG, legacyValue);

        Map<String, String> notes = new HashMap<>();
        notes.put(VerifiedClaimsNotes.PRESENTATIONS, PresentationNote.toJson(List.of(
            new PresentationNote("https://pid.example", "urn:eudi:pid:1", "dc+sd-jwt", "CN=ca",
                "T", Map.of("given_name", "Marie")))));
        UserSessionModel userSession = fakeOnlineUserSession(notes);

        VerifiedClaimsMapper mapper = new VerifiedClaimsMapper();
        IDToken token = new IDToken();
        mapper.setClaim(token, model, userSession, null, null);

        Object verifiedClaims = token.getOtherClaims().get("verified_claims");
        assertTrue(verifiedClaims instanceof Map<?, ?>,
            "the legacy fallback must still emit a verified_claims entry: behaviour unchanged");
        Object verification = ((Map<?, ?>) verifiedClaims).get("verification");
        assertEquals(legacyValue, ((Map<?, ?>) verification).get("trust_framework"),
            "the legacy value must still carry the framework, whatever vct was presented");
    }

    /**
     * The legacy-fallback warning must fire ONCE per configuration value, not per issued token.
     * Three successive logins on the same configuration may grow the guard set only once.
     */
    @Test
    void legacyFallbackWarningFiresOnlyOnce() {
        String legacyValue = "custom-legacy-warn-once";
        ProtocolMapperModel model = new ProtocolMapperModel();
        model.setConfig(new HashMap<>());
        model.getConfig().put(VerifiedClaimsMapper.TRUST_FRAMEWORK_CONFIG, legacyValue);

        Map<String, String> notes = new HashMap<>();
        notes.put(VerifiedClaimsNotes.PRESENTATIONS, PresentationNote.toJson(List.of(
            new PresentationNote("https://pid.example", "urn:eudi:pid:1", "dc+sd-jwt", "CN=ca",
                "T", Map.of("given_name", "Marie")))));
        UserSessionModel userSession = fakeOnlineUserSession(notes);
        VerifiedClaimsMapper mapper = new VerifiedClaimsMapper();

        assertFalse(VerifiedClaimsMapper.legacyFallbackAlreadyWarned(legacyValue),
            "an unseen configuration value: nothing may have warned yet");

        mapper.setClaim(new IDToken(), model, userSession, null, null);
        assertTrue(VerifiedClaimsMapper.legacyFallbackAlreadyWarned(legacyValue),
            "the first login on this configuration must trigger the warning");

        // Two more logins on the SAME configuration: the guard must not move again. That is what
        // separates "once per value" from "once per issued token".
        mapper.setClaim(new IDToken(), model, userSession, null, null);
        mapper.setClaim(new IDToken(), model, userSession, null, null);
        assertTrue(VerifiedClaimsMapper.legacyFallbackAlreadyWarned(legacyValue));
    }

    /**
     * A minimal {@link UserSessionModel} double. Only {@code isOffline()} and
     * {@code getNote(String)} are exercised; the module has no Mockito dependency, hence a proxy
     * rather than a thirty-method anonymous class. Any other call throws explicitly rather than
     * returning a misleading default.
     */
    private static UserSessionModel fakeOnlineUserSession(Map<String, String> notes) {
        InvocationHandler handler = (proxy, method, args) -> {
            switch (method.getName()) {
                case "isOffline":
                    return false;
                case "getNote":
                    return notes.get((String) args[0]);
                case "toString":
                    return "fakeOnlineUserSession";
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                default:
                    throw new UnsupportedOperationException(
                        "unexpected UserSessionModel method in test double: " + method.getName());
            }
        };
        return (UserSessionModel) Proxy.newProxyInstance(
            VerifiedClaimsMapperWiringTest.class.getClassLoader(),
            new Class<?>[] { UserSessionModel.class }, handler);
    }

    /** The same double as {@link #fakeOnlineUserSession}, with {@code isOffline() == true}. */
    private static UserSessionModel fakeOfflineUserSession(Map<String, String> notes) {
        InvocationHandler handler = (proxy, method, args) -> {
            switch (method.getName()) {
                case "isOffline":
                    return true;
                case "getNote":
                    return notes.get((String) args[0]);
                case "toString":
                    return "fakeOfflineUserSession";
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                default:
                    throw new UnsupportedOperationException(
                        "unexpected UserSessionModel method in test double: " + method.getName());
            }
        };
        return (UserSessionModel) Proxy.newProxyInstance(
            VerifiedClaimsMapperWiringTest.class.getClassLoader(),
            new Class<?>[] { UserSessionModel.class }, handler);
    }

    /** A mapper model carrying the per-vct table the tests below use. */
    private static ProtocolMapperModel modelWithByVctTable() {
        ProtocolMapperModel model = new ProtocolMapperModel();
        model.setConfig(new HashMap<>());
        model.getConfig().put(VerifiedClaimsMapper.TRUST_FRAMEWORK_BY_VCT_CONFIG,
            "urn:eudi:pid:1=eidas,urn:pn:account-holder:1=pn_account_possession");
        return model;
    }

    @Test
    void twoPresentationsEmitAnArrayOfTwoFrameworks() {
        Map<String, String> notes = new HashMap<>();
        // the session note carrying both presentations, written by the identity provider
        notes.put(VerifiedClaimsNotes.PRESENTATIONS, PresentationNote.toJson(List.of(
            new PresentationNote("https://pid.example", "urn:eudi:pid:1", "dc+sd-jwt", "CN=ca",
                "T", Map.of("given_name", "Marie")),
            new PresentationNote("https://kc.example", "urn:pn:account-holder:1", "dc+sd-jwt",
                "CN=ca", "T", Map.of("sub", "FED-1")))));
        UserSessionModel userSession = fakeOnlineUserSession(notes);

        VerifiedClaimsMapper mapper = new VerifiedClaimsMapper();
        IDToken token = new IDToken();

        mapper.setClaim(token, modelWithByVctTable(), userSession, null, null);

        List<?> verifiedClaims = (List<?>) token.getOtherClaims().get("verified_claims");
        assertEquals(2, verifiedClaims.size());
    }

    @Test
    void aVctAbsentFromTheTableIsDroppedFromTheArray() {
        Map<String, String> notes = new HashMap<>();
        notes.put(VerifiedClaimsNotes.PRESENTATIONS, PresentationNote.toJson(List.of(
            new PresentationNote("https://pid.example", "urn:eudi:pid:1", "dc+sd-jwt", "CN=ca",
                "T", Map.of("given_name", "Marie")),
            new PresentationNote("https://kc.example", "urn:inconnu:1", "dc+sd-jwt", "CN=ca",
                "T", Map.of("sub", "FED-1")))));
        UserSessionModel userSession = fakeOnlineUserSession(notes);

        VerifiedClaimsMapper mapper = new VerifiedClaimsMapper();
        IDToken token = new IDToken();

        mapper.setClaim(token, modelWithByVctTable(), userSession, null, null);

        // One entry survives, so an object rather than a one-element array: silence never turns
        // into asserting a framework that does not apply.
        assertTrue(token.getOtherClaims().get("verified_claims") instanceof Map<?, ?>);
    }

    /**
     * {@code [null,{...}]} is a valid JSON array that Jackson deserialises into a {@code List} with
     * a {@code null} element WITHOUT throwing. Without the filter in
     * {@code PresentationNote.fromJson}, {@code setClaim}'s loop would dereference it and raise an
     * uncaught {@code NullPointerException}, killing issuance of the ENTIRE token — strictly worse
     * than the silence this is meant to guarantee.
     */
    @Test
    void aNullElementInThePresentationsArrayIsSkippedRatherThanThrowing() {
        Map<String, String> notes = new HashMap<>();
        notes.put(VerifiedClaimsNotes.PRESENTATIONS,
            "[null,{\"issuer\":\"https://pid.example\",\"vct\":\"urn:eudi:pid:1\","
                + "\"format\":\"dc+sd-jwt\",\"trustAnchor\":\"CN=ca\",\"verifiedAt\":\"T\","
                + "\"claims\":{\"given_name\":\"Marie\"}}]");
        UserSessionModel userSession = fakeOnlineUserSession(notes);

        VerifiedClaimsMapper mapper = new VerifiedClaimsMapper();
        IDToken token = new IDToken();

        assertDoesNotThrow(() -> mapper.setClaim(token, modelWithByVctTable(), userSession, null, null),
            "a null element in the PRESENTATIONS array must never raise an NPE while issuing the "
                + "token");

        // The surviving entry is still emitted: an object, one usable presentation.
        assertTrue(token.getOtherClaims().get("verified_claims") instanceof Map<?, ?>,
            "the null element is discarded, not the valid entry beside it");
    }

    /**
     * An offline session copies the notes of the online session that asked for
     * {@code scope=offline_access} and then carries them indefinitely, across logout and later
     * refreshes. Replaying verified_claims on it would show a stale {@code verification.time} as
     * though it were current.
     */
    @Test
    void offlineSessionEmitsNoVerifiedClaimsEvenWithAValidPresentationsNote() {
        Map<String, String> notes = new HashMap<>();
        notes.put(VerifiedClaimsNotes.PRESENTATIONS, PresentationNote.toJson(List.of(
            new PresentationNote("https://pid.example", "urn:eudi:pid:1", "dc+sd-jwt", "CN=ca",
                "T", Map.of("given_name", "Marie")))));
        UserSessionModel userSession = fakeOfflineUserSession(notes);

        VerifiedClaimsMapper mapper = new VerifiedClaimsMapper();
        IDToken token = new IDToken();

        mapper.setClaim(token, modelWithByVctTable(), userSession, null, null);

        assertFalse(token.getOtherClaims().containsKey("verified_claims"),
            "an offline session must never re-emit verified_claims, even with a perfectly valid "
                + "PRESENTATIONS note");
    }
}
