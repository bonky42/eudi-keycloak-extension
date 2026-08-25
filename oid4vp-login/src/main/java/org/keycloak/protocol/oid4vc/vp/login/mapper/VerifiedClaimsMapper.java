package org.keycloak.protocol.oid4vc.vp.login.mapper;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.protocol.oid4vc.vp.login.protocol.PresentationNote;
import org.keycloak.protocol.oid4vc.vp.login.protocol.VctTable;
import org.keycloak.protocol.oid4vc.vp.login.protocol.VerifiedClaimsBuilder;
import org.keycloak.protocol.oid4vc.vp.login.protocol.VerifiedClaimsNotes;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OIDC ProtocolMapper that reads the verified_claims session notes posted by
 * {@code Oid4vpIdentityProvider} at wallet login time and emits the OIDC4IDA
 * {@code verified_claims} structure into the token.
 *
 * <p>This is a no-op for any session that did not go through the OID4VP wallet
 * login flow (i.e. no {@link VerifiedClaimsNotes#PRESENTATIONS} note present).
 *
 * <p>The {@code OIDC*Mapper} marker interfaces are REQUIRED: {@code TokenManager} selects the
 * mappers to run per token type with an {@code instanceof} filter, so a mapper that only extends
 * {@link AbstractOIDCProtocolMapper} is silently never invoked. The per-token-type
 * {@code *.token.claim} toggles are still honoured by the inherited {@code transform*} methods.
 */
public class VerifiedClaimsMapper extends AbstractOIDCProtocolMapper
        implements ProtocolMapper, OIDCIDTokenMapper, OIDCAccessTokenMapper, UserInfoTokenMapper,
                   TokenIntrospectionTokenMapper {

    public static final String PROVIDER_ID = "oid4vp-verified-claims-mapper";

    public static final String TRUST_FRAMEWORK_CONFIG = "trustFramework";
    public static final String TRUST_FRAMEWORK_BY_VCT_CONFIG = "trustFrameworkByVct";
    private static final String TRUST_FRAMEWORK_DEFAULT = "eidas";

    private static final Logger LOG = Logger.getLogger(VerifiedClaimsMapper.class);

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    /** Values of {@link #TRUST_FRAMEWORK_BY_VCT_CONFIG} already reported as unusable: a
     *  misconfiguration is logged ONCE per value, not once per issued token. Keyed by the value
     *  itself rather than a flag, so a table fixed and then broken differently is reported again.
     *  Capped, because the key comes from administration and nothing an administrator writes may
     *  grow a cache without bound. */
    private static final Set<String> WARNED_UNUSABLE_TABLES = ConcurrentHashMap.newKeySet();
    private static final int WARNED_TABLES_CAP = 32;

    /** Configurations already reported for taking the legacy fallback — no
     *  {@code trustFrameworkByVct} table at all. Same idiom and cap as
     *  {@link #WARNED_UNUSABLE_TABLES}, but deliberately a DISTINCT set: the two warnings describe
     *  different faults (mistyped table vs. absent table) and must not silence each other. */
    private static final Set<String> WARNED_LEGACY_FALLBACK = ConcurrentHashMap.newKeySet();

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES, VerifiedClaimsMapper.class);

        // addIncludeInTokensConfig defaults every *.token.claim toggle to "true". verified_claims
        // carries wallet-derived PII (name, birthdate, address, ...); bearer access tokens and
        // introspection responses are commonly logged or forwarded to resource servers, so default
        // those two OFF for an admin adding this mapper from the console. id_token/userinfo stay
        // opt-in-by-default (front-channel to the client / requires an authenticated caller).
        for (ProviderConfigProperty property : CONFIG_PROPERTIES) {
            if (OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN.equals(property.getName())
                    || OIDCAttributeMapperHelper.INCLUDE_IN_INTROSPECTION.equals(property.getName())) {
                property.setDefaultValue("false");
            }
        }

        ProviderConfigProperty trustFramework = new ProviderConfigProperty();
        trustFramework.setName(TRUST_FRAMEWORK_CONFIG);
        trustFramework.setLabel("Trust framework");
        trustFramework.setHelpText("Trust framework asserted in the verified_claims.verification.trust_framework field (e.g. eidas).");
        trustFramework.setType(ProviderConfigProperty.STRING_TYPE);
        trustFramework.setDefaultValue(TRUST_FRAMEWORK_DEFAULT);
        CONFIG_PROPERTIES.add(trustFramework);

        ProviderConfigProperty byVct = new ProviderConfigProperty();
        byVct.setName(TRUST_FRAMEWORK_BY_VCT_CONFIG);
        byVct.setLabel("Trust framework by credential type");
        byVct.setHelpText("Comma-separated vct=trust_framework pairs. A credential type absent from "
            + "this table emits no verified_claims at all, rather than asserting a framework that "
            + "does not apply to it (e.g. a possession factor issued by this very Keycloak must "
            + "never be reported as eidas).");
        byVct.setType(ProviderConfigProperty.STRING_TYPE);
        byVct.setDefaultValue(null);
        // Required as soon as this Keycloak issues its own card: otherwise the legacy fallback
        // below (trustFramework, default "eidas") applies to it too, contradicting the invariant
        // that our card is a possession factor and never eidas.
        byVct.setHelpText(byVct.getHelpText() + " REQUIRED as soon as this Keycloak issues its own "
            + "credential type (ownVct): without an entry for that vct here, the legacy single "
            + "'trustFramework' setting below applies to it too, and its default is 'eidas' — "
            + "exactly what a possession factor must never be reported as.");
        CONFIG_PROPERTIES.add(byVct);
    }

    /** The trust framework declared for this {@code vct}, or {@code null}. */
    static String trustFrameworkFor(String config, String vct) {
        return vct == null ? null : VctTable.parse(config).get(vct);
    }

    /** How many usable pairs the table holds. A mistyped table silences the whole realm, so it
     *  has to be reported rather than endured. */
    static int usablePairs(String config) {
        return VctTable.parse(config).size();
    }

    /** Test only: true if this value of the legacy {@code trustFramework} key already triggered
     *  {@link #warnOnceIfLegacyFallbackUsed}. With no log-capture framework on the test classpath,
     *  the guard itself — the very one deciding whether {@code LOG.warnf} runs — is the oracle for
     *  "once per value, not per token". */
    static boolean legacyFallbackAlreadyWarned(String legacyTrustFramework) {
        return WARNED_LEGACY_FALLBACK.contains(legacyTrustFramework == null ? "" : legacyTrustFramework);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "OID4VP Verified Claims";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Emits the OIDC4IDA verified_claims structure from an OID4VP wallet login, if present on the session. "
                + "Off by default in access tokens and introspection responses, since it may carry wallet PII.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel model, UserSessionModel userSession,
                             KeycloakSession session, ClientSessionContext clientSessionCtx) {
        // Offline user sessions are created by copying the notes of the online session that
        // requested scope=offline_access, and they then outlive it across logout and every
        // subsequent offline refresh. Re-emitting verified_claims from that copy would replay the
        // ORIGINAL verification.time on a token minted months later off a presentation that was
        // never re-checked — a false assurance claim, not just a stale cache. Skip entirely.
        if (userSession.isOffline()) {
            return;
        }

        List<PresentationNote> presentations =
            PresentationNote.fromJson(userSession.getNote(VerifiedClaimsNotes.PRESENTATIONS));
        if (presentations.isEmpty()) {
            // A session that did not come through an OID4VP wallet login: nothing to emit.
            return;
        }

        String byVctConfig = model.getConfig().get(TRUST_FRAMEWORK_BY_VCT_CONFIG);
        List<Map<String, Object>> entries = new ArrayList<>();
        for (PresentationNote presentation : presentations) {
            String trustFramework = trustFrameworkFor(byVctConfig, presentation.vct());
            if (trustFramework == null && (byVctConfig == null || byVctConfig.isBlank())) {
                // No table configured: fall back to the older single setting.
                trustFramework =
                    model.getConfig().getOrDefault(TRUST_FRAMEWORK_CONFIG, TRUST_FRAMEWORK_DEFAULT);
                // That fallback applies to EVERY vct, ownVct included — whose name this mapper
                // cannot even see, it being identity-provider config — and its default is "eidas".
                warnOnceIfLegacyFallbackUsed(trustFramework);
            }
            if (trustFramework == null || trustFramework.isBlank()) {
                warnOnceIfTableUnusable(byVctConfig);
                LOG.debugf("Mapper %s: credential type '%s' is absent from the '%s' table; emitting "
                    + "no verified_claims entry for it rather than asserting a framework that does "
                    + "not apply to it", PROVIDER_ID, presentation.vct(), TRUST_FRAMEWORK_BY_VCT_CONFIG);
                continue;
            }
            entries.add(VerifiedClaimsBuilder.build(presentation.issuer(), presentation.vct(),
                presentation.format(), presentation.trustAnchor(), presentation.verifiedAt(),
                presentation.claims() == null ? Map.of() : presentation.claims(), trustFramework));
        }

        Object verifiedClaims = VerifiedClaimsBuilder.collapse(entries);
        if (verifiedClaims != null) {
            token.getOtherClaims().put("verified_claims", verifiedClaims);
        }
    }

    /**
     * With no {@code trustFrameworkByVct} table at all, the single legacy key applies to EVERY
     * presented credential type, {@code ownVct} included — and its default, {@code "eidas"}, is
     * exactly what a possession factor must never claim. This mapper cannot see {@code ownVct}
     * (identity-provider config, not mapper config), so it cannot tell the dangerous case from the
     * harmless one and warns in both, once per value of the legacy key.
     */
    private void warnOnceIfLegacyFallbackUsed(String legacyTrustFramework) {
        String warnKey = legacyTrustFramework == null ? "" : legacyTrustFramework;
        if (WARNED_LEGACY_FALLBACK.size() < WARNED_TABLES_CAP && WARNED_LEGACY_FALLBACK.add(warnKey)) {
            LOG.warnf("Mapper %s: no '%s' table configured; falling back to the legacy single '%s' "
                + "value ('%s') for EVERY presented credential type. If this Keycloak issues its own "
                + "credential type (ownVct on the identity provider), that possession factor will be "
                + "reported under this same value — declare '%s' explicitly for its vct to avoid it "
                + "being reported as '%s'", PROVIDER_ID, TRUST_FRAMEWORK_BY_VCT_CONFIG,
                TRUST_FRAMEWORK_CONFIG, legacyTrustFramework, TRUST_FRAMEWORK_BY_VCT_CONFIG,
                TRUST_FRAMEWORK_DEFAULT);
        }
    }

    /**
     * A mistyped {@code trustFrameworkByVct} table silences the whole realm, so it must not do so
     * quietly. Logged ONCE per table value, and kept distinct from the legitimate silence of an
     * unknown {@code vct}, which the caller logs at DEBUG.
     */
    private void warnOnceIfTableUnusable(String byVctConfig) {
        // WARNED_UNUSABLE_TABLES is a ConcurrentHashMap.newKeySet(), whose .add(null) throws.
        // byVctConfig is null whenever no per-vct table is configured, which is exactly the path
        // that reaches here when the legacy key is present but empty. Normalising null to "" also
        // collapses "absent table" and "empty table" onto one warning key: they are the same
        // absence of usable configuration.
        String warnKey = byVctConfig == null ? "" : byVctConfig;
        if (usablePairs(byVctConfig) == 0 && WARNED_UNUSABLE_TABLES.size() < WARNED_TABLES_CAP
                && WARNED_UNUSABLE_TABLES.add(warnKey)) {
            LOG.warnf("Mapper %s: the '%s' table '%s' declares no usable vct=trust_framework "
                + "pair (each pair needs a '=' and a non-empty value); no verified_claims will "
                + "be emitted for ANY credential type until it is fixed",
                PROVIDER_ID, TRUST_FRAMEWORK_BY_VCT_CONFIG, byVctConfig);
        }
    }
}
