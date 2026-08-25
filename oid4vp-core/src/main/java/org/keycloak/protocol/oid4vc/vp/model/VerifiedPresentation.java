package org.keycloak.protocol.oid4vc.vp.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The immutable result of successfully verifying a verifiable presentation: the disclosed claims,
 * the issuer, the subject of the trust anchor that validated the chain, the credential type
 * ({@code vct}), and the expiry of the presented credential.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class VerifiedPresentation {

    private final Map<String, Object> claims;
    private final String issuer;
    private final String trustAnchorSubject;
    private final String vct;
    private final Long expiresAt;

    /** The older four-argument constructor: no expiry known. */
    public VerifiedPresentation(Map<String, Object> claims, String issuer,
                                 String trustAnchorSubject, String vct) {
        this(claims, issuer, trustAnchorSubject, vct, null);
    }

    @JsonCreator
    public VerifiedPresentation(@JsonProperty("claims") Map<String, Object> claims,
                                 @JsonProperty("issuer") String issuer,
                                 @JsonProperty("trustAnchorSubject") String trustAnchorSubject,
                                 @JsonProperty("vct") String vct,
                                 @JsonProperty("expiresAt") Long expiresAt) {
        this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
        this.issuer = issuer;
        this.trustAnchorSubject = trustAnchorSubject;
        this.vct = vct;
        this.expiresAt = expiresAt;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getTrustAnchorSubject() {
        return trustAnchorSubject;
    }

    public String getVct() {
        return vct;
    }

    /** Expiry of the presented credential (epoch seconds), or {@code null} if it carries none.
     *  {@code exp} stays filtered out of the claims (RESERVED_PAYLOAD_CLAIMS): it is exposed here
     *  rather than mixed in with business claims. */
    public Long getExpiresAt() {
        return expiresAt;
    }
}
