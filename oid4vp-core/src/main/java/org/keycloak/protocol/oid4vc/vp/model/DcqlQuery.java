package org.keycloak.protocol.oid4vc.vp.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DcqlQuery {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private List<CredentialQuery> credentials;

    @JsonProperty("credential_sets")
    private List<CredentialSetQuery> credentialSets;

    public List<CredentialQuery> getCredentials() { return credentials; }
    public void setCredentials(List<CredentialQuery> credentials) { this.credentials = credentials; }

    public List<CredentialSetQuery> getCredentialSets() { return credentialSets; }
    public void setCredentialSets(List<CredentialSetQuery> credentialSets) {
        this.credentialSets = credentialSets;
    }

    /** The credential query bearing this {@code id}, or {@code null}. This is how the key of a
     *  {@code vp_token} entry resolves to the query the proof answers. First match wins on a
     *  duplicated {@code id} — undocumented by the specification, and not expected from a
     *  well-formed DCQL: no uniqueness check is made here. */
    public CredentialQuery credentialById(String id) {
        if (credentials == null || id == null) {
            return null;
        }
        for (CredentialQuery query : credentials) {
            if (id.equals(query.getId())) {
                return query;
            }
        }
        return null;
    }

    public static DcqlQuery fromJson(String json) {
        try {
            return MAPPER.readValue(json, DcqlQuery.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid DCQL query", e);
        }
    }

    public String toJson() {
        try {
            return MAPPER.writeValueAsString(this);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class CredentialQuery {
        private String id;
        private String format;
        private Meta meta;
        private List<ClaimQuery> claims;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getFormat() { return format; }
        public void setFormat(String format) { this.format = format; }
        public Meta getMeta() { return meta; }
        public void setMeta(Meta meta) { this.meta = meta; }
        public List<ClaimQuery> getClaims() { return claims; }
        public void setClaims(List<ClaimQuery> claims) { this.claims = claims; }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Meta {
        @JsonProperty("vct_values")
        private List<String> vctValues;
        public List<String> getVctValues() { return vctValues; }
        public void setVctValues(List<String> vctValues) { this.vctValues = vctValues; }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ClaimQuery {
        private List<String> path;
        public List<String> getPath() { return path; }
        public void setPath(List<String> path) { this.path = path; }
    }

    /**
     * A set of credentials that satisfies one use (OID4VP 1.0 section 6.2). Two properties only —
     * there is NO {@code purpose} field in 1.0.
     *
     * <p><b>Purely informational on the server side.</b> {@link #getRequired()}/{@link
     * #isRequiredOrDefault()} and {@link DcqlQuery#getCredentialSets()} have no consumer in
     * production: it is the WALLET that must satisfy every {@code required} set, client-side
     * (section 6.4.2). Nothing here checks it server-side, and that is not an oversight to correct.
     * For the DCQL shipped here (two {@code required:false} sets) it makes no difference; an
     * administrator writing {@code "required": true} into {@code dcqlQueryJson} should know that no
     * server-side enforcement follows from it.</p>
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class CredentialSetQuery {
        private List<List<String>> options;
        private Boolean required;

        public List<List<String>> getOptions() { return options; }
        public void setOptions(List<List<String>> options) { this.options = options; }
        public Boolean getRequired() { return required; }
        public void setRequired(Boolean required) { this.required = required; }

        /** An omitted {@code required} means {@code true} (section 6.2). Boxed as a {@link Boolean}
         *  on purpose: telling it apart from an explicit {@code false} is what allows the query to be
         *  re-serialised exactly as the administrator wrote it. Informational only — see the class
         *  javadoc: nothing server-side enforces this value. */
        @JsonIgnore
        public boolean isRequiredOrDefault() { return required == null || required; }
    }
}
