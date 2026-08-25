package org.keycloak.protocol.oid4vc.vp.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import org.keycloak.protocol.oid4vc.vp.request.ResponseEncryptionKey;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class PresentationTransaction {

    private String id;
    private String nonce;
    private String state;
    private String dcqlQueryJson;
    private TransactionStatus status;
    /** The verified presentations of the response, in the order of the {@code vp_token} object. A
     *  list rather than one field per attribute: a response can carry two, and flattening it to
     *  "the" presentation would mean arbitrarily electing one here, whereas identity precedence is
     *  decided in the login layer. */
    private List<VerifiedPresentation> presentations;
    private String errorCode;
    private long createdAt;

    /** Ephemeral response-encryption material, one pair per transaction (HAIP). Serialized with the
     *  transaction into the single-use store, so it expires with it. */
    private String responseEncKid;
    private String responseEncPrivateKey;
    private String responseEncPublicKey;

    public PresentationTransaction() {
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }

    public String getState() { return state; }
    public void setState(String state) { this.state = state; }

    public String getDcqlQueryJson() { return dcqlQueryJson; }
    public void setDcqlQueryJson(String dcqlQueryJson) { this.dcqlQueryJson = dcqlQueryJson; }

    public TransactionStatus getStatus() { return status; }
    public void setStatus(TransactionStatus status) { this.status = status; }

    public List<VerifiedPresentation> getPresentations() { return presentations; }
    public void setPresentations(List<VerifiedPresentation> presentations) {
        this.presentations = presentations;
    }

    public String getErrorCode() { return errorCode; }
    public void setErrorCode(String errorCode) { this.errorCode = errorCode; }

    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }

    public String getResponseEncKid() { return responseEncKid; }
    public void setResponseEncKid(String responseEncKid) { this.responseEncKid = responseEncKid; }

    public String getResponseEncPrivateKey() { return responseEncPrivateKey; }
    public void setResponseEncPrivateKey(String responseEncPrivateKey) {
        this.responseEncPrivateKey = responseEncPrivateKey;
    }

    public String getResponseEncPublicKey() { return responseEncPublicKey; }
    public void setResponseEncPublicKey(String responseEncPublicKey) {
        this.responseEncPublicKey = responseEncPublicKey;
    }

    /** Rebuilds the key pair from the three stored strings. */
    @JsonIgnore
    public ResponseEncryptionKey responseEncryptionKey() {
        return ResponseEncryptionKey.restore(responseEncKid, responseEncPrivateKey, responseEncPublicKey);
    }
}
