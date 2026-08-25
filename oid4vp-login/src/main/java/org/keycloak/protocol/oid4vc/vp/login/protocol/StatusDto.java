package org.keycloak.protocol.oid4vc.vp.login.protocol;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.protocol.oid4vc.vp.model.PresentationTransaction;
import org.keycloak.protocol.oid4vc.vp.model.TransactionStatus;

/**
 * The polling DTO, exposing the transaction's status and NOTHING else: never claims, never an
 * errorCode, never any other sensitive data.
 */
public final class StatusDto {

    public String status;

    public StatusDto() {
        // Jackson
    }

    public StatusDto(String status) {
        this.status = status;
    }

    /**
     * Maps a transaction — or null, meaning expired or absent — onto the DTO exposed to polling.
     * Reveals the status ONLY, never claims and never a precise errorCode.
     */
    public static StatusDto of(PresentationTransaction tx) {
        if (tx == null) {
            return new StatusDto("expired");
        }

        TransactionStatus txStatus = tx.getStatus();
        if (txStatus == null) {
            return new StatusDto("expired");
        }

        String status = switch (txStatus) {
            case PENDING -> "pending";
            case COMPLETED -> "completed";
            case FAILED -> "failed";
            case EXPIRED -> "expired";
        };

        return new StatusDto(status);
    }

    /** Serialises this DTO to JSON carrying the 'status' field and no other. */
    public String toJson() {
        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.writeValueAsString(this);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize StatusDto", e);
        }
    }

    /** Deserialises JSON into this DTO. */
    public static StatusDto fromJson(String json) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.readValue(json, StatusDto.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to deserialize StatusDto", e);
        }
    }
}
