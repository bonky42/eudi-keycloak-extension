package org.keycloak.protocol.oid4vc.vp.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.protocol.oid4vc.vp.model.PresentationTransaction;

import java.util.Map;

public class SingleUseTransactionStore implements TransactionStore {

    private static final String KEY_PREFIX = "oid4vp.tx.";
    private static final String NOTE = "tx";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final SingleUseObjectProvider singleUse;

    public SingleUseTransactionStore(SingleUseObjectProvider singleUse) {
        this.singleUse = singleUse;
    }

    @Override
    public void put(PresentationTransaction tx, int ttlSeconds) {
        singleUse.put(KEY_PREFIX + tx.getId(), ttlSeconds, Map.of(NOTE, serialize(tx)));
    }

    @Override
    public PresentationTransaction get(String id) {
        Map<String, String> notes = singleUse.get(KEY_PREFIX + id);
        return notes == null ? null : deserialize(notes.get(NOTE));
    }

    @Override
    public PresentationTransaction consume(String id) {
        Map<String, String> notes = singleUse.remove(KEY_PREFIX + id);
        return notes == null ? null : deserialize(notes.get(NOTE));
    }

    @Override
    public void replace(PresentationTransaction tx, int ttlSeconds) {
        singleUse.replace(KEY_PREFIX + tx.getId(), Map.of(NOTE, serialize(tx)));
    }

    private String serialize(PresentationTransaction tx) {
        try { return MAPPER.writeValueAsString(tx); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }

    private PresentationTransaction deserialize(String json) {
        try { return MAPPER.readValue(json, PresentationTransaction.class); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }
}
