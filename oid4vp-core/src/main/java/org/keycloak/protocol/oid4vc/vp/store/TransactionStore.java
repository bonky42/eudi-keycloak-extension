package org.keycloak.protocol.oid4vc.vp.store;

import org.keycloak.protocol.oid4vc.vp.model.PresentationTransaction;

public interface TransactionStore {
    void put(PresentationTransaction tx, int ttlSeconds);
    PresentationTransaction get(String id);      // null when absent - does NOT consume
    PresentationTransaction consume(String id);  // null when absent - removes atomically

    /**
     * Updates the transaction state if the id exists and has not been consumed.
     * This is a silent no-op if the id is absent or already consumed — no exception is thrown
     * and no entry is created.
     *
     * Note: The {@code ttlSeconds} parameter is NOT applied. The original TTL set by {@link #put}
     * remains in effect; replacing does not reset or extend the transaction's lifespan.
     *
     * @param tx the updated transaction
     * @param ttlSeconds ignored; the original TTL is preserved
     */
    void replace(PresentationTransaction tx, int ttlSeconds); // updates the state
}
