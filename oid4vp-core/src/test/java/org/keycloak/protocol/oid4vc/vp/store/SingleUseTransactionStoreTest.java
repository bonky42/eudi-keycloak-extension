package org.keycloak.protocol.oid4vc.vp.store;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.model.PresentationTransaction;
import org.keycloak.protocol.oid4vc.vp.model.TransactionStatus;
import org.keycloak.protocol.oid4vc.vp.testsupport.InMemorySingleUseObjects;

import static org.junit.jupiter.api.Assertions.*;

class SingleUseTransactionStoreTest {

    private PresentationTransaction newTx(String id) {
        PresentationTransaction tx = new PresentationTransaction();
        tx.setId(id);
        tx.setNonce("nonce-1");
        tx.setState("state-1");
        tx.setStatus(TransactionStatus.PENDING);
        tx.setCreatedAt(1000L);
        return tx;
    }

    @Test
    void putThenGetReturnsCopyWithoutConsuming() {
        SingleUseTransactionStore store = new SingleUseTransactionStore(new InMemorySingleUseObjects());
        store.put(newTx("t1"), 120);
        assertEquals("nonce-1", store.get("t1").getNonce());
        assertNotNull(store.get("t1")); // still there
    }

    @Test
    void consumeRemovesAtomically() {
        SingleUseTransactionStore store = new SingleUseTransactionStore(new InMemorySingleUseObjects());
        store.put(newTx("t1"), 120);
        assertNotNull(store.consume("t1"));
        assertNull(store.consume("t1")); // second read: nothing
        assertNull(store.get("t1"));
    }

    @Test
    void replaceUpdatesStatus() {
        SingleUseTransactionStore store = new SingleUseTransactionStore(new InMemorySingleUseObjects());
        PresentationTransaction tx = newTx("t1");
        store.put(tx, 120);
        tx.setStatus(TransactionStatus.COMPLETED);
        store.replace(tx, 120);
        assertEquals(TransactionStatus.COMPLETED, store.get("t1").getStatus());
    }

    @Test
    void unknownIdReturnsNull() {
        SingleUseTransactionStore store = new SingleUseTransactionStore(new InMemorySingleUseObjects());
        assertNull(store.get("nope"));
    }

    @Test
    void replaceOnAbsentIdIsSilentNoOp() {
        SingleUseTransactionStore store = new SingleUseTransactionStore(new InMemorySingleUseObjects());
        PresentationTransaction tx = newTx("absent");

        // Attempting to replace an id that was never stored should be a silent no-op
        assertDoesNotThrow(() -> store.replace(tx, 120));
        assertNull(store.get("absent"), "replace() on absent id should not create an entry");

        // Also test replace on already-consumed id
        store.put(newTx("consumed"), 120);
        store.consume("consumed");

        PresentationTransaction updatedTx = newTx("consumed");
        updatedTx.setStatus(TransactionStatus.COMPLETED);
        assertDoesNotThrow(() -> store.replace(updatedTx, 120));
        assertNull(store.get("consumed"), "replace() on consumed id should not recreate an entry");
    }
}
