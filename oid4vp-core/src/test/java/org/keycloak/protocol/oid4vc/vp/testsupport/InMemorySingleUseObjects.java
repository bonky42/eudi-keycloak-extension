package org.keycloak.protocol.oid4vc.vp.testsupport;

import org.keycloak.models.SingleUseObjectProvider;

import java.util.HashMap;
import java.util.Map;

/**
 * In-memory fake of {@link SingleUseObjectProvider} for tests. TTL is ignored — entries
 * only disappear via {@link #remove(String)} or the manual {@link #expire(String)} hook.
 */
public class InMemorySingleUseObjects implements SingleUseObjectProvider {

    private final Map<String, Map<String, String>> store = new HashMap<>();

    @Override
    public void put(String key, long lifespanSeconds, Map<String, String> notes) {
        store.put(key, notes);
    }

    @Override
    public Map<String, String> get(String key) {
        return store.get(key);
    }

    @Override
    public Map<String, String> remove(String key) {
        return store.remove(key);
    }

    @Override
    public boolean replace(String key, Map<String, String> notes) {
        if (!store.containsKey(key)) {
            return false;
        }
        store.put(key, notes);
        return true;
    }

    @Override
    public boolean putIfAbsent(String key, long lifespanSeconds) {
        if (store.containsKey(key)) {
            return false;
        }
        store.put(key, Map.of());
        return true;
    }

    @Override
    public boolean contains(String key) {
        return store.containsKey(key);
    }

    /** Manual expiration hook for tests — TTL is otherwise ignored. */
    public void expire(String key) {
        store.remove(key);
    }

    @Override
    public void close() {
        // no-op
    }
}
