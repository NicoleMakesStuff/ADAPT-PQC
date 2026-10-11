
package com.adaptpqc.protocol.v2;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

public final class ReplayGuard {

    private final int capacity;
    private final Set<UUID> seen = new LinkedHashSet<>();

    public ReplayGuard(int capacity) {
        if (capacity < 1) {
            throw new IllegalArgumentException(
                    "Capacity must be positive");
        }
        this.capacity = capacity;
    }

    // Returns true only for a newly observed ID.
    public synchronized boolean accept(UUID id) {
        if (id == null || seen.contains(id)) {
            return false;
        }

        seen.add(id);

        if (seen.size() > capacity) {
            UUID oldest = seen.iterator().next();
            seen.remove(oldest);
        }

        return true;
    }

    public synchronized int size() {
        return seen.size();
    }
}
