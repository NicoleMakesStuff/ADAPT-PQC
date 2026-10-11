
package com.adaptpqc.protocol;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.adaptpqc.protocol.v2.ReplayGuard;

class ReplayGuardTest {

    @Test
    void acceptsNewId() {
        ReplayGuard guard = new ReplayGuard(100);
        assertTrue(guard.accept(UUID.randomUUID()));
    }

    @Test
    void rejectsDuplicateId() {
        ReplayGuard guard = new ReplayGuard(100);
        UUID id = UUID.randomUUID();

        assertTrue(guard.accept(id));
        assertFalse(guard.accept(id));
    }

    @Test
    void rejectsNullId() {
        ReplayGuard guard = new ReplayGuard(100);
        assertFalse(guard.accept(null));
    }

    @Test
    void evictsOldestIdWhenFull() {
        ReplayGuard guard = new ReplayGuard(2);
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        UUID third = UUID.randomUUID();

        assertTrue(guard.accept(first));
        assertTrue(guard.accept(second));
        assertTrue(guard.accept(third));

        assertEquals(2, guard.size());

        // This bounded cache evicts the oldest ID.
        assertTrue(guard.accept(first));
    }

    @Test
    void rejectsInvalidCapacity() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ReplayGuard(0));
    }
}
