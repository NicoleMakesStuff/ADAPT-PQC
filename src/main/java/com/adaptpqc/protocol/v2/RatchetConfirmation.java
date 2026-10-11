package com.adaptpqc.protocol.v2;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

public final class RatchetConfirmation {
    private final UUID offerId;
    private final int generation;
    private final byte[] authenticationTag;

    public RatchetConfirmation(UUID offerId, int generation, byte[] authenticationTag) {
        if (offerId == null) throw new IllegalArgumentException("offerId is required");
        if (generation < 1) throw new IllegalArgumentException("Invalid generation");
        if (authenticationTag == null || authenticationTag.length == 0)
            throw new IllegalArgumentException("authenticationTag is required");
        this.offerId = offerId;
        this.generation = generation;
        this.authenticationTag = authenticationTag.clone();
    }

    public UUID offerId() { return offerId; }
    public int generation() { return generation; }
    public byte[] authenticationTag() { return authenticationTag.clone(); }

    byte[] authenticatedBytes() {
        return ProtocolCrypto.encode("ADAPT-PQC/v2/ratchet-confirmation",
                ProtocolCrypto.uuidBytes(offerId),
                Integer.toString(generation).getBytes(StandardCharsets.UTF_8));
    }

    public RatchetConfirmation withTag(byte[] tag) {
        return new RatchetConfirmation(offerId, generation, tag);
    }
}
