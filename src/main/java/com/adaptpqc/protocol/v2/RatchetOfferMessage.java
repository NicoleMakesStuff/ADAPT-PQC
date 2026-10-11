package com.adaptpqc.protocol.v2;

import java.util.UUID;

public final class RatchetOfferMessage {
    private final UUID offerId;
    private final int nextGeneration;
    private final byte[] encapsulation;
    private final byte[] salt;
    private final byte[] authenticationTag;

    public RatchetOfferMessage(UUID offerId, int nextGeneration,
                               byte[] encapsulation, byte[] salt,
                               byte[] authenticationTag) {
        if (offerId == null) throw new IllegalArgumentException("offerId is required");
        if (nextGeneration < 1) throw new IllegalArgumentException("Invalid generation");
        this.offerId = offerId;
        this.nextGeneration = nextGeneration;
        this.encapsulation = required(encapsulation, "encapsulation");
        this.salt = required(salt, "salt");
        this.authenticationTag = required(authenticationTag, "authenticationTag");
    }

    private static byte[] required(byte[] value, String name) {
        if (value == null || value.length == 0)
            throw new IllegalArgumentException(name + " is required");
        return value.clone();
    }

    public UUID offerId() { return offerId; }
    public int nextGeneration() { return nextGeneration; }
    public byte[] encapsulation() { return encapsulation.clone(); }
    public byte[] salt() { return salt.clone(); }
    public byte[] authenticationTag() { return authenticationTag.clone(); }

    byte[] authenticatedBytes() {
        return ProtocolCrypto.encode("ADAPT-PQC/v2/ratchet-offer",
                ProtocolCrypto.uuidBytes(offerId),
                Integer.toString(nextGeneration).getBytes(java.nio.charset.StandardCharsets.UTF_8),
                encapsulation, salt);
    }

    public RatchetOfferMessage withEncapsulation(byte[] replacement) {
        return new RatchetOfferMessage(offerId, nextGeneration, replacement,
                salt, authenticationTag);
    }

    public RatchetOfferMessage withSalt(byte[] replacement) {
        return new RatchetOfferMessage(offerId, nextGeneration, encapsulation,
                replacement, authenticationTag);
    }

    public RatchetOfferMessage withTag(byte[] replacement) {
        return new RatchetOfferMessage(offerId, nextGeneration, encapsulation,
                salt, replacement);
    }
}
