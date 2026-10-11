
package com.adaptpqc.ratchet;

public final class PreparedRatchet {

    private final RatchetOffer offer;
    private final byte[] pendingSharedSecret;

    public PreparedRatchet(
            RatchetOffer offer,
            byte[] pendingSharedSecret) {

        if (offer == null
                || pendingSharedSecret == null
                || pendingSharedSecret.length == 0) {
            throw new IllegalArgumentException(
                    "Invalid prepared ratchet."
            );
        }

        this.offer = offer;
        this.pendingSharedSecret = pendingSharedSecret.clone();
    }

    public RatchetOffer getOffer() {
        return offer;
    }

    byte[] getPendingSharedSecret() {
        return pendingSharedSecret.clone();
    }
}
