
package com.adaptpqc.ratchet;

public final class RatchetOffer {

    private final byte[] encapsulation;
    private final byte[] salt;
    private final long nextGeneration;

    public RatchetOffer(
            byte[] encapsulation,
            byte[] salt,
            long nextGeneration) {

        if (encapsulation == null || encapsulation.length == 0
                || salt == null || salt.length == 0
                || nextGeneration < 1) {
            throw new IllegalArgumentException(
                    "Invalid ratchet offer."
            );
        }

        this.encapsulation = encapsulation.clone();
        this.salt = salt.clone();
        this.nextGeneration = nextGeneration;
    }

    public byte[] getEncapsulation() {
        return encapsulation.clone();
    }

    public byte[] getSalt() {
        return salt.clone();
    }

    public long getNextGeneration() {
        return nextGeneration;
    }
}
