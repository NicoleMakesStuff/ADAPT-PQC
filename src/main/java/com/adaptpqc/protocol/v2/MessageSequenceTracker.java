package com.adaptpqc.protocol.v2;

public final class MessageSequenceTracker {
    private long expectedSequence = 0;

    public synchronized boolean isExpected(long sequence) {
        return sequence == expectedSequence;
    }

    public synchronized void markAccepted(long sequence) {
        if (sequence != expectedSequence) {
            throw new IllegalStateException(
                    "Unexpected sequence number");
        }

        if (expectedSequence == Long.MAX_VALUE) {
            throw new IllegalStateException(
                    "Sequence number exhausted; re-establish session");
        }

        expectedSequence++;
    }

    public synchronized long expectedSequence() {
        return expectedSequence;
    }
}