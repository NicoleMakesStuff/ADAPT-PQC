package com.adaptpqc.protocol.v2;

import java.security.GeneralSecurityException;

/**
 * Thrown when the receiver rejects a message. It extends
 * GeneralSecurityException, so existing catch blocks still work.
 */
public final class ProtocolRejectionException
        extends GeneralSecurityException {

    private final ProtocolRejectionReason reason;

    public ProtocolRejectionException(
            ProtocolRejectionReason reason,
            String message) {

        super(message);

        if (reason == null) {
            throw new IllegalArgumentException(
                    "Rejection reason is required");
        }

        this.reason = reason;
    }

    public ProtocolRejectionException(
            ProtocolRejectionReason reason,
            String message,
            Throwable cause) {

        super(message, cause);

        if (reason == null) {
            throw new IllegalArgumentException(
                    "Rejection reason is required");
        }

        this.reason = reason;
    }

    public ProtocolRejectionReason reason() {
        return reason;
    }
}
