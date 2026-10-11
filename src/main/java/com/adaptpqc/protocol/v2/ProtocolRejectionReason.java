package com.adaptpqc.protocol.v2;

/**
 * The specific reason a received message was rejected.
 *
 * The receiver records exactly one reason per rejected attempt so
 * callers can map it to a security event without guessing from
 * exception text.
 */
public enum ProtocolRejectionReason {

    NULL_MESSAGE,

    WRONG_SESSION,

    WRONG_GENERATION,

    REPLAY_OR_OUT_OF_ORDER,

    AUTHENTICATION_FAILED,

    DECRYPTION_FAILED
}
