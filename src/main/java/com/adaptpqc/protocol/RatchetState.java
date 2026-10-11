
package com.adaptpqc.protocol;

public enum RatchetState {
    IDLE,
    OFFER_PREPARED,
    OFFER_RECEIVED,
    KEY_UPDATED,
    CONFIRMED,
    ABORTED
}
