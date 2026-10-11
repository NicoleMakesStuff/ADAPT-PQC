package com.adaptpqc.security;

import com.adaptpqc.protocol.v2.ProtocolRejectionReason;
import com.adaptpqc.ratchet.RatchetDecision;

public record ReceiveResult(
        boolean accepted,
        String plaintext,
        ProtocolRejectionReason rejectionReason,
        SecurityEventType eventType,
        RatchetDecision ratchetDecision,
        long processingNanos
) {
}
