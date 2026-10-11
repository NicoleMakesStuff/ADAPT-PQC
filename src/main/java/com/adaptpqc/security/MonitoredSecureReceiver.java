package com.adaptpqc.security;

import java.security.GeneralSecurityException;
import java.util.Objects;

import com.adaptpqc.protocol.v2.ProtocolRejectionException;
import com.adaptpqc.protocol.v2.SecureMessage;
import com.adaptpqc.protocol.v2.SecureMessageService;
import com.adaptpqc.ratchet.RatchetController;
import com.adaptpqc.ratchet.RatchetDecision;
import com.adaptpqc.session.SessionState;

/**
 * Connects the receiving side of the protocol to the risk engine.
 *
 * Every rejected message produces exactly one security event, and
 * every attempt ends with a ratchet recommendation from the
 * controller. This class only recommends. It never rotates keys.
 */
public final class MonitoredSecureReceiver {

    private final SecureMessageService service;
    private final SessionState sessionState;
    private final SecurityMonitor monitor;
    private final RatchetController controller;

    public MonitoredSecureReceiver(
            SecureMessageService service,
            SessionState sessionState,
            SecurityMonitor monitor,
            RatchetController controller) {

        this.service = Objects.requireNonNull(service);
        this.sessionState = Objects.requireNonNull(sessionState);
        this.monitor = Objects.requireNonNull(monitor);
        this.controller = Objects.requireNonNull(controller);
    }

    public synchronized ReceiveResult receive(SecureMessage message)
            throws GeneralSecurityException {

        long start = System.nanoTime();

        try {
            String plaintext = service.decrypt(message);

            sessionState.incrementMessageCount();

            return new ReceiveResult(
                    true,
                    plaintext,
                    null,
                    null,
                    controller.evaluate(sessionState),
                    System.nanoTime() - start);

        } catch (ProtocolRejectionException rejection) {

            SecurityEvent event =
                    RejectionEventMapper.toEvent(rejection.reason());

            monitor.recordEvent(event);

            RatchetDecision decision =
                    controller.evaluate(sessionState);

            return new ReceiveResult(
                    false,
                    null,
                    rejection.reason(),
                    event.getType(),
                    decision,
                    System.nanoTime() - start);
        }
    }
}
