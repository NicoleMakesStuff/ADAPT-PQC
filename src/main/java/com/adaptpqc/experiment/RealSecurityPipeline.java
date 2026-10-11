
package com.adaptpqc.experiment;

import java.util.Objects;

import com.adaptpqc.attack.AttackResult;
import com.adaptpqc.ratchet.RatchetController;
import com.adaptpqc.ratchet.RatchetDecision;
import com.adaptpqc.security.SecurityEvent;
import com.adaptpqc.security.SecurityMonitor;
import com.adaptpqc.session.SessionState;

public final class RealSecurityPipeline
        implements AttackExperimentRunner.SecurityPipeline {

    private final SessionState sessionState;
    private final SecurityMonitor securityMonitor;
    private final RatchetController ratchetController;

    private boolean lastEventProcessed;

    public RealSecurityPipeline() {
        this(new SessionState());
    }

    public RealSecurityPipeline(SessionState sessionState) {
        this.sessionState = Objects.requireNonNull(sessionState);
        this.securityMonitor = new SecurityMonitor(sessionState);
        this.ratchetController = new RatchetController();
    }

    @Override
    public synchronized double currentRiskScore() {
        return securityMonitor.getCurrentRisk();
    }

    @Override
    public synchronized String currentSecurityState() {
        return securityMonitor.getCurrentState().name();
    }

    @Override
    public synchronized String evaluateRatchetDecision() {
        RatchetDecision decision =
                ratchetController.evaluate(sessionState);

        return decision.name();
    }

    @Override
    public synchronized boolean process(AttackResult attack) {
        Objects.requireNonNull(attack, "Attack result is required");

        SecurityEvent event = attack.event();

        securityMonitor.recordEvent(event);
        lastEventProcessed = true;

        return lastEventProcessed;
    }

    public synchronized int eventCount() {
        return securityMonitor.getEventCount();
    }

    public synchronized boolean wasEventProcessed() {
        return lastEventProcessed;
    }

    public SessionState sessionState() {
        return sessionState;
    }

    public SecurityMonitor securityMonitor() {
        return securityMonitor;
    }
}
