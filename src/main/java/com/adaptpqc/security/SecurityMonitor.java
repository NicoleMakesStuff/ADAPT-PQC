
package com.adaptpqc.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.adaptpqc.session.SessionState;

public class SecurityMonitor {

    private final RiskEngine riskEngine;
    private final SessionState sessionState;
    private final List<SecurityEvent> events;

    public SecurityMonitor(SessionState sessionState) {
        if (sessionState == null) {
            throw new IllegalArgumentException(
                    "Session state cannot be null."
            );
        }

        this.sessionState = sessionState;
        this.riskEngine = new RiskEngine();
        this.events = new ArrayList<>();
    }

    /**
     * Records an event, updates the risk score,
     * and updates the session's security state.
     */
    public synchronized void recordEvent(SecurityEvent event) {
        if (event == null) {
            throw new IllegalArgumentException(
                    "Security event cannot be null."
            );
        }

        double updatedRisk = riskEngine.calculateRisk(
                sessionState.getRiskScore(),
                event
        );

        events.add(event);

        sessionState.setRiskScore(updatedRisk);
        sessionState.setSecurityState(
                riskEngine.determineState(updatedRisk)
        );
    }

    /**
     * Applies one risk-decay step.
     */
    public synchronized void decayRisk() {
        double updatedRisk = riskEngine.decayRisk(
                sessionState.getRiskScore()
        );

        sessionState.setRiskScore(updatedRisk);
        sessionState.setSecurityState(
                riskEngine.determineState(updatedRisk)
        );
    }

    public synchronized List<SecurityEvent> getEvents() {
        return Collections.unmodifiableList(
                new ArrayList<>(events)
        );
    }

    public synchronized int getEventCount() {
        return events.size();
    }

    public synchronized double getCurrentRisk() {
        return sessionState.getRiskScore();
    }

    public synchronized SecurityState getCurrentState() {
        return sessionState.getSecurityState();
    }
}
