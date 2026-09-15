package com.adaptpqc.session;

import java.time.Instant;
import java.util.UUID;

import com.adaptpqc.security.SecurityState;

public class SessionState {

    private final String sessionId;

    private long messageCount;

    private long keyGeneration;

    private Instant keyCreatedAt;

    private Instant lastRatchetAt;

    private SecurityState securityState;

    private double riskScore;


    public SessionState() {

        this.sessionId =
                UUID.randomUUID().toString();

        this.messageCount = 0;

        this.keyGeneration = 0;

        this.keyCreatedAt =
                Instant.now();

        this.lastRatchetAt =
                Instant.now();

        this.securityState =
                SecurityState.NORMAL;

        this.riskScore = 0.0;
    }


    public String getSessionId() {
        return sessionId;
    }


    public long getMessageCount() {
        return messageCount;
    }


    public void incrementMessageCount() {
        messageCount++;
    }


    public long getKeyGeneration() {
        return keyGeneration;
    }


    public void incrementKeyGeneration() {

        keyGeneration++;

        keyCreatedAt =
                Instant.now();

        lastRatchetAt =
                Instant.now();
    }


    public Instant getKeyCreatedAt() {
        return keyCreatedAt;
    }


    public Instant getLastRatchetAt() {
        return lastRatchetAt;
    }


    public SecurityState getSecurityState() {
        return securityState;
    }


    public void setSecurityState(
            SecurityState securityState) {

        this.securityState =
                securityState;
    }


    public double getRiskScore() {
        return riskScore;
    }


    public void setRiskScore(
            double riskScore) {

        if (riskScore < 0.0 ||
            riskScore > 1.0) {

            throw new IllegalArgumentException(
                    "Risk score must be between 0 and 1."
            );
        }

        this.riskScore =
                riskScore;
    }
}