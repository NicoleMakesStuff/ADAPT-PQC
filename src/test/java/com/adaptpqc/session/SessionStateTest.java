package com.adaptpqc.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

import com.adaptpqc.security.SecurityState;

class SessionStateTest {

    @Test
    void newSessionShouldStartInNormalState() {

        SessionState session =
                new SessionState();

        assertEquals(
                SecurityState.NORMAL,
                session.getSecurityState()
        );

        assertEquals(
                0,
                session.getMessageCount()
        );

        assertEquals(
                0,
                session.getKeyGeneration()
        );

        assertEquals(
                0.0,
                session.getRiskScore()
        );
    }


    @Test
    void messageCountShouldIncrease() {

        SessionState session =
                new SessionState();

        session.incrementMessageCount();
        session.incrementMessageCount();

        assertEquals(
                2,
                session.getMessageCount()
        );
    }


    @Test
    void keyGenerationShouldIncrease() {

        SessionState session =
                new SessionState();

        assertEquals(
                0,
                session.getKeyGeneration()
        );

        session.incrementKeyGeneration();

        assertEquals(
                1,
                session.getKeyGeneration()
        );
    }


    @Test
    void riskScoreShouldBeBetweenZeroAndOne() {

        SessionState session =
                new SessionState();

        session.setRiskScore(0.75);

        assertEquals(
                0.75,
                session.getRiskScore()
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> session.setRiskScore(1.5)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> session.setRiskScore(-0.1)
        );
    }
}