package ai.keycard.oauth.testing;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * A clock tests move by hand, for TTL and expiry behavior without real waits. Safe to read from
 * many threads.
 */
public final class TestClock extends Clock {

    private volatile Instant now;

    /**
     * A clock at a fixed, arbitrary instant.
     *
     * @return the clock
     */
    public static TestClock start() {
        return new TestClock(Instant.parse("2026-11-10T12:00:00Z"));
    }

    private TestClock(Instant now) {
        this.now = now;
    }

    /**
     * Moves the clock forward.
     *
     * @param duration how far to move
     */
    public void advance(Duration duration) {
        now = now.plus(duration);
    }

    @Override
    public Instant instant() {
        return now;
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        throw new UnsupportedOperationException("TestClock is UTC only");
    }
}
