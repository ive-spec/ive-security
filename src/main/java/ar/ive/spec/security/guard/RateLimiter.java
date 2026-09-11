package ar.ive.spec.security.guard;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * THE USAGE LIMIT OF {@code rateLimit}, counted per origin. It does not
 * depend on the identity: not authenticating and not limiting are two
 * different things, and only one needs identity infrastructure.
 *
 * <p>THE WINDOW SLIDES, it is not a clock minute: with fixed windows,
 * whoever sends twice the limit right at the edge gets through (N at the
 * end of one minute and N at the start of the next are 2N in two
 * seconds).</p>
 *
 * <p>IN MEMORY AND PER PROCESS. With several instances each one keeps its
 * own count; then the limit moves to the front and this one is turned off
 * with {@code maxPerMinute <= 0}. Said here instead of left for someone
 * to discover. A rejection is thrown with
 * {@link SecurityFailures#tooManyRequests}.</p>
 */
public final class RateLimiter {

    /**
     * @param allowed           whether the call may go on
     * @param retryAfterSeconds seconds until there is room again (what the 429 communicates)
     */
    public record Verdict(boolean allowed, long retryAfterSeconds) { }

    private static final long WINDOW_MS = 60_000L;
    private static final int CLEANUP_ABOVE = 10_000;

    private final int maxPerMinute;
    private final LongSupplier nowMillis;
    private final Map<String, Deque<Long>> byOrigin = new HashMap<>();

    public RateLimiter(int maxPerMinute) {
        this(maxPerMinute, System::currentTimeMillis);
    }

    /** With a clock of one's own (tests). */
    public RateLimiter(int maxPerMinute, LongSupplier nowMillis) {
        this.maxPerMinute = maxPerMinute;
        this.nowMillis = nowMillis;
    }

    /** Counts one call from {@code origin}, or says when there is room again. */
    public synchronized Verdict check(String origin) {
        if (maxPerMinute <= 0) {
            return new Verdict(true, 0);
        }
        long now = nowMillis.getAsLong();
        long since = now - WINDOW_MS;
        Deque<Long> marks = byOrigin.computeIfAbsent(origin, key -> new ArrayDeque<>());
        while (!marks.isEmpty() && marks.peekFirst() <= since) {
            marks.pollFirst();
        }
        if (marks.size() >= maxPerMinute) {
            long wait = (marks.peekFirst() + WINDOW_MS - now + 999) / 1000;
            return new Verdict(false, Math.max(1, wait));
        }
        marks.addLast(now);
        // THE TABLE CLEANS ITSELF: an origin that called once and never
        // came back would otherwise stay in memory forever.
        if (byOrigin.size() > CLEANUP_ABOVE) {
            for (Iterator<Deque<Long>> it = byOrigin.values().iterator(); it.hasNext(); ) {
                Deque<Long> other = it.next();
                if (other.isEmpty() || other.peekLast() <= since) {
                    it.remove();
                }
            }
        }
        return new Verdict(true, 0);
    }
}
