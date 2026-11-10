package ai.keycard.oauth;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.function.Supplier;

/**
 * Runs at most one fetch per key at a time; concurrent callers for the key wait for it and share
 * its outcome. If the thread running the fetch is interrupted, waiters start a fresh fetch rather
 * than inheriting that caller's cancellation (base.md: one caller's cancellation MUST NOT poison a
 * shared fetch).
 *
 * <p>The fetching thread signals interruption the way the transport does: a {@link
 * KeycardException} whose cause is an {@link InterruptedException}.
 */
final class SingleFlight<K, V> {

    private final ConcurrentHashMap<K, CompletableFuture<V>> inFlight = new ConcurrentHashMap<>();

    /**
     * Returns {@code fetch}'s result for {@code key}, sharing one run among concurrent callers.
     *
     * @param waitingFor names the work in the exception an interrupted waiter gets
     */
    V run(K key, Supplier<V> fetch, String waitingFor) {
        while (true) {
            CompletableFuture<V> mine = new CompletableFuture<>();
            CompletableFuture<V> shared = inFlight.putIfAbsent(key, mine);
            if (shared == null) {
                return lead(key, fetch, mine);
            }
            try {
                return shared.get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new NetworkException("interrupted while waiting for " + waitingFor, e);
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof FetcherInterrupted) {
                    inFlight.remove(key, shared);
                    continue;
                }
                if (cause instanceof RuntimeException runtime) {
                    throw runtime;
                }
                if (cause instanceof Error error) {
                    throw error;
                }
                throw new KeycardException(waitingFor + " failed", cause);
            }
        }
    }

    /** Forgets any fetch in flight for {@code key}; callers already waiting still get its result. */
    void forget(K key) {
        inFlight.remove(key);
    }

    /** Forgets every fetch in flight. */
    void forgetAll() {
        inFlight.clear();
    }

    private V lead(K key, Supplier<V> fetch, CompletableFuture<V> mine) {
        try {
            V value = fetch.get();
            mine.complete(value);
            return value;
        } catch (KeycardException e) {
            mine.completeExceptionally(e.getCause() instanceof InterruptedException ? new FetcherInterrupted() : e);
            throw e;
        } catch (RuntimeException | Error e) {
            mine.completeExceptionally(e);
            throw e;
        } finally {
            inFlight.remove(key, mine);
        }
    }

    /** Marks a shared fetch that ended because its own thread was interrupted. */
    private static final class FetcherInterrupted extends RuntimeException {

        private static final long serialVersionUID = 1L;

        FetcherInterrupted() {
            super(null, null, false, false);
        }
    }
}
