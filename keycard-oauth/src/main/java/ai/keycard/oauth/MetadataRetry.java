package ai.keycard.oauth;

import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.ResolverStyle;
import java.time.temporal.ChronoField;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.LongSupplier;
import org.jspecify.annotations.Nullable;

record MetadataRetry(KeycardException failure, long until, long nextMillis) {

    private static final DateTimeFormatter IMF = formatter("EEE, dd MMM uuuu HH:mm:ss 'GMT'");
    private static final DateTimeFormatter ASCTIME = formatter("EEE MMM d HH:mm:ss uuuu");
    private static final DateTimeFormatter WEEKDAY = formatter("EEEE");

    private static DateTimeFormatter formatter(String pattern) {
        return DateTimeFormatter.ofPattern(pattern, Locale.US).withResolverStyle(ResolverStyle.STRICT);
    }

    static LongSupplier ticker(Clock clock) {
        return Clock.systemUTC().equals(clock) ? System::nanoTime : () -> clock.millis() * 1_000_000;
    }

    static void check(@Nullable MetadataRetry retry, long now) {
        if (retry != null && now - retry.until < 0) {
            throw retry.failure;
        }
    }

    static @Nullable MetadataRetry after(
            @Nullable MetadataRetry previous, long now, Instant wallTime, KeycardException failure) {
        if (!failure.retryable() || failure.getCause() instanceof InterruptedException) {
            return previous;
        }
        Throwable cause = failure instanceof JwksException.Fetch ? failure.getCause() : failure;
        int status = 0;
        String retryAfterHeader = null;
        if (cause instanceof HttpStatusException http) {
            status = http.status();
            retryAfterHeader = http.retryAfter();
        } else if (cause instanceof ResponseBodyTooLargeException oversized) {
            status = oversized.status();
            retryAfterHeader = oversized.retryAfter();
        }
        if (status >= 200 && status < 300) {
            return previous;
        }
        long next = previous == null ? 1_000 : previous.nextMillis;
        if (status == 429 || status == 503) {
            Duration delay = retryAfter(wallTime, retryAfterHeader);
            if (delay != null) {
                return new MetadataRetry(failure, now + delay.toNanos(), next);
            }
            if (status == 429) {
                return previous;
            }
        }
        long delay = Math.min(30_000, (long) (next * ThreadLocalRandom.current().nextDouble(0.8, 1.2)));
        return new MetadataRetry(failure, now + delay * 1_000_000, Math.min(64_000, next * 2));
    }

    private static @Nullable Duration retryAfter(Instant now, @Nullable String value) {
        if (value == null) {
            return null;
        }
        String header = value.strip();
        if (header.matches("[0-9]+")) {
            String significant = header.replaceFirst("^0+(?!$)", "");
            return Duration.ofSeconds(significant.length() > 2 ? 60 : Math.min(60, Integer.parseInt(significant)));
        }
        try {
            Duration delay = Duration.between(now, httpDate(now, header));
            return delay.isNegative()
                    ? Duration.ZERO
                    : (delay.compareTo(Duration.ofSeconds(60)) > 0 ? Duration.ofSeconds(60) : delay);
        } catch (DateTimeException e) {
            return null;
        }
    }

    private static Instant httpDate(Instant now, String header) {
        if (header.matches("[A-Za-z]+, [0-9]{2}-[A-Za-z]{3}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT")) {
            ZonedDateTime latest = now.atZone(ZoneOffset.UTC).plusYears(50);
            DateTimeFormatter rfc850 = new DateTimeFormatterBuilder()
                    .appendPattern("dd-MMM-")
                    .appendValueReduced(ChronoField.YEAR, 2, 2, latest.getYear() - 99)
                    .appendPattern(" HH:mm:ss 'GMT'")
                    .toFormatter(Locale.US)
                    .withResolverStyle(ResolverStyle.STRICT);
            LocalDateTime date = LocalDateTime.parse(header.substring(header.indexOf(',') + 2), rfc850);
            if (date.isAfter(latest.toLocalDateTime())) {
                date = date.minusYears(100);
            }
            if (header.startsWith(WEEKDAY.format(date) + ", ")) {
                return date.toInstant(ZoneOffset.UTC);
            }
            throw new DateTimeException("invalid HTTP-date weekday");
        }
        if (header.matches("[A-Za-z]{3} [A-Za-z]{3} (?: [1-9]|[0-9]{2}) [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}")) {
            return LocalDateTime.parse(header.replace("  ", " "), ASCTIME).toInstant(ZoneOffset.UTC);
        }
        if (header.matches("[A-Za-z]{3}, [0-9]{2} [A-Za-z]{3} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT")) {
            return LocalDateTime.parse(header, IMF).toInstant(ZoneOffset.UTC);
        }
        throw new DateTimeException("invalid HTTP-date");
    }

    static final class Cache<K> {
        private static final int MAX_ENTRIES = 128;
        private final LinkedHashMap<K, MetadataRetry> entries = new LinkedHashMap<>();

        synchronized void check(K key, long now) {
            MetadataRetry.check(entries.get(key), now);
        }

        synchronized void record(K key, long now, Instant wallTime, KeycardException error) {
            MetadataRetry previous = entries.get(key);
            MetadataRetry retry = after(previous, now, wallTime, error);
            if (retry != null && retry != previous) {
                entries.remove(key);
                entries.put(key, retry);
                if (entries.size() > MAX_ENTRIES) {
                    entries.remove(entries.keySet().iterator().next());
                }
            }
        }

        synchronized void remove(K key) {
            entries.remove(key);
        }

        synchronized void clear() {
            entries.clear();
        }
    }
}
