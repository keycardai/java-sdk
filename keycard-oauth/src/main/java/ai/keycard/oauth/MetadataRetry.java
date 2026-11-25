package ai.keycard.oauth;

import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.util.Locale;
import java.util.concurrent.ThreadLocalRandom;
import org.jspecify.annotations.Nullable;

record MetadataRetry(KeycardException failure, Instant until, long nextMillis) {

    private static final DateTimeFormatter ASCTIME = DateTimeFormatter.ofPattern("MMM d HH:mm:ss uuuu", Locale.US);

    static void check(@Nullable MetadataRetry retry, Instant now) {
        if (retry != null && now.isBefore(retry.until)) {
            throw retry.failure;
        }
    }

    static @Nullable MetadataRetry after(@Nullable MetadataRetry previous, Instant now, KeycardException failure) {
        if (!failure.retryable() || failure.getCause() instanceof InterruptedException) {
            return previous;
        }
        Throwable cause = failure instanceof JwksException.Fetch ? failure.getCause() : failure;
        long next = previous == null ? 1_000 : previous.nextMillis;
        if (cause instanceof HttpStatusException status && (status.status() == 429 || status.status() == 503)) {
            Duration delay = retryAfter(now, status.retryAfter());
            if (delay != null) {
                return new MetadataRetry(failure, now.plus(delay), next);
            }
            if (status.status() == 429) {
                return previous;
            }
        }
        long delay = Math.min(30_000, (long) (next * ThreadLocalRandom.current().nextDouble(0.8, 1.2)));
        return new MetadataRetry(failure, now.plusMillis(delay), Math.min(64_000, next * 2));
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
        if (header.matches("[A-Za-z]{6,9}, [0-9]{2}-[A-Za-z]{3}-[0-9]{2} [0-9:]{8} GMT")) {
            ZonedDateTime latest = now.atZone(ZoneOffset.UTC).plusYears(50);
            DateTimeFormatter rfc850 = new DateTimeFormatterBuilder()
                    .appendPattern("dd-MMM-")
                    .appendValueReduced(ChronoField.YEAR, 2, 2, latest.getYear() - 99)
                    .appendPattern(" HH:mm:ss 'GMT'")
                    .toFormatter(Locale.US);
            LocalDateTime date = LocalDateTime.parse(header.substring(header.indexOf(',') + 2), rfc850);
            return (date.isAfter(latest.toLocalDateTime()) ? date.minusYears(100) : date).toInstant(ZoneOffset.UTC);
        }
        if (header.matches("[A-Za-z]{3} [A-Za-z]{3} [ 0-9][0-9] [0-9:]{8} [0-9]{4}")) {
            return LocalDateTime.parse(header.substring(4).replace("  ", " "), ASCTIME)
                    .toInstant(ZoneOffset.UTC);
        }
        return ZonedDateTime.parse(header, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
    }
}
