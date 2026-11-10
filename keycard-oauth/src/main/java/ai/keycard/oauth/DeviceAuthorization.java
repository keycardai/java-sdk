package ai.keycard.oauth;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * A device authorization response (RFC 8628 §3.2): the code the device polls with, and what the
 * person is shown. A plain value, so a caller may persist its fields and poll from another
 * process that authenticates as the same client.
 *
 * <p>Show the person {@link #verificationUriComplete()} when present, {@link #verificationUri()}
 * otherwise, and always {@link #userCode()} so they can compare it with the confirmation page.
 * Never show {@link #deviceCode()}.
 *
 * @param deviceCode the code the device polls with
 * @param userCode the code the person confirms
 * @param verificationUri where the person enters the user code
 * @param verificationUriComplete the verification URI with the user code filled in, or {@code
 *     null}
 * @param expiresIn the lifetime of both codes
 * @param interval the minimum wait between polls; 5 seconds when the response omits it
 * @param expiresAt when the codes expire: the time the response arrived plus {@code expiresIn}
 */
public record DeviceAuthorization(
        String deviceCode,
        String userCode,
        URI verificationUri,
        @Nullable URI verificationUriComplete,
        Duration expiresIn,
        Duration interval,
        Instant expiresAt) {

    /** The interval RFC 8628 §3.2 assumes when the response omits one. */
    public static final Duration DEFAULT_INTERVAL = Duration.ofSeconds(5);

    /**
     * Checks the fields.
     *
     * @param deviceCode the code the device polls with
     * @param userCode the code the person confirms
     * @param verificationUri where the person enters the user code
     * @param verificationUriComplete the prefilled verification URI, or {@code null}
     * @param expiresIn the lifetime of both codes
     * @param interval the minimum wait between polls
     * @param expiresAt when the codes expire
     * @throws ConfigurationException when a code is empty or a duration isn't positive
     */
    public DeviceAuthorization {
        Objects.requireNonNull(deviceCode, "deviceCode");
        Objects.requireNonNull(userCode, "userCode");
        Objects.requireNonNull(verificationUri, "verificationUri");
        Objects.requireNonNull(expiresIn, "expiresIn");
        Objects.requireNonNull(interval, "interval");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (deviceCode.isEmpty() || userCode.isEmpty()) {
            throw new ConfigurationException("deviceCode and userCode must not be empty");
        }
        if (interval.isNegative() || interval.isZero()) {
            throw new ConfigurationException("interval must be positive, got " + interval);
        }
    }

    /**
     * Names the user code and URIs, never the device code.
     *
     * @return a description without the device code
     */
    @Override
    public String toString() {
        return "DeviceAuthorization[userCode=" + userCode + ", verificationUri=" + verificationUri
                + ", verificationUriComplete=" + verificationUriComplete + ", interval=" + interval
                + ", expiresAt=" + expiresAt + "]";
    }
}
