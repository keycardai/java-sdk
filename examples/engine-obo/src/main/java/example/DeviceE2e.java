package example;

import ai.keycard.oauth.AuthorizationCodeClient;
import ai.keycard.oauth.DeviceAuthorization;
import ai.keycard.oauth.DeviceAuthorizationClient;
import ai.keycard.oauth.FileTokenSource;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.TokenResponse;
import ai.keycard.oauth.WorkloadIdentity;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * device-authorization.md Integration Tests against a live zone, with the engine authenticating
 * by its v2 workload credential (a JWT-SVID assertion). Prints claims and codes only, never a
 * token.
 *
 * <p>{@code headless} runs the rows that need no person: an unknown resource (row 5) and a poll
 * from another client (row 4). {@code confirm} runs row 1 and row 6: it prints a user code,
 * waits while a person approves it, then refreshes for the second resource. {@code deny} runs row
 * 2, where the person denies.
 */
public final class DeviceE2e {

    private DeviceE2e() {}

    public static void main(String[] args) throws Exception {
        String mode = args.length > 0 ? args[0] : "headless";
        URI zone = Env.uri("KEYCARD_ZONE_URL");
        URI ledger = Env.uri("LEDGER_RESOURCE");
        URI gateway = Env.uri("GATEWAY_RESOURCE");
        WorkloadIdentity engine = WorkloadIdentity.builder(FileTokenSource.of(Path.of(Env.require("SVID_FILE"))))
                .clientId(Env.require("ENGINE_V2_CLIENT_ID"))
                .build();
        DeviceAuthorizationClient device =
                DeviceAuthorizationClient.builder(zone).credential(engine).build();
        List<String> failures = new ArrayList<>();

        switch (mode) {
            case "headless" -> {
                expectError(failures, "row 5: an unknown resource is invalid_target", "invalid_target", () ->
                        device.requestDeviceAuthorization(List.of(), List.of(URI.create("https://unregistered.java-sdk.test"))));

                DeviceAuthorization authorization = device.requestDeviceAuthorization(List.of(), List.of(ledger));
                System.out.println("  ok   device authorization as the engine: user_code=" + authorization.userCode()
                        + " interval=" + authorization.interval().toSeconds() + "s expires_in="
                        + authorization.expiresIn().toSeconds() + "s");
                expectError(failures, "pending before anyone confirms", "authorization_pending", () ->
                        device.pollOnce(authorization));
                WorkloadIdentity gatewayIdentity = WorkloadIdentity.builder(
                                FileTokenSource.of(Path.of(Env.require("GATEWAY_SVID_FILE"))))
                        .clientId(Env.require("GATEWAY_V2_CLIENT_ID"))
                        .build();
                DeviceAuthorizationClient other =
                        DeviceAuthorizationClient.builder(zone).credential(gatewayIdentity).build();
                expectError(failures, "row 4: a poll from another client is invalid_grant", "invalid_grant", () ->
                        other.pollOnce(authorization));
            }
            case "confirm" -> {
                DeviceAuthorization authorization =
                        device.requestDeviceAuthorization(List.of("openid"), List.of(ledger, gateway));
                show(authorization);
                TokenResponse token = device.pollUntilDone(authorization);
                Map<String, Object> claims = Env.claims(token.accessToken());
                Map<String, Object> id = token.idToken() == null ? Map.of() : Env.claims(token.idToken());
                boolean row1 = token.refreshToken() != null && id.get("sub") != null;
                report(failures, row1, "row 1: access token aud=" + claims.get("aud") + ", refresh_token "
                        + (token.refreshToken() == null ? "absent" : "present") + ", id_token sub=" + id.get("sub"));

                AuthorizationCodeClient refresher =
                        AuthorizationCodeClient.builder(zone).credential(engine).build();
                TokenResponse refreshed = refresher.refresh(token.refreshToken(), List.of(gateway), List.of());
                Object aud = Env.claims(refreshed.accessToken()).get("aud");
                report(failures, String.valueOf(aud).contains(gateway.toString()),
                        "row 6: refresh for the second resource gives aud=" + aud);
            }
            case "deny" -> {
                DeviceAuthorization authorization = device.requestDeviceAuthorization(List.of(), List.of(ledger));
                show(authorization);
                System.out.println("  (deny this one on the confirmation page)");
                expectError(failures, "row 2: the person denies", "access_denied", () -> device.pollUntilDone(authorization));
            }
            default -> throw new IllegalArgumentException("mode must be headless, confirm or deny");
        }

        System.out.println(failures.isEmpty() ? "ALL PASSED" : "FAILED: " + failures);
        System.exit(failures.isEmpty() ? 0 : 1);
    }

    private static void show(DeviceAuthorization authorization) {
        URI open = authorization.verificationUriComplete() != null
                ? authorization.verificationUriComplete()
                : authorization.verificationUri();
        System.out.println("  Open " + open);
        System.out.println("  and confirm the code " + authorization.userCode() + " (expires in "
                + authorization.expiresIn().toMinutes() + " minutes)");
        System.out.flush();
    }

    @FunctionalInterface
    private interface Call {
        Object run() throws Exception;
    }

    private static void expectError(List<String> failures, String name, String code, Call call) {
        try {
            call.run();
            report(failures, false, name + ": succeeded, expected " + code);
        } catch (OAuthErrorException e) {
            report(failures, e.error().equals(code), name + ": " + e.error());
        } catch (KeycardException e) {
            report(failures, false, name + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
        } catch (Exception e) {
            report(failures, false, name + ": " + e);
        }
    }

    private static void report(List<String> failures, boolean ok, String line) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + line);
        if (!ok) {
            failures.add(line);
        }
    }
}
