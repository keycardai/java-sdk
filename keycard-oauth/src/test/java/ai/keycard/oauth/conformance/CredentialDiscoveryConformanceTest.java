package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.CredentialDiscovery;
import ai.keycard.oauth.CredentialDiscoveryException;
import ai.keycard.oauth.CredentialDiscoveryException.Reason;
import ai.keycard.oauth.FileTokenSource;
import ai.keycard.oauth.WebIdentity;
import ai.keycard.oauth.WorkloadIdentity;
import ai.keycard.oauth.WorkloadIdentityConfigurationException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** credential-discovery.md (spec-version 2), Unit Tests table, rows 1 to 22. */
class CredentialDiscoveryConformanceTest {

    @TempDir
    Path dir;

    @Test
    @DisplayName("row 1: client id and secret build a ClientSecret")
    void row1() {
        Credential credential = discover(env("KEYCARD_CLIENT_ID", "cid", "KEYCARD_CLIENT_SECRET", "sec"));
        assertThat(credential)
                .isInstanceOfSatisfying(
                        ClientSecret.class,
                        c -> assertThat(c.clientId(URI.create("https://z"))).isEqualTo("cid"));
    }

    @Test
    @DisplayName("row 2: each token-file variable alone builds a WorkloadIdentity without a client id")
    void row2() throws Exception {
        for (String variable : FileTokenSource.DISCOVERY_VARIABLES) {
            Credential credential = discover(env(variable, tokenFile("t").toString()));
            assertThat(credential)
                    .as(variable)
                    .isInstanceOfSatisfying(
                            WorkloadIdentity.class,
                            w -> assertThat(w.clientId()).isNull());
        }
    }

    @Test
    @DisplayName("row 3: an empty environment is absent")
    void row3() {
        assertReason(env(), Reason.ABSENT);
    }

    @Test
    @DisplayName("row 4: a secret without an id is incomplete")
    void row4() {
        assertReason(env("KEYCARD_CLIENT_SECRET", "sec"), Reason.INCOMPLETE);
    }

    @Test
    @DisplayName("row 5: a client secret and a token file are ambiguous, naming both")
    void row5() throws Exception {
        CredentialDiscoveryException e = assertReason(
                env(
                        "KEYCARD_CLIENT_ID",
                        "cid",
                        "KEYCARD_CLIENT_SECRET",
                        "sec",
                        "AWS_WEB_IDENTITY_TOKEN_FILE",
                        tokenFile("t").toString()),
                Reason.AMBIGUOUS);
        assertThat(e.resolvable()).containsExactly("client_secret", "workload_identity");
        assertThat(e.getMessage()).contains("KEYCARD_APPLICATION_CREDENTIAL_TYPE");
    }

    @Test
    @DisplayName("row 6: the selector picks among all three, and the legacy alias builds workload identity")
    void row6() throws Exception {
        Map<String, String> all = env(
                "KEYCARD_CLIENT_ID",
                "cid",
                "KEYCARD_CLIENT_SECRET",
                "sec",
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                tokenFile("t").toString(),
                "KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR",
                dir.toString());
        assertThat(discover(with(all, "client_secret"))).isInstanceOf(ClientSecret.class);
        assertThat(discover(with(all, "workload_identity"))).isInstanceOf(WorkloadIdentity.class);
        assertThat(discover(with(all, "eks_workload_identity"))).isInstanceOf(WorkloadIdentity.class);
        assertThat(discover(with(all, "web_identity"))).isInstanceOf(WebIdentity.class);
    }

    @Test
    @DisplayName("row 7: an unknown selector is unknown_type, listing the canonical values")
    void row7() {
        CredentialDiscoveryException e =
                assertReason(env("KEYCARD_APPLICATION_CREDENTIAL_TYPE", "magic"), Reason.UNKNOWN_TYPE);
        assertThat(e.getMessage())
                .contains("client_secret")
                .contains("workload_identity")
                .contains("web_identity");
    }

    @Test
    @DisplayName("row 8: the unknown-type check runs before any other")
    void row8() {
        assertReason(
                env(
                        "KEYCARD_APPLICATION_CREDENTIAL_TYPE",
                        "magic",
                        "KEYCARD_CLIENT_ID",
                        "cid",
                        "KEYCARD_CLIENT_SECRET",
                        "sec"),
                Reason.UNKNOWN_TYPE);
    }

    @Test
    @DisplayName("row 9: selecting client_secret without the secret is not satisfiable")
    void row9() {
        assertReason(
                env("KEYCARD_APPLICATION_CREDENTIAL_TYPE", "client_secret", "KEYCARD_CLIENT_ID", "cid"),
                Reason.NOT_SATISFIABLE);
    }

    @Test
    @DisplayName("row 10: selecting workload_identity without a token file is not satisfiable")
    void row10() {
        assertReason(env("KEYCARD_APPLICATION_CREDENTIAL_TYPE", "workload_identity"), Reason.NOT_SATISFIABLE);
    }

    @Test
    @DisplayName("row 11: a token file plus a client id alone attaches the id to the workload identity")
    void row11() throws Exception {
        Credential credential =
                discover(env("AZURE_FEDERATED_TOKEN_FILE", tokenFile("t").toString(), "KEYCARD_CLIENT_ID", "cid"));
        assertThat(credential)
                .isInstanceOfSatisfying(
                        WorkloadIdentity.class, w -> assertThat(w.clientId()).isEqualTo("cid"));
    }

    @Test
    @DisplayName("row 12: a client id alone is absent")
    void row12() {
        assertReason(env("KEYCARD_CLIENT_ID", "cid"), Reason.ABSENT);
    }

    @Test
    @DisplayName("row 13: with several token files, the first in discovery order wins")
    void row13() throws Exception {
        Path keycard = tokenFile("keycard");
        Path aws = tokenFile("aws");
        Credential credential = discover(env(
                "KEYCARD_APPLICATION_CREDENTIAL_TYPE", "eks_workload_identity",
                "AWS_WEB_IDENTITY_TOKEN_FILE", aws.toString(),
                "KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE", keycard.toString()));
        assertThat(credential.toString()).contains(keycard.toString()).doesNotContain(aws.toString());
    }

    @Test
    @DisplayName("row 14: a missing token file is the workload-identity configuration error")
    void row14() {
        assertThatThrownBy(() -> discover(
                        env("AWS_WEB_IDENTITY_TOKEN_FILE", dir.resolve("nope").toString())))
                .isInstanceOf(WorkloadIdentityConfigurationException.class)
                .isNotInstanceOf(CredentialDiscoveryException.class);
    }

    @Test
    @DisplayName("row 15: discovery reads the mapping it's given, not the process environment")
    void row15() {
        assertReason(Map.of(), Reason.ABSENT);
    }

    @Test
    @DisplayName("row 16: the storage directory builds a WebIdentity named after the server")
    void row16() throws Exception {
        Credential credential = CredentialDiscovery.discover(
                env("KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR", dir.toString()), "Payments API");
        assertThat(credential).isInstanceOfSatisfying(WebIdentity.class, w -> {
            assertThat(w.keyId()).isEqualTo("payments-api");
            w.publicJwks();
        });
        assertThat(dir.resolve("payments-api.pem")).exists();
    }

    @Test
    @DisplayName("row 17: the server name is optional")
    void row17() {
        assertThat(discover(env("KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR", dir.toString())))
                .isInstanceOf(WebIdentity.class);
    }

    @Test
    @DisplayName("row 18: a client secret and a storage directory are ambiguous")
    void row18() {
        CredentialDiscoveryException e = assertReason(
                env(
                        "KEYCARD_CLIENT_ID",
                        "cid",
                        "KEYCARD_CLIENT_SECRET",
                        "sec",
                        "KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR",
                        dir.toString()),
                Reason.AMBIGUOUS);
        assertThat(e.resolvable()).containsExactly("client_secret", "web_identity");
    }

    @Test
    @DisplayName("row 19: a token file and a storage directory are ambiguous")
    void row19() throws Exception {
        CredentialDiscoveryException e = assertReason(
                env(
                        "AWS_WEB_IDENTITY_TOKEN_FILE",
                        tokenFile("t").toString(),
                        "KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR",
                        dir.toString()),
                Reason.AMBIGUOUS);
        assertThat(e.resolvable()).containsExactly("workload_identity", "web_identity");
    }

    @Test
    @DisplayName("row 20: selecting web_identity without a directory uses the default storage")
    void row20() {
        Credential credential = discover(env("KEYCARD_APPLICATION_CREDENTIAL_TYPE", "web_identity"));
        assertThat(credential).isInstanceOf(WebIdentity.class);
        assertThat(credential.toString()).contains("server_keys");
    }

    @Test
    @DisplayName("row 21: a mapping holding only the storage directory builds a WebIdentity over it")
    void row21() {
        Credential credential = discover(env("KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR", dir.toString()));
        assertThat(credential.toString()).contains(dir.toString());
    }

    @Test
    @DisplayName("row 22: an empty mapping is absent")
    void row22() {
        CredentialDiscoveryException e = assertReason(new HashMap<>(), Reason.ABSENT);
        assertThat(e.resolvable()).isEmpty();
        assertThat(e.retryable()).isFalse();
    }

    @Test
    @DisplayName("empty strings count as unset")
    void emptyIsUnset() {
        assertReason(env("KEYCARD_CLIENT_ID", "", "KEYCARD_CLIENT_SECRET", ""), Reason.ABSENT);
    }

    private static Credential discover(Map<String, String> environment) {
        return CredentialDiscovery.discover(environment);
    }

    private static CredentialDiscoveryException assertReason(Map<String, String> environment, Reason reason) {
        try {
            discover(environment);
        } catch (CredentialDiscoveryException e) {
            assertThat(e.reason()).isEqualTo(reason);
            return e;
        }
        throw new AssertionError("expected a discovery error with reason " + reason);
    }

    private Path tokenFile(String name) throws Exception {
        Path file = dir.resolve(name + ".jwt");
        Files.writeString(file, "header.payload.signature");
        return file;
    }

    private static Map<String, String> env(String... keysAndValues) {
        Map<String, String> env = new HashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            env.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return env;
    }

    private static Map<String, String> with(Map<String, String> base, String selector) {
        Map<String, String> env = new HashMap<>(base);
        env.put("KEYCARD_APPLICATION_CREDENTIAL_TYPE", selector);
        return env;
    }
}
