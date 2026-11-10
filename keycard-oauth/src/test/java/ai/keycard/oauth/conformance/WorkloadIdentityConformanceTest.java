package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ClientAuthentication;
import ai.keycard.oauth.ClientCredentialsClient;
import ai.keycard.oauth.FileTokenSource;
import ai.keycard.oauth.GcpMetadataTokenSource;
import ai.keycard.oauth.HttpStatusException;
import ai.keycard.oauth.NetworkException;
import ai.keycard.oauth.TokenExchangeContext;
import ai.keycard.oauth.TokenExchangeRequest;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.WorkloadIdentity;
import ai.keycard.oauth.WorkloadIdentityConfigurationException;
import ai.keycard.oauth.WorkloadIdentityRuntimeException;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.StubZone.StubResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * workload-identity.md (spec-version 2), Unit Tests table. Rows 9 ({@code FlyTokenSource}) and 10
 * (the deprecated EKS constructors) have no Java counterpart by design: Java ships neither (see
 * docs/idiom-profile.md and the plan's out-of-scope list).
 */
class WorkloadIdentityConformanceTest {

    private static final URI ISSUER = URI.create("https://acme.keycard.cloud");
    private static final URI TOKEN = URI.create("https://acme.keycard.cloud/oauth/token");

    @TempDir
    Path dir;

    @Test
    @DisplayName("row 1: the prepared request carries the source token as a jwt-bearer assertion, no Basic")
    void row1() {
        URI resource = URI.create("https://api.example.com");
        TokenExchangeRequest request = WorkloadIdentity.of(() -> "platform.jwt.token")
                .prepareTokenExchangeRequest(TokenExchangeContext.of("subject", resource, ISSUER));

        assertThat(request.clientAssertion()).isEqualTo("platform.jwt.token");
        assertThat(request.clientAssertionType()).isEqualTo(TokenTypes.JWT_BEARER_ASSERTION);
        assertThat(request.subjectTokenType()).isEqualTo(TokenTypes.ACCESS_TOKEN);
        assertThat(request.subjectToken()).isEqualTo("subject");
        assertThat(request.resource()).isEqualTo(resource);
        assertThat(WorkloadIdentity.of(() -> "t").authenticate(ISSUER, TOKEN).headers())
                .isEmpty();
    }

    @Test
    @DisplayName("row 2: a changed source token is used on the next request; nothing is cached")
    void row2() throws IOException {
        Path file = write("first-token");
        WorkloadIdentity credential = WorkloadIdentity.of(FileTokenSource.of(file));

        assertThat(prepare(credential).clientAssertion()).isEqualTo("first-token");
        Files.writeString(file, "second-token\n");
        assertThat(prepare(credential).clientAssertion()).isEqualTo("second-token");
        assertThat(credential.authenticate(ISSUER, TOKEN).formFields())
                .containsEntry("client_assertion", "second-token");
    }

    @Test
    @DisplayName("row 3: a source failure is a runtime error carrying the source identifier and cause")
    void row3() throws IOException {
        Path file = write("token");
        WorkloadIdentity fromFile = WorkloadIdentity.of(FileTokenSource.of(file));
        Files.delete(file);

        assertThatThrownBy(() -> prepare(fromFile))
                .isInstanceOfSatisfying(WorkloadIdentityRuntimeException.class, e -> {
                    assertThat(e.source()).isEqualTo("file");
                    assertThat(e.getCause()).isInstanceOf(IOException.class);
                    assertThat(e.retryable()).isFalse();
                });

        IllegalStateException boom = new IllegalStateException("vault sealed");
        WorkloadIdentity custom = WorkloadIdentity.of(() -> {
            throw boom;
        });
        assertThatThrownBy(() -> prepare(custom)).isInstanceOfSatisfying(WorkloadIdentityRuntimeException.class, e -> {
            assertThat(e.source()).isEqualTo("custom");
            assertThat(e.getCause()).isSameAs(boom);
        });

        WorkloadIdentityRuntimeException typed = new WorkloadIdentityRuntimeException(
                "spire down", "spiffe", new NetworkException("x", new IOException()));
        WorkloadIdentity passthrough = WorkloadIdentity.of(() -> {
            throw typed;
        });
        assertThatThrownBy(() -> prepare(passthrough)).isSameAs(typed);
        assertThat(typed.retryable()).isTrue();

        assertThatThrownBy(() -> prepare(WorkloadIdentity.of(() -> "")))
                .isInstanceOfSatisfying(
                        WorkloadIdentityRuntimeException.class,
                        e -> assertThat(e.source()).isEqualTo("custom"));
    }

    @Test
    @DisplayName("row 4: a bare lambda is accepted as a source")
    void row4() {
        AtomicInteger calls = new AtomicInteger();
        WorkloadIdentity credential = WorkloadIdentity.of(() -> "token-" + calls.incrementAndGet());

        assertThat(prepare(credential).clientAssertion()).isEqualTo("token-1");
        assertThat(prepare(credential).clientAssertion()).isEqualTo("token-2");
    }

    @Test
    @DisplayName("row 4a: a configured client_id rides on the token request; unconfigured, none is sent")
    void row4a() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond("POST", StubZone.TOKEN_PATH, 200, "{\"access_token\":\"at\"}");

            ClientCredentialsClient.builder(zone.issuer())
                    .credential(WorkloadIdentity.builder(() -> "platform-token")
                            .clientId("app-cred-1")
                            .build())
                    .build()
                    .requestToken();
            ClientCredentialsClient.builder(zone.issuer())
                    .credential(WorkloadIdentity.of(() -> "platform-token"))
                    .build()
                    .requestToken();

            List<StubZone.RecordedRequest> requests = zone.requests(StubZone.TOKEN_PATH);
            assertThat(requests.get(0).formParams())
                    .containsEntry("client_id", List.of("app-cred-1"))
                    .containsEntry("client_assertion", List.of("platform-token"))
                    .containsEntry("client_assertion_type", List.of(TokenTypes.JWT_BEARER_ASSERTION));
            assertThat(requests.get(1).formParams()).doesNotContainKey("client_id");
            assertThat(requests.get(0).header("Authorization")).isNull();

            assertThat(prepare(WorkloadIdentity.builder(() -> "t")
                                    .clientId("app-cred-1")
                                    .build())
                            .clientId())
                    .isEqualTo("app-cred-1");
            assertThat(prepare(WorkloadIdentity.of(() -> "t")).clientId()).isNull();
        }
    }

    @Test
    @DisplayName("row 4b: client authentication is form fields only, client_id only when configured")
    void row4b() {
        ClientAuthentication with = WorkloadIdentity.builder(() -> "platform-token")
                .clientId("app-cred-1")
                .build()
                .authenticate(ISSUER, TOKEN);
        ClientAuthentication without =
                WorkloadIdentity.of(() -> "platform-token").authenticate(ISSUER, TOKEN);

        assertThat(with.headers()).isEmpty();
        assertThat(with.formFields())
                .containsExactly(
                        Map.entry("client_assertion", "platform-token"),
                        Map.entry("client_assertion_type", TokenTypes.JWT_BEARER_ASSERTION),
                        Map.entry("client_id", "app-cred-1"));
        assertThat(without.formFields()).containsOnlyKeys("client_assertion", "client_assertion_type");
        assertThat(with.formFields()).doesNotContainKey("subject_token_type");
    }

    @Test
    @DisplayName("row 4c: a token that is not a JWT is sent unchanged")
    void row4c() {
        String opaque = "  not-a-jwt: opaque/value  ";
        WorkloadIdentity credential = WorkloadIdentity.of(() -> opaque);

        assertThat(prepare(credential).clientAssertion()).isEqualTo(opaque);
        assertThat(credential.authenticate(ISSUER, TOKEN).formFields()).containsEntry("client_assertion", opaque);
    }

    @Test
    @DisplayName("row 5: an explicit token_file_path to a non-empty file is used and validated at construction")
    void row5() throws IOException {
        Path file = write("  file-token\n");

        FileTokenSource source = FileTokenSource.builder()
                .tokenFilePath(file)
                .environment(Map.of("AWS_WEB_IDENTITY_TOKEN_FILE", "/does/not/exist"))
                .build();

        assertThat(source.path()).isEqualTo(file);
        assertThat(source.identityToken()).isEqualTo("file-token");

        Path empty = write(" \n");
        assertThatThrownBy(() -> FileTokenSource.of(empty))
                .isInstanceOfSatisfying(
                        WorkloadIdentityConfigurationException.class,
                        e -> assertThat(e.source()).isEqualTo("file"));
        assertThatThrownBy(() -> FileTokenSource.of(dir.resolve("missing")))
                .isInstanceOf(WorkloadIdentityConfigurationException.class);
    }

    @Test
    @DisplayName("row 6: without a path, the first set discovery variable wins, env_var_name first")
    void row6() throws IOException {
        Path custom = write("custom-token");
        Path eks = write("eks-token");
        Path aws = write("aws-token");
        Path azure = write("azure-token");

        assertThat(discover(
                                null,
                                Map.of(
                                        "AWS_WEB_IDENTITY_TOKEN_FILE",
                                        aws.toString(),
                                        "AZURE_FEDERATED_TOKEN_FILE",
                                        azure.toString()))
                        .identityToken())
                .isEqualTo("aws-token");
        assertThat(discover(null, Map.of("AZURE_FEDERATED_TOKEN_FILE", azure.toString()))
                        .identityToken())
                .isEqualTo("azure-token");
        assertThat(discover(
                                null,
                                Map.of(
                                        "KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE",
                                        eks.toString(),
                                        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
                                        aws.toString()))
                        .identityToken())
                .isEqualTo("eks-token");
        assertThat(discover(
                                "MY_TOKEN_FILE",
                                Map.of(
                                        "MY_TOKEN_FILE",
                                        custom.toString(),
                                        "KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE",
                                        eks.toString()))
                        .identityToken())
                .isEqualTo("custom-token");
        assertThat(FileTokenSource.DISCOVERY_VARIABLES)
                .containsExactly(
                        "KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE",
                        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
                        "AWS_WEB_IDENTITY_TOKEN_FILE",
                        "AZURE_FEDERATED_TOKEN_FILE");
    }

    @Test
    @DisplayName("row 7: no path and no discovery variable is a configuration error at construction")
    void row7() {
        assertThatThrownBy(() -> discover("MY_TOKEN_FILE", Map.of("UNRELATED", "x")))
                .isInstanceOfSatisfying(WorkloadIdentityConfigurationException.class, e -> {
                    assertThat(e.source()).isEqualTo("file");
                    assertThat(e.getMessage()).contains("MY_TOKEN_FILE", "AZURE_FEDERATED_TOKEN_FILE");
                    assertThat(e.retryable()).isFalse();
                });
    }

    @Test
    @DisplayName("row 8: GCP fetch carries the identity path, audience, format=full and Metadata-Flavor")
    void row8() {
        try (StubZone metadata = StubZone.start()) {
            metadata.respond(
                    "GET",
                    "/computeMetadata/v1/instance/service-accounts/default/identity",
                    new StubResponse(200, Map.of(), "gcp.signed.jwt\n"));
            GcpMetadataTokenSource source = GcpMetadataTokenSource.builder("https://acme.keycard.cloud/a b")
                    .metadataUrl(metadata.issuer())
                    .build();

            assertThat(source.identityToken()).isEqualTo("gcp.signed.jwt");

            StubZone.RecordedRequest request = metadata.requests().get(0);
            assertThat(request.header("Metadata-Flavor")).isEqualTo("Google");
            assertThat(request.rawQuery()).isEqualTo("audience=https%3A%2F%2Facme.keycard.cloud%2Fa+b&format=full");
        }
    }

    @Test
    @DisplayName("row 8: a non-200 GCP response is a runtime error; a blank audience fails at construction")
    void row8Failures() {
        try (StubZone metadata = StubZone.start()) {
            metadata.respond("GET", "/computeMetadata/v1/instance/service-accounts/default/identity", 403, "{}");
            GcpMetadataTokenSource source = GcpMetadataTokenSource.builder("aud")
                    .metadataUrl(metadata.issuer())
                    .build();

            assertThatThrownBy(source::identityToken)
                    .isInstanceOfSatisfying(WorkloadIdentityRuntimeException.class, e -> {
                        assertThat(e.source()).isEqualTo("gcp-metadata");
                        assertThat(e.getCause()).isInstanceOf(HttpStatusException.class);
                    });
        }
        assertThatThrownBy(() -> GcpMetadataTokenSource.builder(" "))
                .isInstanceOfSatisfying(
                        WorkloadIdentityConfigurationException.class,
                        e -> assertThat(e.source()).isEqualTo("gcp-metadata"));
    }

    @Test
    @DisplayName("row 8: an unreachable metadata server is a retryable runtime error")
    void row8Unreachable() throws IOException {
        GcpMetadataTokenSource source = GcpMetadataTokenSource.builder("aud")
                .metadataUrl(AuthorizationServerDiscoveryConformanceTest.closedPort())
                .build();

        assertThatThrownBy(source::identityToken).isInstanceOfSatisfying(WorkloadIdentityRuntimeException.class, e -> {
            assertThat(e.source()).isEqualTo("gcp-metadata");
            assertThat(e.getCause()).isInstanceOf(NetworkException.class);
            assertThat(e.retryable()).isTrue();
        });
    }

    private static TokenExchangeRequest prepare(WorkloadIdentity credential) {
        return credential.prepareTokenExchangeRequest(TokenExchangeContext.of("subject", null, ISSUER));
    }

    private FileTokenSource discover(String envVarName, Map<String, String> environment) {
        FileTokenSource.Builder builder = FileTokenSource.builder().environment(environment);
        if (envVarName != null) {
            builder.envVarName(envVarName);
        }
        return builder.build();
    }

    private Path write(String contents) throws IOException {
        return Files.writeString(Files.createTempFile(dir, "token", ".jwt"), contents);
    }
}
