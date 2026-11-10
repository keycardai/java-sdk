package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.AccessContext;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.ResourceAccessException;
import ai.keycard.oauth.ResourceAccessException.ErrorType;
import ai.keycard.oauth.TokenResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** access-context.md, Unit Tests table. */
class AccessContextConformanceTest {

    private static final String LEDGER = "https://ledger.example";
    private static final String CRM = "https://crm.example";
    private static final TokenResponse TOKEN = token("t1");
    private static final KeycardException FAILURE =
            new OAuthErrorException("exchange failed", 400, "{}", "invalid_target", null, null);

    @Test
    @DisplayName("row 1: access returns the token for a successful resource")
    void row1() {
        assertThat(new AccessContext(Map.of(LEDGER, TOKEN)).access(LEDGER)).isSameAs(TOKEN);
    }

    @Test
    @DisplayName("row 2: access for a failed resource throws resource_error")
    void row2() {
        AccessContext context = new AccessContext();
        context.setResourceError(LEDGER, FAILURE);

        assertThatThrownBy(() -> context.access(LEDGER)).isInstanceOfSatisfying(ResourceAccessException.class, e -> {
            assertThat(e.errorType()).isEqualTo(ErrorType.RESOURCE_ERROR);
            assertThat(e.errorDetails()).isSameAs(FAILURE);
            assertThat(e.resource()).isEqualTo(LEDGER);
        });
    }

    @Test
    @DisplayName("row 3: access for an ungranted resource throws missing_token, listing what was granted")
    void row3() {
        AccessContext context = new AccessContext(Map.of(CRM, TOKEN));

        assertThatThrownBy(() -> context.access(LEDGER)).isInstanceOfSatisfying(ResourceAccessException.class, e -> {
            assertThat(e.errorType()).isEqualTo(ErrorType.MISSING_TOKEN);
            assertThat(e.availableResources()).containsExactly(CRM);
        });
    }

    @Test
    @DisplayName("row 4: access with a global error throws global_error")
    void row4() {
        AccessContext context = new AccessContext(Map.of(LEDGER, TOKEN));
        context.setError(FAILURE);

        assertThatThrownBy(() -> context.access(LEDGER))
                .isInstanceOfSatisfying(
                        ResourceAccessException.class,
                        e -> assertThat(e.errorType()).isEqualTo(ErrorType.GLOBAL_ERROR));
    }

    @Test
    @DisplayName("rows 5 and 6: resourceError returns the recorded error, empty for a success")
    void rows5And6() {
        AccessContext context = new AccessContext(Map.of(CRM, TOKEN));
        context.setResourceError(LEDGER, FAILURE);

        assertThat(context.resourceError(LEDGER)).containsSame(FAILURE);
        assertThat(context.resourceError(CRM)).isEmpty();
        assertThat(context.errors().resources()).containsExactly(Map.entry(LEDGER, FAILURE));
    }

    @Test
    @DisplayName("rows 7 to 10: hasErrors and hasError")
    void rows7To10() {
        AccessContext ok = new AccessContext(Map.of(LEDGER, TOKEN));
        assertThat(ok.hasErrors()).isFalse();

        AccessContext partial = new AccessContext(Map.of(CRM, TOKEN));
        partial.setResourceError(LEDGER, FAILURE);
        assertThat(partial.hasErrors()).isTrue();
        assertThat(partial.hasError()).isFalse();

        AccessContext global = new AccessContext();
        global.setError(FAILURE);
        assertThat(global.hasErrors()).isTrue();
        assertThat(global.hasError()).isTrue();
        assertThat(global.error()).containsSame(FAILURE);
    }

    @Test
    @DisplayName("rows 11 to 13: status is success, partial_error or error")
    void rows11To13() {
        AccessContext context = new AccessContext(Map.of(LEDGER, TOKEN));
        assertThat(context.status()).isEqualTo(AccessContext.Status.SUCCESS);

        context.setResourceError(CRM, FAILURE);
        assertThat(context.status()).isEqualTo(AccessContext.Status.PARTIAL_ERROR);

        context.setError(FAILURE);
        assertThat(context.status()).isEqualTo(AccessContext.Status.ERROR);
    }

    @Test
    @DisplayName("rows 14 and 15: successful and failed resources are listed separately")
    void rows14And15() {
        AccessContext context = new AccessContext();
        context.setBulkTokens(Map.of(LEDGER, TOKEN));
        context.setResourceError(CRM, FAILURE);

        assertThat(context.successfulResources()).containsExactly(LEDGER);
        assertThat(context.failedResources()).containsExactly(CRM);
    }

    @Test
    @DisplayName("row 16: setToken and setResourceError on one resource replace each other")
    void row16() {
        AccessContext context = new AccessContext();
        context.setToken(LEDGER, TOKEN);
        context.setResourceError(LEDGER, FAILURE);
        assertThat(context.successfulResources()).isEmpty();
        assertThat(context.failedResources()).containsExactly(LEDGER);

        context.setToken(LEDGER, TOKEN);
        assertThat(context.failedResources()).isEmpty();
        assertThat(context.access(LEDGER)).isSameAs(TOKEN);
        assertThat(context.toString()).doesNotContain("t1");
    }

    private static TokenResponse token(String value) {
        return new TokenResponse(value, "Bearer", null, List.of(), null, null, null, Map.of());
    }
}
