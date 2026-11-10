package ai.keycard.oauth;

/**
 * The user didn't finish signing in within the loopback flow's callback timeout. Retryable: run
 * the flow again.
 */
public class InteractionTimeoutException extends KeycardException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message how long the flow waited
     */
    public InteractionTimeoutException(String message) {
        super(message, null, true);
    }
}
