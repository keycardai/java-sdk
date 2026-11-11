package ai.keycard.oauth;

/**
 * The user didn't finish signing in within the loopback flow's callback timeout. Not retryable
 * by base.md's default: repeating the call unchanged needs the person to act, so ask before
 * starting the flow again.
 */
public class InteractionTimeoutException extends KeycardException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message how long the flow waited
     */
    public InteractionTimeoutException(String message) {
        super(message, null, false);
    }
}
