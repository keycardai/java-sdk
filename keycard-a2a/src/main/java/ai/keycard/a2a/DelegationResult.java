package ai.keycard.a2a;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * What a delegated call returned: the JSON-RPC result as received, and the target's card.
 *
 * @param result the JSON-RPC result, carrying a {@code message} or a {@code task}
 * @param agentCard the target's card
 */
public record DelegationResult(Map<String, Object> result, AgentCard agentCard) {

    /**
     * Freezes the result.
     *
     * @param result the JSON-RPC result
     * @param agentCard the target's card
     */
    public DelegationResult {
        result = Collections.unmodifiableMap(new LinkedHashMap<>(result));
        Objects.requireNonNull(agentCard, "agentCard");
    }

    /**
     * The agent's reply message.
     *
     * @return the message, empty when the agent answered with a task
     */
    public Optional<Map<String, Object>> message() {
        return member("message");
    }

    /**
     * The task the agent started.
     *
     * @return the task, empty when the agent answered with a message
     */
    public Optional<Map<String, Object>> task() {
        return member("task");
    }

    /**
     * The text of the reply message's first text part.
     *
     * @return the text, empty when there is no reply message or it has no text part
     */
    public Optional<String> text() {
        return message()
                .flatMap(message ->
                        message.get("parts") instanceof Iterable<?> parts ? firstText(parts) : Optional.empty());
    }

    @SuppressWarnings("unchecked")
    private Optional<Map<String, Object>> member(String name) {
        return result.get(name) instanceof Map<?, ?> value
                ? Optional.of((Map<String, Object>) value)
                : Optional.empty();
    }

    private static Optional<String> firstText(Iterable<?> parts) {
        for (Object part : parts) {
            if (part instanceof Map<?, ?> map && map.get("text") instanceof String text) {
                return Optional.of(text);
            }
        }
        return Optional.empty();
    }
}
