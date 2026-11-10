package ai.keycard.a2a;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * An agent card as published at {@link A2aProtocol#AGENT_CARD_PATH}. Only {@code name} is
 * required; everything else is in {@link #raw()} as received.
 *
 * @param name the agent's name
 * @param raw the complete card
 */
public record AgentCard(String name, Map<String, Object> raw) {

    /**
     * Freezes the card.
     *
     * @param name the agent's name
     * @param raw the complete card
     */
    public AgentCard {
        Objects.requireNonNull(name, "name");
        raw = Collections.unmodifiableMap(new LinkedHashMap<>(raw));
    }
}
