package ai.keycard.a2a;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * A2A wire constants, matching the Go and Ruby SDKs, plus a builder for the common text message.
 * A2A 1.0 is the default generation; 0.3 is an opt-in that switches the whole envelope.
 */
public final class A2aProtocol {

    /** Where an agent publishes its card, relative to its base URL. */
    public static final String AGENT_CARD_PATH = "/.well-known/agent-card.json";

    /** The JSON-RPC endpoint used when the card names none, relative to the base URL. */
    public static final String JSONRPC_PATH = "/a2a/jsonrpc";

    /** The default protocol generation. */
    public static final String PROTOCOL_VERSION = "1.0";

    /** The 0.3 generation, available as an opt-in. */
    public static final String LEGACY_PROTOCOL_VERSION = "0.3";

    /** The 1.0 JSON-RPC method for sending a message. */
    public static final String MESSAGE_SEND_METHOD = "SendMessage";

    /** The 0.3 JSON-RPC method for sending a message. */
    public static final String LEGACY_MESSAGE_SEND_METHOD = "message/send";

    /** The 1.0 protocol version header. */
    public static final String PROTOCOL_VERSION_HEADER = "A2A-Version";

    /** The 0.3 protocol version header. */
    public static final String LEGACY_PROTOCOL_VERSION_HEADER = "X-A2A-Protocol-Version";

    /** The 1.0 role of a message the caller sends. */
    public static final String ROLE_USER = "ROLE_USER";

    /** The 1.0 role of a message an agent sends. */
    public static final String ROLE_AGENT = "ROLE_AGENT";

    private A2aProtocol() {}

    /**
     * {@code message/send} params carrying one text part in the 1.0 shape, with a fresh message
     * id. With the 0.3 opt-in, the client translates it to the 0.3 shape on the wire.
     *
     * @param text the text
     * @return the params
     */
    public static Map<String, Object> textMessage(String text) {
        Map<String, Object> message = new LinkedHashMap<>();
        message.put("role", ROLE_USER);
        message.put("parts", List.of(Map.of("text", text)));
        message.put("messageId", UUID.randomUUID().toString());
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("message", message);
        return params;
    }
}
