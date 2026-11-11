package ai.keycard.a2a;

import ai.keycard.oauth.ConfigurationException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/** One protocol generation's envelope: method, header, roles, part shape and preferred interface. */
record Wire(String version, String header, String method) {

    private static final Map<String, String> LEGACY_ROLES =
            Map.of(A2aProtocol.ROLE_USER, "user", A2aProtocol.ROLE_AGENT, "agent");

    static Wire of(String version) {
        if (A2aProtocol.PROTOCOL_VERSION.equals(version)) {
            return new Wire(version, A2aProtocol.PROTOCOL_VERSION_HEADER, A2aProtocol.MESSAGE_SEND_METHOD);
        }
        if (A2aProtocol.LEGACY_PROTOCOL_VERSION.equals(version)) {
            return new Wire(
                    version, A2aProtocol.LEGACY_PROTOCOL_VERSION_HEADER, A2aProtocol.LEGACY_MESSAGE_SEND_METHOD);
        }
        throw new ConfigurationException("unsupported A2A protocol version " + version + " (supported: "
                + A2aProtocol.PROTOCOL_VERSION + ", " + A2aProtocol.LEGACY_PROTOCOL_VERSION + ")");
    }

    boolean legacy() {
        return A2aProtocol.LEGACY_PROTOCOL_VERSION.equals(version);
    }

    /** The params on the wire: unchanged for 1.0; roles and text parts translated for 0.3. */
    Map<String, Object> encodeParams(Map<String, Object> params) {
        if (!legacy() || !(params.get("message") instanceof Map<?, ?> message)) {
            return params;
        }
        Map<String, Object> translated = new LinkedHashMap<>();
        message.forEach((key, value) -> translated.put(String.valueOf(key), value));
        Object role = message.get("role");
        if (role instanceof String name) {
            translated.put("role", LEGACY_ROLES.getOrDefault(name, name));
        }
        if (message.get("parts") instanceof List<?> parts) {
            List<Object> legacyParts = new ArrayList<>();
            for (Object part : parts) {
                legacyParts.add(legacyPart(part));
            }
            translated.put("parts", legacyParts);
        }
        Map<String, Object> out = new LinkedHashMap<>(params);
        out.put("message", translated);
        return out;
    }

    /**
     * Puts a result in the 1.0 shape. A 1.0 result wraps its payload ({@code {"message": {...}}} or
     * {@code {"task": {...}}}); a 0.3 result is the message or task itself, tagged with {@code
     * kind}, so it is wrapped under that kind.
     */
    Map<String, Object> decodeResult(Map<String, Object> result) {
        if (legacy()
                && result.get("kind") instanceof String kind
                && (kind.equals("message") || kind.equals("task"))
                && !result.containsKey(kind)) {
            Map<String, Object> wrapped = new LinkedHashMap<>();
            wrapped.put(kind, result);
            return wrapped;
        }
        return result;
    }

    /**
     * The JSON-RPC URL the card advertises: the JSONRPC interface matching this generation, else
     * the first JSONRPC interface, else a 0.3 card's top-level {@code url}.
     */
    @Nullable
    String endpointFrom(AgentCard card) {
        List<Map<?, ?>> interfaces = new ArrayList<>();
        if (card.raw().get("supportedInterfaces") instanceof List<?> list) {
            for (Object entry : list) {
                if (entry instanceof Map<?, ?> iface
                        && iface.get("protocolBinding") instanceof String binding
                        && binding.toUpperCase(Locale.ROOT).equals("JSONRPC")
                        && iface.get("url") instanceof String url
                        && !url.isEmpty()) {
                    interfaces.add(iface);
                }
            }
        }
        for (Map<?, ?> iface : interfaces) {
            if (version.equals(iface.get("protocolVersion"))) {
                return (String) iface.get("url");
            }
        }
        if (!interfaces.isEmpty()) {
            return (String) interfaces.get(0).get("url");
        }
        return card.raw().get("url") instanceof String url && !url.isEmpty() ? url : null;
    }

    private static Object legacyPart(Object part) {
        if (part instanceof Map<?, ?> map && map.containsKey("text") && !map.containsKey("kind")) {
            Map<String, Object> tagged = new LinkedHashMap<>();
            tagged.put("kind", "text");
            map.forEach((key, value) -> tagged.put(String.valueOf(key), value));
            return tagged;
        }
        return part;
    }
}
