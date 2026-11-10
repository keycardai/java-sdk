package ai.keycard.oauth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Keeps each key at {@code <dir>/<key id>.pem}, readable only by the owner, the layout the Python
 * and Ruby SDKs use. Loading also looks in {@code ./mcp_keys}, the legacy default, so keys created
 * there keep working; new keys always go to the configured directory.
 */
public final class FileKeyStorage implements KeyStorage {

    /** The default directory. */
    public static final Path DEFAULT_DIR = Path.of("./server_keys");

    /** Directories searched after the configured one when loading. */
    static final List<Path> LEGACY_DIRS = List.of(Path.of("./mcp_keys"));

    private final Path dir;

    private FileKeyStorage(Path dir) {
        this.dir = dir;
    }

    /**
     * Storage in a directory, created on first write.
     *
     * @param dir the directory
     * @return the storage
     */
    public static FileKeyStorage of(Path dir) {
        return new FileKeyStorage(Objects.requireNonNull(dir, "dir"));
    }

    /**
     * Storage in {@link #DEFAULT_DIR}.
     *
     * @return the storage
     */
    public static FileKeyStorage defaultStorage() {
        return of(DEFAULT_DIR);
    }

    /**
     * The directory new keys are written to.
     *
     * @return the directory
     */
    public Path dir() {
        return dir;
    }

    @Override
    public @Nullable String load(String keyId) {
        for (Path candidate : searchPath()) {
            Path file = candidate.resolve(keyId + ".pem");
            if (Files.isRegularFile(file)) {
                try {
                    return Files.readString(file, StandardCharsets.UTF_8);
                } catch (IOException e) {
                    throw new ConfigurationException("cannot read the key file " + file, e);
                }
            }
        }
        return null;
    }

    @Override
    public void store(String keyId, String pem) {
        Path file = dir.resolve(keyId + ".pem");
        try {
            Files.createDirectories(dir);
            Files.writeString(file, pem, StandardCharsets.UTF_8);
            try {
                Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException e) {
                // Not a POSIX file system, such as Windows; the directory's ACLs apply.
            }
        } catch (IOException e) {
            throw new ConfigurationException("cannot write the key file " + file, e);
        }
    }

    private List<Path> searchPath() {
        if (LEGACY_DIRS.contains(dir)) {
            return List.of(dir);
        }
        return java.util.stream.Stream.concat(java.util.stream.Stream.of(dir), LEGACY_DIRS.stream())
                .toList();
    }

    @Override
    public String toString() {
        return "FileKeyStorage[" + dir + "]";
    }
}
