package ai.keycard.oauth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;

/**
 * Keeps each key at {@code <dir>/<key id>.pem}, readable only by the owner, the layout the Python
 * and Ruby SDKs use. With the default directory, loading also looks in {@code ./mcp_keys}, the
 * legacy default, so keys created there keep working; new keys always go to the configured
 * directory.
 *
 * <p>A key file is created with owner-only permissions from the start and appears whole or not at
 * all. When two processes generate a key under the same id at once, the first one stored wins and
 * {@link #store} leaves it in place, so a caller that reloads after storing ends up with the same
 * key as every other process.
 *
 * <p>Key ids are file names: letters, digits, {@code .}, {@code _} and {@code -}, starting with a
 * letter or digit, at most 128 characters.
 */
public final class FileKeyStorage implements KeyStorage {

    /** The default directory. */
    public static final Path DEFAULT_DIR = Path.of("./server_keys");

    /** Directories searched after the configured one when loading. */
    static final List<Path> LEGACY_DIRS = List.of(Path.of("./mcp_keys"));

    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");

    private static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");

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
        String name = fileName(keyId);
        for (Path candidate : searchPath()) {
            Path file = candidate.resolve(name);
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

    /**
     * Stores a key unless one is already stored under the id, in which case the stored key stays.
     *
     * @param keyId the key id
     * @param pem the PKCS#8 PEM text of the private key
     * @throws ConfigurationException when the key id isn't a valid file name or the directory
     *     can't be written
     */
    @Override
    public void store(String keyId, String pem) {
        Path file = dir.resolve(fileName(keyId));
        Path temp = null;
        try {
            Files.createDirectories(dir);
            // Created owner-only, so the key is never readable by others, even for a moment.
            temp = Files.createTempFile(dir, "." + keyId + ".", ".tmp", ownerOnly());
            Files.writeString(temp, pem, StandardCharsets.UTF_8);
            publish(temp, file);
        } catch (FileAlreadyExistsException e) {
            // Another process stored a key first; keep it.
        } catch (IOException e) {
            throw new ConfigurationException("cannot write the key file " + file, e);
        } finally {
            if (temp != null) {
                try {
                    Files.deleteIfExists(temp);
                } catch (IOException e) {
                    // A leftover temp file holds no live key; nothing reads it.
                }
            }
        }
    }

    /** Makes the written temp file visible under its final name, never replacing a stored key. */
    private static void publish(Path temp, Path file) throws IOException {
        try {
            // A hard link appears atomically and fails if the name is taken.
            Files.createLink(file, temp);
        } catch (FileAlreadyExistsException e) {
            throw e;
        } catch (UnsupportedOperationException | FileSystemException e) {
            // The file system refuses hard links; a move without replace still won't overwrite.
            Files.move(temp, file);
        }
    }

    private static FileAttribute<?>[] ownerOnly() {
        boolean posix = java.nio.file.FileSystems.getDefault()
                .supportedFileAttributeViews()
                .contains("posix");
        // Not a POSIX file system, such as Windows: the directory's ACLs apply.
        return posix
                ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(OWNER_ONLY)}
                : new FileAttribute<?>[0];
    }

    private static String fileName(String keyId) {
        if (keyId == null || !KEY_ID.matcher(keyId).matches()) {
            throw new ConfigurationException(
                    "key id must be letters, digits, '.', '_' or '-', start with a letter or digit, and be at most"
                            + " 128 characters");
        }
        return keyId + ".pem";
    }

    private List<Path> searchPath() {
        // Only the default directory falls back to the legacy one: a caller who picked a directory
        // must never be handed a key from somewhere else.
        if (!dir.normalize().equals(DEFAULT_DIR.normalize())) {
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
