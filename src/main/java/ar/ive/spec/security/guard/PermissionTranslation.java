package ar.ive.spec.security.guard;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * The organization's permission names, and the catalog's.
 *
 * <p>The specification declares {@code facts:publish}; the client's
 * identity provider says {@code GG-FACTS-PUB}, a GUID, or a whole DN. They
 * are the same permission. A translation table declares the equivalence,
 * so the client does not have to rename the groups of ITS directory --
 * groups twenty other systems use.</p>
 *
 * <ul>
 *   <li>{@code map} -- {@code {"<what the store says>": [catalog permissions]}}.
 *       The key goes VERBATIM (the whole DN, the whole GUID).</li>
 *   <li>{@code passthrough} -- whether what is not in the map passes as it
 *       is. Off by default: otherwise a directory group named
 *       {@code facts:admin} would grant admin without anyone declaring it.</li>
 *   <li>{@code log} -- where to report what did not match, ON THE SERVER
 *       SIDE (the organization's group names do not go in the 403).</li>
 * </ul>
 *
 * <p>The counterpart of Python's {@code ive_security.translation}: the same
 * rules, the same notices.</p>
 */
public final class PermissionTranslation {

    private final Map<String, List<String>> map;
    private final boolean passthrough;
    private final Consumer<String> log;

    /**
     * @param map         store name -> catalog permissions; {@code null} or
     *                    empty is the same as no table
     * @param passthrough whether a name not in the map passes as it is
     * @param log         where what did not match is reported, or {@code null}
     */
    public PermissionTranslation(Map<String, ? extends Collection<String>> map, boolean passthrough,
                                 Consumer<String> log) {
        Map<String, List<String>> copy = new LinkedHashMap<>();
        if (map != null) {
            map.forEach((name, targets) -> copy.put(name, targets == null ? List.of() : List.copyOf(targets)));
        }
        this.map = java.util.Collections.unmodifiableMap(copy);
        this.passthrough = passthrough;
        this.log = log;
    }

    /** A table with that map, no passthrough and no log. */
    public static PermissionTranslation of(Map<String, ? extends Collection<String>> map) {
        return new PermissionTranslation(map, false, null);
    }

    /** The same table, letting what is not in the map pass as it is. */
    public PermissionTranslation withPassthrough(boolean passthrough) {
        return new PermissionTranslation(map, passthrough, log);
    }

    /** The same table, reporting what did not match there. */
    public PermissionTranslation withLog(Consumer<String> log) {
        return new PermissionTranslation(map, passthrough, log);
    }

    public Map<String, List<String>> map() {
        return map;
    }

    public boolean passthrough() {
        return passthrough;
    }

    private static boolean isEmpty(PermissionTranslation translation) {
        return translation == null || translation.map.isEmpty();
    }

    /**
     * Checks the table AT STARTUP and returns the notice for the console.
     *
     * <p>A target that does not exist refuses to start
     * ({@link IllegalStateException}): a mistyped permission does not fail
     * when asked, it grants nothing forever, silently. A permission nobody
     * reaches is only warned about. An EMPTY map is the same as no table
     * ({@link #translate} passes the names as they are).</p>
     *
     * @param vocabulary every permission the catalog declares
     */
    public static String check(Collection<String> vocabulary, PermissionTranslation translation) {
        List<String> names = vocabulary == null ? List.of() : List.copyOf(vocabulary);
        if (isEmpty(translation)) {
            return "PERMISSIONS: no translation table. The names the verifier returns are used as they are,\n"
                    + "so they have to be the catalog's: " + String.join(", ", names) + ".";
        }
        Set<String> known = new LinkedHashSet<>(names);
        Set<String> unknown = new LinkedHashSet<>();
        for (List<String> targets : translation.map.values()) {
            for (String target : targets) {
                if (!known.contains(target)) {
                    unknown.add(target);
                }
            }
        }
        if (!unknown.isEmpty()) {
            throw new IllegalStateException(
                    "The permission translation table grants permissions the catalog does not declare: "
                    + String.join(", ", unknown) + ".\n"
                    + "The ones that exist are: " + String.join(", ", names) + ".\n"
                    + "A mistyped permission does not fail when asked: it grants nothing forever, silently.");
        }
        List<String> orphans = new ArrayList<>();
        for (String permission : names) {
            boolean granted = translation.map.values().stream().anyMatch(targets -> targets.contains(permission));
            if (!granted) {
                orphans.add(permission);
            }
        }
        String notice = "PERMISSIONS: " + translation.map.size() + " equivalence(s) declared"
                + (translation.passthrough ? ", and what is not in the table PASSES AS IT IS." : ".");
        if (!orphans.isEmpty() && !translation.passthrough) {
            notice += "\n  NOTE: nothing grants " + String.join(", ", orphans) + ". In this installation nobody"
                    + "\n  can do those operations. If that is on purpose, fine.";
        }
        return notice;
    }

    /**
     * The caller with the catalog permissions that correspond to its
     * {@link Caller#SCOPES}.
     *
     * <p>WITHOUT A TABLE, WHAT CAME: whoever names their scopes like the
     * catalog has nothing to translate.</p>
     */
    public static Caller translate(Caller caller, PermissionTranslation translation) {
        if (caller == null || isEmpty(translation)) {
            return caller;
        }
        List<String> raw = caller.scopes();
        List<String> out = new ArrayList<>();
        for (String name : raw) {
            List<String> targets = translation.map.get(name);
            if (targets != null) {
                for (String target : targets) {
                    if (!out.contains(target)) {
                        out.add(target);
                    }
                }
            } else if (translation.passthrough && !out.contains(name)) {
                out.add(name);
            }
        }
        // THE TWO FAILURES ARE SAID DIFFERENTLY BECAUSE THEY ARE FIXED IN
        // DIFFERENT PLACES: the token brought no permissions (look at which
        // claim they are read from), or it brought some the table does not name.
        if (translation.log != null && out.isEmpty()) {
            if (raw.isEmpty()) {
                translation.log.accept("The caller brought NO permission. Check where they are read from: the provider"
                        + " may send them in another claim (`roles`, `groups`, `realm_access.roles`).");
            } else {
                translation.log.accept("The caller brought " + raw.size() + " permission(s) and the translation table"
                        + " names none: " + String.join(", ", raw) + ". They are missing from the table, or they"
                        + " changed in the directory.");
            }
        }
        Map<String, Object> claims = new LinkedHashMap<>(caller.claims());
        claims.put(Caller.SCOPES, List.copyOf(out));
        return Caller.of(claims);
    }
}
