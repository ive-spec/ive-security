package ar.ive.spec.security.guard;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Who is calling, as the deployment's {@code CredentialVerifier} returned
 * it.
 *
 * <p>No shape is required of the claims: the only one the guard reads is
 * {@link #SCOPES}, and only when the specification declares permissions.
 * Everything else (subject, tenant, organization) stays available to
 * whoever needs it.</p>
 *
 * <p>{@link #nobody()} is an EMPTY caller, and that is not a permission:
 * it means there was nobody to identify (a public operation, or an
 * installation that chose not to verify).</p>
 */
public final class Caller {

    /** The claim the permissions are read from. */
    public static final String SCOPES = "scopes";

    private static final Caller NOBODY = new Caller(Map.of());

    private final Map<String, Object> claims;

    private Caller(Map<String, Object> claims) {
        this.claims = claims;
    }

    /** A caller with those claims (copied; null values are kept). */
    public static Caller of(Map<String, ?> claims) {
        if (claims == null || claims.isEmpty()) {
            return NOBODY;
        }
        return new Caller(Collections.unmodifiableMap(new LinkedHashMap<>(claims)));
    }

    /** Nobody was identified. */
    public static Caller nobody() {
        return NOBODY;
    }

    /** The claims, unmodifiable. */
    public Map<String, Object> claims() {
        return claims;
    }

    /** Whether there are no claims at all. */
    public boolean isEmpty() {
        return claims.isEmpty();
    }

    /** The strings of the {@link #SCOPES} claim; empty when it is missing or not a collection. */
    public List<String> scopes() {
        Object value = claims.get(SCOPES);
        if (!(value instanceof Collection<?> collection)) {
            return List.of();
        }
        List<String> scopes = new ArrayList<>();
        for (Object scope : collection) {
            if (scope instanceof String text) {
                scopes.add(text);
            }
        }
        return Collections.unmodifiableList(scopes);
    }

    @Override
    public String toString() {
        // The claims are not printed: they may carry personal data.
        return "Caller" + claims.keySet();
    }
}
