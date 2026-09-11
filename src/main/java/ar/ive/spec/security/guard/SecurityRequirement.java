package ar.ive.spec.security.guard;

import java.util.List;

/**
 * A requirement of the catalog that the guard enforces, with the error and
 * the causes it fails with (the requirement's {@code failure}).
 *
 * <p>The catalog says it once for every technology: {@code authentication}
 * fails with 401 for one of three causes, {@code authorization} with 403,
 * {@code rateLimit} with 429. The instances are in
 * {@link SecurityRequirements}, generated from the catalog.</p>
 *
 * @param key        the requirement's key in the catalog ({@code authentication})
 * @param errorRef   the catalog error it fails with ({@code 401_Unauthorized})
 * @param code       that error's code
 * @param conditions the causes the catalog declares for the failure
 */
public record SecurityRequirement(String key, String errorRef, int code, List<String> conditions) {

    public SecurityRequirement {
        conditions = List.copyOf(conditions);
    }

    /** Whether the catalog declares {@code condition} as a cause of this requirement's failure. */
    public boolean declares(String condition) {
        return conditions.contains(condition);
    }
}
