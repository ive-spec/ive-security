package ar.ive.spec.security.guard;

import ar.ive.spec.errors.Conditions;

import java.util.List;

/**
 * The catalog's security requirements and how each one fails.
 *
 * <p>GENERATED FROM THE CATALOG. Which requirements, with which error and
 * which causes, is the catalog's; this class only names them.</p>
 */
public final class SecurityRequirements {

    /** <code>authentication</code>: fails with <code>401_Unauthorized</code>. */
    public static final SecurityRequirement AUTHENTICATION = new SecurityRequirement(
            "authentication", "401_Unauthorized", 401,
            List.of(Conditions.CREDENTIAL_MISSING, Conditions.CREDENTIAL_INVALID, Conditions.CREDENTIAL_EXPIRED));

    /** <code>authorization</code>: fails with <code>403_Forbidden</code>. */
    public static final SecurityRequirement AUTHORIZATION = new SecurityRequirement(
            "authorization", "403_Forbidden", 403,
            List.of(Conditions.PERMISSION_MISSING, Conditions.RESOURCE_NOT_PERMITTED));

    /** <code>rateLimit</code>: fails with <code>429_TooManyRequests</code>. */
    public static final SecurityRequirement RATE_LIMIT = new SecurityRequirement(
            "rateLimit", "429_TooManyRequests", 429,
            List.of(Conditions.RATE_LIMIT_EXCEEDED, Conditions.PERIOD_QUOTA_EXHAUSTED));

    /** Every requirement above, in the catalog's order. */
    public static final List<SecurityRequirement> ALL = List.of(
            AUTHENTICATION,
            AUTHORIZATION,
            RATE_LIMIT
    );

    private SecurityRequirements() { }

    /** The requirement with that catalog key, or {@code null}. */
    public static SecurityRequirement of(String key) {
        for (SecurityRequirement requirement : ALL) {
            if (requirement.key().equals(key)) {
                return requirement;
            }
        }
        return null;
    }
}
