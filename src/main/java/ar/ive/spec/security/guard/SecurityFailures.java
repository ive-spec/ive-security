package ar.ive.spec.security.guard;

import ar.ive.spec.errors.ForbiddenException;
import ar.ive.spec.errors.Guidance;
import ar.ive.spec.errors.Guidances;
import ar.ive.spec.errors.TooManyRequestsException;
import ar.ive.spec.errors.UnauthorizedException;

import java.util.function.BiFunction;

/**
 * The error of a security requirement's cause, ready to throw.
 *
 * <p>The error carries only its cause ({@code condition}); its
 * {@code expects} reaches the response body through the guide (the error
 * handler writes it with {@code ErrorBody}). The MESSAGE is the guide's
 * when the cause has a row there -- the catalog's, or the one the project
 * registered with its own text -- and the default otherwise.</p>
 *
 * <p>{@code guide} is how the message is looked up: {@link #CATALOG_GUIDE}
 * ({@code Guidances::of}, the process table), or the project's own
 * lookup when it has one (the generated {@code ErrorGuidance::of}, which
 * registers the project's rows before answering).</p>
 */
public final class SecurityFailures {

    /** The process guide of ive-errors-runtime. */
    public static final BiFunction<String, String, Guidance> CATALOG_GUIDE = Guidances::of;

    private SecurityFailures() { }

    /** The 401 of {@link SecurityRequirements#AUTHENTICATION} for that cause. */
    public static UnauthorizedException unauthorized(String condition, String defaultMessage,
                                                     BiFunction<String, String, Guidance> guide) {
        SecurityRequirement requirement = SecurityRequirements.AUTHENTICATION;
        return new UnauthorizedException(requirement.errorRef(),
                messageOf(requirement, condition, defaultMessage, guide)).withCondition(condition);
    }

    /** The 403 of {@link SecurityRequirements#AUTHORIZATION} for that cause. */
    public static ForbiddenException forbidden(String condition, String defaultMessage,
                                               BiFunction<String, String, Guidance> guide) {
        SecurityRequirement requirement = SecurityRequirements.AUTHORIZATION;
        return new ForbiddenException(requirement.errorRef(),
                messageOf(requirement, condition, defaultMessage, guide)).withCondition(condition);
    }

    /** The 429 of {@link SecurityRequirements#RATE_LIMIT} for that cause. */
    public static TooManyRequestsException tooManyRequests(String condition, String defaultMessage,
                                                           BiFunction<String, String, Guidance> guide) {
        SecurityRequirement requirement = SecurityRequirements.RATE_LIMIT;
        return new TooManyRequestsException(requirement.errorRef(),
                messageOf(requirement, condition, defaultMessage, guide)).withCondition(condition);
    }

    /** The guide's message for that cause, or the default. */
    public static String messageOf(SecurityRequirement requirement, String condition, String defaultMessage,
                                   BiFunction<String, String, Guidance> guide) {
        Guidance row = (guide == null ? CATALOG_GUIDE : guide).apply(requirement.errorRef(), condition);
        return row != null && row.message() != null && !row.message().isBlank() ? row.message() : defaultMessage;
    }
}
