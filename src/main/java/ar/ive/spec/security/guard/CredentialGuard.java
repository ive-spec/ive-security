package ar.ive.spec.security.guard;

import ar.ive.spec.errors.Conditions;
import ar.ive.spec.errors.ForbiddenException;
import ar.ive.spec.errors.Guidance;
import ar.ive.spec.errors.UnauthorizedException;
import ar.ive.spec.security.CredentialExpiredException;
import ar.ive.spec.security.CredentialInvalidException;
import ar.ive.spec.security.CredentialVerifier;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Enforces {@code authentication} and {@code authorization} for one
 * service: who is calling, or the 401 with its cause; whether the caller
 * has the permissions, or the 403.
 *
 * <p>WHAT IS NOT HERE, ON PURPOSE:</p>
 * <ul>
 *   <li>HOW a credential is verified. That is the deployment's, behind the
 *       {@link CredentialVerifier} port. Without one, no credential is
 *       valid: absence is not a permission.</li>
 *   <li>WHICH route needs what. That is the specification's, and stays
 *       generated in each project (with the web framework's wiring).</li>
 * </ul>
 *
 * <p>THE THREE CAUSES OF THE 401 ARE TOLD APART because the contract
 * declares three different actions: send the credential, authenticate
 * from scratch, or RENEW and retry the same message. Collapsing them sends
 * the caller down the wrong path -- and it is what any framework does by
 * default.</p>
 */
public final class CredentialGuard {

    private final Supplier<? extends CredentialVerifier> verifier;
    private final Map<String, List<String>> includes;
    private final String withoutIdentity;
    private final BiFunction<String, String, Guidance> guide;

    /**
     * @param verifier        gives the deployment's verifier, or {@code null}
     *                        when there is none (a supplier, so a framework
     *                        can resolve it lazily)
     * @param includes        which permission includes which others,
     *                        already closed (the specification's table);
     *                        empty when it declares none
     * @param withoutIdentity WHY this installation chose not to verify, or
     *                        {@code null}. Text and not a boolean: whoever
     *                        audits reads it. Check the choice at startup
     *                        with {@link DeploymentChoice#check}.
     * @param guide           how a cause's message is looked up
     *                        ({@link SecurityFailures#CATALOG_GUIDE} when null)
     */
    public CredentialGuard(Supplier<? extends CredentialVerifier> verifier,
                           Map<String, ? extends Collection<String>> includes,
                           String withoutIdentity,
                           BiFunction<String, String, Guidance> guide) {
        this.verifier = verifier == null ? () -> null : verifier;
        Map<String, List<String>> copy = new LinkedHashMap<>();
        if (includes != null) {
            includes.forEach((permission, included) -> copy.put(permission, List.copyOf(included)));
        }
        this.includes = Map.copyOf(copy);
        this.withoutIdentity = DeploymentChoice.reasonOrNull(withoutIdentity);
        this.guide = guide == null ? SecurityFailures.CATALOG_GUIDE : guide;
    }

    /** A guard over that verifier, with no permission includes and the catalog's guide. */
    public CredentialGuard(CredentialVerifier verifier) {
        this(() -> verifier, Map.of(), null, null);
    }

    /** Why this installation does not verify, or {@code null} when it does. */
    public String withoutIdentity() {
        return withoutIdentity;
    }

    /**
     * Who is calling, or the 401 that corresponds.
     *
     * <p>THE VERIFIER IS CALLED EVEN WITHOUT A CREDENTIAL: with a proxy in
     * front, the identity comes in another header, and cutting before
     * would leave that deployment with no way to identify anyone.</p>
     *
     * @param credential the credential header's value, possibly null or blank
     * @param headers    the request headers, in lower case (see {@link #headers})
     * @return the caller; {@link Caller#nobody()} when the installation
     *         chose not to verify
     */
    public Caller identify(String credential, Map<String, String> headers) throws UnauthorizedException {
        if (withoutIdentity != null) {
            // NOBODY TO IDENTIFY, BECAUSE THAT IS HOW IT WAS INSTALLED. The
            // header is not required either: asking for it and not looking
            // would be a 401 for not sending something nobody verifies.
            return Caller.nobody();
        }
        CredentialVerifier current = verifier.get();
        if (current == null) {
            // EVERYTHING IS NOT ACCEPTED. Without a verifier the service
            // cannot keep its contract, and a 401 exposes nothing.
            throw SecurityFailures.unauthorized(Conditions.CREDENTIAL_INVALID,
                    "This service has nothing to verify credentials with: a CredentialVerifier is missing.", guide);
        }
        boolean missing = credential == null || credential.isBlank();
        try {
            Map<String, Object> claims = current.verify(credential == null ? "" : credential,
                    headers == null ? Map.of() : headers);
            return Caller.of(claims);
        } catch (CredentialExpiredException expired) {
            throw SecurityFailures.unauthorized(Conditions.CREDENTIAL_EXPIRED,
                    messageOr(expired, "The credential expired"), guide);
        } catch (CredentialInvalidException invalid) {
            if (missing) {
                // THERE WAS NOTHING TO INVALIDATE: the cause is that the
                // credential is missing, not that theirs is wrong.
                throw SecurityFailures.unauthorized(Conditions.CREDENTIAL_MISSING,
                        "The request carries no credential", guide);
            }
            throw SecurityFailures.unauthorized(Conditions.CREDENTIAL_INVALID,
                    messageOr(invalid, "The credential is not valid"), guide);
        }
    }

    /**
     * Requires every one of {@code required}, or the 403 with
     * {@code permissionMissing}.
     *
     * <p>ONLY {@code permissionMissing}: it is what can be decided at the
     * edge, looking at the caller's scopes. The other cause of the 403,
     * {@code resourceNotPermitted}, needs the resource and lives in the
     * service. The catalog already separates them.</p>
     *
     * <p>With {@link #withoutIdentity()} nothing is checked: there is no
     * door, by a written choice. {@link DeploymentChoice#check} is what
     * refuses that choice when the specification requires permissions it
     * did not delegate.</p>
     */
    public void requirePermissions(Caller caller, Collection<String> required) throws ForbiddenException {
        if (required == null || required.isEmpty() || withoutIdentity != null) {
            return;
        }
        Set<String> has = permissionsOf(caller == null ? Caller.nobody() : caller);
        List<String> missing = required.stream().filter(scope -> !has.contains(scope)).toList();
        if (!missing.isEmpty()) {
            throw SecurityFailures.forbidden(Conditions.PERMISSION_MISSING,
                    "Missing permissions: " + String.join(", ", missing), guide);
        }
    }

    /** The caller's permissions with what each one includes. */
    public Set<String> permissionsOf(Caller caller) {
        return withIncluded(caller.scopes(), includes);
    }

    /**
     * {@code scopes} plus what each one includes.
     *
     * <p>WHAT THE CALLER HAS is expanded, not what the operation requires:
     * "admin includes read" means whoever has admin has read. Expanding the
     * required side would say something else -- that either one is enough.
     * The table comes already closed, so this is a lookup, not a walk.</p>
     */
    public static Set<String> withIncluded(Collection<String> scopes,
                                           Map<String, ? extends Collection<String>> includes) {
        Set<String> all = new HashSet<>(scopes == null ? List.of() : scopes);
        if (includes != null && scopes != null) {
            for (String scope : scopes) {
                Collection<String> included = includes.get(scope);
                if (included != null) {
                    all.addAll(included);
                }
            }
        }
        return all;
    }

    /**
     * The request headers in lower case, whatever the framework: the
     * verifier someone writes has to serve every chain without learning
     * three conventions. {@code headers(Collections.list(request.getHeaderNames()), request::getHeader)}.
     */
    public static Map<String, String> headers(Iterable<String> names, Function<String, String> valueOf) {
        Map<String, String> headers = new HashMap<>();
        if (names != null) {
            for (String name : names) {
                headers.put(name.toLowerCase(Locale.ROOT), valueOf.apply(name));
            }
        }
        return headers;
    }

    private static String messageOr(Exception failure, String defaultMessage) {
        return failure.getMessage() == null || failure.getMessage().isBlank() ? defaultMessage : failure.getMessage();
    }
}
