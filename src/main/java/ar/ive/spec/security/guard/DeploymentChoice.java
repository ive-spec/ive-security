package ar.ive.spec.security.guard;

import java.util.Collection;

/**
 * THE DEPLOYMENT'S CHOICE, checked at startup and not on the first request.
 *
 * <p>When the specification declares that {@code authentication} is
 * resolved by whoever installs ({@code satisfiedByDeployment}), that does
 * not make the requirement optional: it makes the choice the installer's,
 * and the choice has to be MADE. Two options, and neither is the absence:
 * a verifier, or a written reason not to verify. A misconfigured service
 * has to fail while someone is looking at the console, not six hours later
 * against a client.</p>
 *
 * <p>How each option is named is the framework's (a Spring bean and a
 * property, two environment variables, two options of a function), so the
 * caller passes those names for the messages.</p>
 */
public final class DeploymentChoice {

    private DeploymentChoice() { }

    /** A reason as the guard keeps it: trimmed, or {@code null} when blank. */
    public static String reasonOrNull(String raw) {
        return raw == null || raw.isBlank() ? null : raw.trim();
    }

    /**
     * Refuses a deployment that did not choose, chose both, or chose not to
     * verify while the specification requires permissions it did not
     * delegate.
     *
     * @param hasVerifier                whether there is something to verify with
     * @param withoutIdentity            why this installation does not verify, or null
     * @param resolvedByDeployment       the specification's reason for delegating
     * @param permissionsUnderDeployment the permissions the specification did NOT
     *                                   delegate (empty when none)
     * @param verifierOption             how the verifier option is named (for the message)
     * @param withoutIdentityOption      how the no-identity option is named
     * @throws IllegalStateException with what to do
     */
    public static void check(boolean hasVerifier, String withoutIdentity, String resolvedByDeployment,
                             Collection<String> permissionsUnderDeployment,
                             String verifierOption, String withoutIdentityOption) {
        boolean open = reasonOrNull(withoutIdentity) != null;
        if (hasVerifier && open) {
            throw new IllegalStateException(
                    "This service has " + verifierOption + " and also declares " + withoutIdentityOption
                    + ". They are two answers to the same question and only one can hold: if there is"
                    + " something to verify with, it verifies.");
        }
        if (!hasVerifier && !open) {
            throw new IllegalStateException(
                    "This service requires `authentication` and its specification says whoever installs it"
                    + " resolves it:\n  " + resolvedByDeployment + "\n"
                    + "So a choice has to be MADE, and there is no default: either provide " + verifierOption
                    + " or declare " + withoutIdentityOption + ". It does not start without one of them: a"
                    + " service left open by oversight and one open on purpose look the same from outside,"
                    + " and only one of them is right.");
        }
        if (open && permissionsUnderDeployment != null && !permissionsUnderDeployment.isEmpty()) {
            // NOWHERE TO READ THE SCOPES FROM. Nobody to verify does not
            // mean everyone may do everything: it means nothing to decide with.
            throw new IllegalStateException(
                    "This specification requires concrete permissions (" + String.join(", ", permissionsUnderDeployment)
                    + "), so " + withoutIdentityOption + " is not an available choice: without an identity"
                    + " there are no scopes to check, and granting everything would not be an open service"
                    + " but one that says it checks and does not.");
        }
    }
}
