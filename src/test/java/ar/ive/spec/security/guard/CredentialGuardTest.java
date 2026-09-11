package ar.ive.spec.security.guard;

import ar.ive.spec.core.IveBusinessException;
import ar.ive.spec.errors.Conditions;
import ar.ive.spec.errors.ForbiddenException;
import ar.ive.spec.errors.Guidance;
import ar.ive.spec.errors.Guidances;
import ar.ive.spec.errors.TooManyRequestsException;
import ar.ive.spec.errors.UnauthorizedException;
import ar.ive.spec.security.CredentialExpiredException;
import ar.ive.spec.security.CredentialInvalidException;
import ar.ive.spec.security.CredentialVerifier;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

/**
 * What has to stay true of the guard: the three causes of the 401 are told
 * apart, the 403 names what is missing, the cause's guide gives the message
 * and the {@code expects}, and the deployment has to choose.
 */
class CredentialGuardTest {

    private static final CredentialVerifier GOOD = credential -> {
        if (credential.equals("expired")) throw new CredentialExpiredException("expired token");
        if (!credential.equals("good")) throw new CredentialInvalidException("bad token");
        return Map.of("sub", "ana", Caller.SCOPES, List.of("pets:admin"));
    };

    private static final Map<String, List<String>> INCLUDES = Map.of("pets:admin", List.of("pets:read"));

    private static void assertCause(IveBusinessException e, String errorRef, String condition) {
        assertEquals(errorRef, e.errorRef());
        assertEquals(condition, e.condition());
        Guidance row = Guidances.of(errorRef, condition);
        if (row != null) {
            // The message is the guide's, and `expects` reaches the body from it.
            assertEquals(row.message(), e.getMessage());
            assertEquals(row.expects(), e.expects());
        }
    }

    // --- the catalog -------------------------------------------------------

    @Test
    void theRequirementsAreTheCatalogs() {
        assertEquals(3, SecurityRequirements.ALL.size());
        assertEquals(UnauthorizedException.REF, SecurityRequirements.AUTHENTICATION.errorRef());
        assertEquals(ForbiddenException.REF, SecurityRequirements.AUTHORIZATION.errorRef());
        assertEquals(TooManyRequestsException.REF, SecurityRequirements.RATE_LIMIT.errorRef());
        assertTrue(SecurityRequirements.AUTHENTICATION.declares(Conditions.CREDENTIAL_MISSING));
        assertTrue(SecurityRequirements.AUTHENTICATION.declares(Conditions.CREDENTIAL_EXPIRED));
        assertTrue(SecurityRequirements.AUTHENTICATION.declares(Conditions.CREDENTIAL_INVALID));
        assertTrue(SecurityRequirements.AUTHORIZATION.declares(Conditions.PERMISSION_MISSING));
        assertSame(SecurityRequirements.AUTHENTICATION, SecurityRequirements.of("authentication"));
    }

    @Test
    void everyCauseOfARequirementIsDeclaredOnItsError() {
        for (SecurityRequirement requirement : SecurityRequirements.ALL) {
            for (String condition : requirement.conditions()) {
                assertNotNull(Guidances.of(requirement.errorRef(), condition),
                        requirement.key() + ": the catalog's " + requirement.errorRef() + " does not declare " + condition);
            }
        }
    }

    // --- identify --------------------------------------------------------------

    @Test
    void aGoodCredentialGivesTheCaller() throws Exception {
        Caller caller = new CredentialGuard(GOOD).identify("good", Map.of());
        assertEquals("ana", caller.claims().get("sub"));
        assertEquals(List.of("pets:admin"), caller.scopes());
    }

    @Test
    void anExpiredCredentialIsToldApart() {
        UnauthorizedException e = assertThrows(UnauthorizedException.class,
                () -> new CredentialGuard(GOOD).identify("expired", Map.of()));
        assertCause(e, "401_Unauthorized", Conditions.CREDENTIAL_EXPIRED);
    }

    @Test
    void anInvalidCredentialIsInvalid() {
        UnauthorizedException e = assertThrows(UnauthorizedException.class,
                () -> new CredentialGuard(GOOD).identify("forged", Map.of()));
        assertCause(e, "401_Unauthorized", Conditions.CREDENTIAL_INVALID);
    }

    @Test
    void nothingSentIsMissingNotInvalid() {
        UnauthorizedException e = assertThrows(UnauthorizedException.class,
                () -> new CredentialGuard(GOOD).identify(null, Map.of()));
        assertCause(e, "401_Unauthorized", Conditions.CREDENTIAL_MISSING);
    }

    @Test
    void theVerifierIsAskedEvenWithoutACredential() throws Exception {
        CredentialVerifier proxy = new CredentialVerifier() {
            @Override
            public Map<String, Object> verify(String credential) throws CredentialInvalidException {
                throw new CredentialInvalidException("no header");
            }

            @Override
            public Map<String, Object> verify(String credential, Map<String, String> headers) {
                return Map.of("sub", headers.get("x-forwarded-user"));
            }
        };
        Map<String, String> headers = CredentialGuard.headers(List.of("X-Forwarded-User"), name -> "bea");
        assertEquals("bea", new CredentialGuard(proxy).identify("", headers).claims().get("sub"));
    }

    @Test
    void withoutAVerifierNothingIsValid() {
        CredentialGuard guard = new CredentialGuard(() -> null, Map.of(), null, null);
        UnauthorizedException e = assertThrows(UnauthorizedException.class, () -> guard.identify("good", Map.of()));
        assertCause(e, "401_Unauthorized", Conditions.CREDENTIAL_INVALID);
    }

    @Test
    void anInstallationWithoutIdentityAsksNobody() throws Exception {
        AtomicInteger asked = new AtomicInteger();
        CredentialGuard guard = new CredentialGuard(() -> credential -> {
            asked.incrementAndGet();
            return Map.of();
        }, Map.of(), "  internal network only  ", null);
        assertEquals("internal network only", guard.withoutIdentity());
        assertTrue(guard.identify(null, Map.of()).isEmpty());
        guard.requirePermissions(Caller.nobody(), List.of("pets:admin"));
        assertEquals(0, asked.get());
    }

    @Test
    void aProjectsOwnGuideWinsForTheMessage() {
        CredentialGuard guard = new CredentialGuard(() -> GOOD, Map.of(), null,
                (ref, condition) -> new Guidance(ref, 401, condition, "renew it", "renew and retry"));
        UnauthorizedException e = assertThrows(UnauthorizedException.class, () -> guard.identify("expired", Map.of()));
        assertEquals("renew it", e.getMessage());
    }

    // --- permissions -----------------------------------------------------------

    @Test
    void whatAPermissionIncludesCounts() throws Exception {
        CredentialGuard guard = new CredentialGuard(() -> GOOD, INCLUDES, null, null);
        Caller caller = guard.identify("good", Map.of());
        guard.requirePermissions(caller, List.of("pets:read", "pets:admin"));
        assertEquals(Set.of("pets:admin", "pets:read"), guard.permissionsOf(caller));
    }

    @Test
    void theRequiredSideIsNotExpanded() {
        CredentialGuard guard = new CredentialGuard(() -> GOOD, INCLUDES, null, null);
        Caller reader = Caller.of(Map.of(Caller.SCOPES, List.of("pets:read")));
        ForbiddenException e = assertThrows(ForbiddenException.class,
                () -> guard.requirePermissions(reader, List.of("pets:admin")));
        assertCause(e, "403_Forbidden", Conditions.PERMISSION_MISSING);
    }

    // --- the deployment's choice -------------------------------------------------

    @Test
    void theDeploymentHasToChooseExactlyOne() {
        assertThrows(IllegalStateException.class,
                () -> DeploymentChoice.check(false, null, "the gateway", List.of(), "a verifier", "a reason"));
        assertThrows(IllegalStateException.class,
                () -> DeploymentChoice.check(true, "open", "the gateway", List.of(), "a verifier", "a reason"));
        DeploymentChoice.check(true, null, "the gateway", List.of("pets:admin"), "a verifier", "a reason");
        DeploymentChoice.check(false, "open", "the gateway", List.of(), "a verifier", "a reason");
    }

    @Test
    void openIsNotAChoiceWhenPermissionsWereNotDelegated() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> DeploymentChoice.check(false, "open", "the gateway", List.of("pets:admin"), "a verifier", "a reason"));
        assertTrue(e.getMessage().contains("pets:admin"));
    }

    // --- the rate limit ----------------------------------------------------------

    @Test
    void theWindowSlides() {
        AtomicLong now = new AtomicLong(1_000_000);
        RateLimiter limiter = new RateLimiter(2, now::get);
        assertTrue(limiter.check("a").allowed());
        now.addAndGet(30_000);
        assertTrue(limiter.check("a").allowed());
        RateLimiter.Verdict refused = limiter.check("a");
        assertFalse(refused.allowed());
        assertEquals(30, refused.retryAfterSeconds());
        assertTrue(limiter.check("b").allowed(), "counted per origin");
        now.addAndGet(30_001);
        assertTrue(limiter.check("a").allowed());
        assertTrue(new RateLimiter(0, now::get).check("a").allowed(), "0 turns it off");
    }

    @Test
    void theRefusalIsThe429WithItsCause() {
        TooManyRequestsException e = SecurityFailures.tooManyRequests(Conditions.RATE_LIMIT_EXCEEDED,
                "Too many requests", null);
        assertCause(e, "429_TooManyRequests", Conditions.RATE_LIMIT_EXCEEDED);
    }
}
