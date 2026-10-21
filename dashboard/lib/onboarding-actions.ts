/**
 * The actions the onboarding surface can perform.
 *
 * The list lives here rather than inside the route so that a test can
 * enumerate it. An action added here without a matching expectation in the
 * test fails the test, instead of quietly falling through to whatever the
 * route's last branch happens to do — and on this route the last branch
 * erases the memory layer's detector state, which is not something to reach
 * by accident.
 */
export const ONBOARDING_ACTIONS = [
  "seed-corpus",
  "seed-bait",
  "reset-detection",
] as const;

export type OnboardingAction = (typeof ONBOARDING_ACTIONS)[number];

export function isOnboardingAction(value: unknown): value is OnboardingAction {
  return (
    typeof value === "string" && (ONBOARDING_ACTIONS as readonly string[]).includes(value)
  );
}
