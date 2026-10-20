import OnboardingClient from "./OnboardingClient";

export const metadata = {
  title: "Connect your agent — Project Black Monolith",
  description:
    "Set up the agent gateway from the console: check the stack, load the demo corpus, and run your agent behind all three layers.",
};

export default function OnboardingPage() {
  return <OnboardingClient />;
}
