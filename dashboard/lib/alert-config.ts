// Webhook configuration validation.
//
// WHAT THIS FILE IS
// -----------------
// A single function that decides whether the critical-alert webhook is
// enabled, given MONOLITH_ALERT_WEBHOOK_URL and MONOLITH_ALERT_WEBHOOK_SECRET.
// It is used in TWO places so the ingest path and the operations page agree:
//   - event-store.ts insertWithClient() — only queues alert_outbox rows when
//     this says enabled,
//   - /api/operations route — surfaces the enabled/error state on the
//     Operations page.
//
// THE RULES
// ---------
//   - Both URL and secret configured together, or neither (partial config =
//     disabled with an error).
//   - Secret must be 32-512 safe characters (no newlines/NUL).
//   - URL must not embed credentials or a fragment.
//   - HTTPS required; HTTP allowed only for loopback hosts (local testing).
//   - The dispatcher (scripts/dispatch-alerts.mjs) enforces the same rules
//     for its own startup, so a config that "looks enabled" here is also a
//     config the dispatcher will accept.

export type AlertConfigStatus = {
  enabled: boolean;
  error?: string;
};

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function alertConfigStatus(
  environment: Record<string, string | undefined> = process.env,
): AlertConfigStatus {
  const rawUrl = environment.MONOLITH_ALERT_WEBHOOK_URL?.trim() ?? "";
  const secret = environment.MONOLITH_ALERT_WEBHOOK_SECRET ?? "";
  if (!rawUrl && !secret) return { enabled: false };
  if (!rawUrl || !secret) {
    return { enabled: false, error: "webhook URL and signing secret must be configured together" };
  }
  if (secret.length < 32 || secret.length > 512 || /[\r\n\0]/.test(secret)) {
    return { enabled: false, error: "webhook signing secret must be 32-512 safe characters" };
  }
  try {
    const url = new URL(rawUrl);
    if (url.username || url.password || url.hash) {
      return { enabled: false, error: "webhook URL must not contain credentials or a fragment" };
    }
    if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname))) {
      return { enabled: false, error: "webhook URL must use HTTPS (HTTP is loopback-only)" };
    }
  } catch {
    return { enabled: false, error: "webhook URL is invalid" };
  }
  return { enabled: true };
}
