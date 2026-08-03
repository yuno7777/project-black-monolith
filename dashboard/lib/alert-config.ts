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
