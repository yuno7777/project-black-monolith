import type { BusinessAction } from "@/lib/business-policy";

export const actionNames: Record<BusinessAction["kind"], string> = {
  refund: "Issue refund",
  customer_reply: "Send customer reply",
  crm_update: "Update CRM record",
  invoice_review: "Record invoice review",
};

export function decimalAmount(amount: number, currency: string) {
  const digits = new Intl.NumberFormat("en", { style: "currency", currency }).resolvedOptions().maximumFractionDigits ?? 2;
  const text = String(amount).padStart(digits + 1, "0");
  return digits === 0 ? text : text.slice(0, -digits) + "." + text.slice(-digits);
}

export function ActionPreview({ action }: { action: BusinessAction }) {
  let fields: [string, string][];
  switch (action.kind) {
    case "refund":
      fields = [["Order", action.orderId], ["Destination", action.destination], ["Amount", decimalAmount(action.amountMinor, action.currency) + " " + action.currency]];
      break;
    case "customer_reply":
      fields = [["Recipient", action.recipient], ["Message", action.body]];
      if (action.afterRefundId) fields.push(["Required refund", action.afterRefundId]);
      break;
    case "crm_update":
      fields = [["Record", action.recordId], ["Field", action.field], ["New value", action.value]];
      break;
    case "invoice_review":
      fields = [["Invoice", action.invoiceId], ["Review note", action.note]];
      break;
  }
  return <dl className="biz-fields">{fields.map(([label, value]) => (
    <div key={label}><dt>{label}</dt><dd>{value}</dd></div>
  ))}</dl>;
}

export async function businessRequest<T>(path: string, payload?: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`/api/business${path}`, {
    method: payload === undefined ? "GET" : "POST",
    cache: "no-store",
    headers: payload === undefined ? undefined : { "Content-Type": "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload),
    signal,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "The workspace could not complete this request.");
  return data as T;
}

export type Save = (path: string, body: unknown, message: string) => Promise<boolean>;
