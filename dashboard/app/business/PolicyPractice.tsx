import { useState } from "react";
import { BUSINESS_CURRENCIES, BUSINESS_TEMPLATES, type BusinessAction, type BusinessPolicy } from "@/lib/business-policy";
import { actionNames, businessRequest, decimalAmount, type Save } from "./business-ui";

function decimals(currency: string) {
  return new Intl.NumberFormat("en", { style: "currency", currency }).resolvedOptions().maximumFractionDigits ?? 2;
}

function minorUnits(raw: string, currency: string) {
  const digits = decimals(currency);
  const [whole, fraction = ""] = raw.split(".");
  if (!/^\d+(?:\.\d+)?$/.test(raw) || fraction.length > digits) throw new Error(`Enter an amount in ${currency} with up to ${digits} decimal places.`);
  const result = Number(whole + fraction.padEnd(digits, "0"));
  if (!Number.isSafeInteger(result)) throw new Error("Amount is too large.");
  return result;
}

type PracticeResult = { ok: boolean; reason: string; reviewerTeam?: string };

function PracticeFields({ kind, currency }: { kind: BusinessAction["kind"]; currency: string }) {
  switch (kind) {
    case "refund":
      return <div className="biz-grid">
        <label>Order ID<input name="orderId" required /></label><label>Refund destination<input name="destination" required /></label>
        <label>Refund amount ({currency})<input name="amount" required inputMode="decimal" /></label>
      </div>;
    case "customer_reply":
      return <><label>Recipient<input name="recipient" required /></label><label>Message<textarea name="body" required /></label></>;
    case "crm_update":
      return <><div className="biz-grid"><label>Record ID<input name="recordId" required /></label><label>Field<input name="field" required /></label></div><label>New value<textarea name="value" required /></label></>;
    case "invoice_review":
      return <><label>Invoice ID<input name="invoiceId" required /></label><label>Review note<textarea name="note" required /></label></>;
  }
}

export function PolicyPractice({ policy, admin, busy, save }: { policy: BusinessPolicy; admin: boolean; busy: boolean; save: Save }) {
  const [currency, setCurrency] = useState(policy.currency);
  const [threshold, setThreshold] = useState(decimalAmount(policy.refundThresholdMinor, policy.currency));
  const [defaultTeam, setDefaultTeam] = useState(policy.defaultTeam);
  const [financeTeam, setFinanceTeam] = useState(policy.financeTeam);
  const [template, setTemplate] = useState<(typeof BUSINESS_TEMPLATES)[number]>(() => BUSINESS_TEMPLATES.find((item) => item.id === "refund") ?? BUSINESS_TEMPLATES[0]);
  const [kind, setKind] = useState<BusinessAction["kind"]>("refund");
  const [result, setResult] = useState<PracticeResult | null>(null);
  const [error, setError] = useState("");
  const [running, setRunning] = useState(false);
  function draft() {
    return { refundThresholdMinor: minorUnits(threshold, currency), currency, defaultTeam, financeTeam };
  }
  return <>
    <form className="biz-panel biz-form" onChange={() => setResult(null)} onSubmit={async (event) => {
      event.preventDefault();
      try { setError(""); await save("/policies", { policy: draft() }, "Approval policy saved."); }
      catch (failure) { setError((failure as Error).message); }
    }}>
      <h2>Approval policy</h2>
      <p>Refunds above this threshold go to finance. Invoice reviews also go to finance.</p>
      <div className="biz-grid">
        <label>Refund threshold<input required inputMode="decimal" value={threshold} onChange={(event) => setThreshold(event.target.value)} /></label>
        <label>Currency<select value={currency} onChange={(event) => setCurrency(event.target.value as typeof currency)}>{BUSINESS_CURRENCIES.map((code) => <option key={code}>{code}</option>)}</select></label>
        <label>Default review team<input required value={defaultTeam} onChange={(event) => setDefaultTeam(event.target.value)} /></label>
        <label>Finance review team<input required value={financeTeam} onChange={(event) => setFinanceTeam(event.target.value)} /></label>
      </div>
      {admin && <div><button className="biz-primary" disabled={busy || running}>Save policy</button></div>}
    </form>
    <form className="biz-panel biz-form" onChange={() => setResult(null)} onSubmit={async (event) => {
      event.preventDefault();
      setRunning(true); setError(""); setResult(null);
      try {
        const fields = Object.fromEntries(new FormData(event.currentTarget));
        const { amount, ...actionFields } = fields;
        const action = kind === "refund" ? { kind, ...actionFields, amountMinor: minorUnits(String(amount), currency), currency } : { kind, ...actionFields };
        setResult(await businessRequest<PracticeResult>("/practice", { action, templateId: template.id, policy: draft() }));
      } catch (failure) { setError((failure as Error).message); }
      finally { setRunning(false); }
    }}>
      <h2>Practice a workflow</h2><p>Preview how the policy above routes a sample action. Practice sends nothing to a connected app.</p>
      <fieldset disabled={running} className="biz-form">
      <div className="biz-grid">
        <label>Workflow<select value={template.id} onChange={(event) => {
          const next = BUSINESS_TEMPLATES.find((item) => item.id === event.target.value)!;
          setTemplate(next); setKind(next.actionKinds[0]);
        }}>{BUSINESS_TEMPLATES.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
        <label>Action<select value={kind} onChange={(event) => setKind(event.target.value as BusinessAction["kind"])}>{template.actionKinds.map((item) => <option key={item} value={item}>{actionNames[item]}</option>)}</select></label>
      </div>
      <p>{template.description}</p>
      <PracticeFields key={kind} kind={kind} currency={currency} />
      {kind === "customer_reply" && template.id === "refund" && <label>Required refund action ID<input name="afterRefundId" required /></label>}
      <div><button className="ghost-btn" disabled={busy || running}>Preview decision</button></div>
      </fieldset>
      {result && <div className="biz-result" role="status"><strong>{result.ok ? `Review team · ${result.reviewerTeam}` : "Action blocked"}</strong><p>{result.reason}</p></div>}
    </form>
    {error && <p className="ops-error" role="alert">{error}</p>}
  </>;
}
