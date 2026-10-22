#!/usr/bin/env python3
"""
Lightweight Statistical ML Incident Triage & Recommendation Engine for Project Black Monolith.

Extracts multi-field features (layer, event_type, severity, metadata keywords) from security
events and predicts:
  1. Threat Taxonomy Category (e.g., Prompt Injection, Corpus Poisoning, Tool Tampering, Secret Leakage)
  2. Recommended Operator Remediation Action (e.g., Revoke Session, Quarantine Document, Reset Baseline)
  3. Action Urgency & Confidence Score
"""

import json
import math
import os
import sys
import urllib.request
from typing import Any, Dict, List, Tuple

# Threat taxonomies
CLASSES = [
    "ADVERSARIAL_PROMPT_INJECTION",
    "TOOL_SCHEMA_TAMPERING",
    "RAG_CORPUS_POISONING",
    "CREDENTIAL_EXFILTRATION",
    "CIRCUIT_BREAKER_REVOCATION",
    "OPERATIONAL_INFRA_ANOMALY",
    "BENIGN_SYSTEM_ACTIVITY",
]

RECOMMENDED_ACTIONS = {
    "ADVERSARIAL_PROMPT_INJECTION": {
        "action": "Terminate LLM generation stream and log prompt fingerprint for refusal tuning.",
        "urgency": "P0 - CRITICAL INTERCEPT",
        "resolution_hint": "true_positive",
    },
    "TOOL_SCHEMA_TAMPERING": {
        "action": "Reject mutated tool catalogue, enforce cached HMAC baseline, and inspect MCP server binary.",
        "urgency": "P0 - CRITICAL INTERCEPT",
        "resolution_hint": "true_positive",
    },
    "RAG_CORPUS_POISONING": {
        "action": "Quarantine target document, purge ChromaDB embeddings, and invalidate retrieval cache.",
        "urgency": "P0 - CRITICAL INTERCEPT",
        "resolution_hint": "true_positive",
    },
    "CREDENTIAL_EXFILTRATION": {
        "action": "Redact exposed credential, rotate upstream secret key, and audit model reasoning trace.",
        "urgency": "P1 - HIGH THREAT",
        "resolution_hint": "true_positive",
    },
    "CIRCUIT_BREAKER_REVOCATION": {
        "action": "Maintain tenant session quarantine; require explicit analyst approval to restore identity.",
        "urgency": "P1 - HIGH THREAT",
        "resolution_hint": "true_positive",
    },
    "OPERATIONAL_INFRA_ANOMALY": {
        "action": "Verify service connectivity, check provider rate limits, and initialize missing baselines.",
        "urgency": "P2 - OPERATIONAL ATTENTION",
        "resolution_hint": "false_positive",
    },
    "BENIGN_SYSTEM_ACTIVITY": {
        "action": "No remediation required. Routine telemetry and baseline verification.",
        "urgency": "P3 - INFORMATIONAL",
        "resolution_hint": "benign",
    },
}

# Ground truth mapping heuristic for training/calibration
GROUND_TRUTH_MAPPING = {
    "reasoning_divergence_terminate": "ADVERSARIAL_PROMPT_INJECTION",
    "schema_mismatch": "TOOL_SCHEMA_TAMPERING",
    "suspicious_description": "TOOL_SCHEMA_TAMPERING",
    "suspicious_catalog_entry": "TOOL_SCHEMA_TAMPERING",
    "suspicious_error_payload": "TOOL_SCHEMA_TAMPERING",
    "suspicious_tool_output": "TOOL_SCHEMA_TAMPERING",
    "tool_call_argument_flagged": "CREDENTIAL_EXFILTRATION",
    "pii_redacted": "CREDENTIAL_EXFILTRATION",
    "secret_boundary_denial": "CREDENTIAL_EXFILTRATION",
    "corpus_poison_quarantine": "RAG_CORPUS_POISONING",
    "session_quarantined": "CIRCUIT_BREAKER_REVOCATION",
    "tool_call_blocked": "CIRCUIT_BREAKER_REVOCATION",
    "upstream_stream_error": "OPERATIONAL_INFRA_ANOMALY",
    "analysis_error": "OPERATIONAL_INFRA_ANOMALY",
    "baseline_missing": "OPERATIONAL_INFRA_ANOMALY",
    "baseline_persist_failed": "OPERATIONAL_INFRA_ANOMALY",
    "baseline_lock_failed": "OPERATIONAL_INFRA_ANOMALY",
    "baseline_reload_failed": "OPERATIONAL_INFRA_ANOMALY",
    "configuration_invalid": "OPERATIONAL_INFRA_ANOMALY",
    "service_start": "BENIGN_SYSTEM_ACTIVITY",
    "service_stop": "BENIGN_SYSTEM_ACTIVITY",
    "retrieval": "BENIGN_SYSTEM_ACTIVITY",
    "generation_completed": "BENIGN_SYSTEM_ACTIVITY",
    "baseline_registered": "BENIGN_SYSTEM_ACTIVITY",
    "divergence_disabled": "BENIGN_SYSTEM_ACTIVITY",
    "contract_probe": "BENIGN_SYSTEM_ACTIVITY",
    "auth_probe": "BENIGN_SYSTEM_ACTIVITY",
    "lifecycle_probe": "BENIGN_SYSTEM_ACTIVITY",
    "collision_probe_alpha": "BENIGN_SYSTEM_ACTIVITY",
    "collision_probe_beta": "BENIGN_SYSTEM_ACTIVITY",
    "rank_probe": "BENIGN_SYSTEM_ACTIVITY",
}


def extract_features(event: Dict[str, Any]) -> List[str]:
    """Extract multi-field bag-of-tokens and attributes for classification."""
    features = []
    # Module & type
    features.append(f"mod:{event.get('module', 'unknown')}")
    features.append(f"type:{event.get('event_type', 'unknown')}")
    features.append(f"sev:{event.get('severity', 'unknown')}")

    # Details keyword tokens
    details = event.get("details", {})
    if isinstance(details, dict):
        for k, v in details.items():
            features.append(f"key:{k}")
            if isinstance(v, (str, int, float, bool)):
                s = str(v).lower()
                for kw in ["divergence", "poison", "bait", "secret", "token", "schema", "mismatch", "quarantine", "tamper", "key", "refusal", "credential"]:
                    if kw in s:
                        features.append(f"kw:{kw}")
    return features


class FastTriageClassifier:
    """Multinomial Naive Bayes model with Laplace smoothing for fast sub-millisecond inference."""

    def __init__(self):
        self.classes = CLASSES
        self.class_counts = {c: 0 for c in self.classes}
        self.feature_counts = {c: {} for c in self.classes}
        self.total_docs = 0
        self.vocab = set()

    def fit(self, events: List[Dict[str, Any]]):
        self.total_docs = len(events)
        for ev in events:
            ev_type = ev.get("event_type", "")
            target_class = GROUND_TRUTH_MAPPING.get(ev_type, "BENIGN_SYSTEM_ACTIVITY")
            self.class_counts[target_class] += 1
            for f in extract_features(ev):
                self.vocab.add(f)
                self.feature_counts[target_class][f] = self.feature_counts[target_class].get(f, 0) + 1

    def predict_proba(self, event: Dict[str, Any]) -> Dict[str, float]:
        features = extract_features(event)
        log_probs = {}
        vocab_size = max(1, len(self.vocab))

        for c in self.classes:
            prior = math.log((self.class_counts[c] + 1) / (self.total_docs + len(self.classes)))
            total_class_tokens = sum(self.feature_counts[c].values()) + vocab_size
            likelihood = 0.0
            for f in features:
                count = self.feature_counts[c].get(f, 0) + 1
                likelihood += math.log(count / total_class_tokens)
            log_probs[c] = prior + likelihood

        # Softmax normalization
        max_log = max(log_probs.values())
        exp_scores = {c: math.exp(score - max_log) for c, score in log_probs.items()}
        sum_exp = sum(exp_scores.values())
        return {c: exp_scores[c] / sum_exp for c in self.classes}

    def predict(self, event: Dict[str, Any]) -> Dict[str, Any]:
        probas = self.predict_proba(event)
        best_class = max(probas.items(), key=lambda x: x[1])
        category = best_class[0]
        confidence = round(best_class[1] * 100, 1)
        rec = RECOMMENDED_ACTIONS.get(category, RECOMMENDED_ACTIONS["BENIGN_SYSTEM_ACTIVITY"])

        return {
            "threat_category": category,
            "confidence_percent": confidence,
            "urgency": rec["urgency"],
            "recommended_action": rec["action"],
            "resolution_hint": rec["resolution_hint"],
            "probabilities": {k: round(v * 100, 1) for k, v in probas.items()},
        }


def load_dataset() -> List[Dict[str, Any]]:
    # Read token from .env
    env = {}
    if os.path.exists(".env"):
        for line in open(".env", encoding="utf-8"):
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                env[k] = v
    token = env.get("MONOLITH_OPERATOR_TOKEN", "")
    req = urllib.request.Request(
        "http://localhost:3000/api/incidents?status=all&limit=500",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode())
        return data.get("incidents", [])


def main():
    events = load_dataset()
    print(f"[*] Loaded {len(events)} security events from Black Monolith ledger.")
    model = FastTriageClassifier()
    model.fit(events)

    # Evaluate accuracy
    correct = 0
    class_eval = {c: {"tp": 0, "fp": 0, "fn": 0} for c in CLASSES}
    for ev in events:
        true_class = GROUND_TRUTH_MAPPING.get(ev.get("event_type", ""), "BENIGN_SYSTEM_ACTIVITY")
        pred = model.predict(ev)
        pred_class = pred["threat_category"]
        if pred_class == true_class:
            correct += 1
            class_eval[true_class]["tp"] += 1
        else:
            class_eval[pred_class]["fp"] += 1
            class_eval[true_class]["fn"] += 1

    acc = (correct / len(events)) * 100 if events else 0.0
    print("\n=======================================================")
    print("  BLACK MONOLITH ML INCIDENT TRIAGE CLASSIFIER")
    print("=======================================================")
    print(f"Overall Model Accuracy: {acc:.2f}%\n")
    print(f"{'Threat Category':<32} {'Precision':<10} {'Recall':<10} {'F1-Score':<10}")
    print("-" * 64)
    for c in CLASSES:
        tp = class_eval[c]["tp"]
        fp = class_eval[c]["fp"]
        fn = class_eval[c]["fn"]
        prec = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 100.0
        rec = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 100.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        print(f"{c:<32} {prec:6.1f}%    {rec:6.1f}%    {f1:6.1f}%")

    print("\n[*] Sample Recent Incident Inference:")
    sample = events[0] if events else None
    if sample:
        res = model.predict(sample)
        print(f"  Event ID:           {sample.get('event_id')}")
        print(f"  Module / Type:      {sample.get('module')} -> {sample.get('event_type')}")
        print(f"  Predicted Category: {res['threat_category']} ({res['confidence_percent']}% confidence)")
        print(f"  Urgency Level:      {res['urgency']}")
        print(f"  Recommended Action: {res['recommended_action']}")
    print("=======================================================\n")


if __name__ == "__main__":
    main()
