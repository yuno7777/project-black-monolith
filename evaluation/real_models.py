"""Held-out evaluation with real Ollama models and semantic embeddings.

This command never substitutes mock output when an external model is missing.
It records detector behavior, not whether an attack prompt actually compromised
an agent. Prompt labels and observed output-secret presence are separate metrics.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import statistics
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(__file__).with_name("held_out.json")


def summarize(rows):
    tp = sum(r["attack"] and r["detected"] for r in rows)
    fp = sum(not r["attack"] and r["detected"] for r in rows)
    fn = sum(r["attack"] and not r["detected"] for r in rows)
    tn = sum(not r["attack"] and not r["detected"] for r in rows)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "attack_prompt_detection_rate": tp / (tp + fn) if tp + fn else None,
        "benign_false_positive_rate": fp / (fp + tn) if fp + tn else None,
    }


def percentile(values, fraction):
    return (
        sorted(values)[min(len(values) - 1, int((len(values) - 1) * fraction))] if values else None
    )


def validate_dataset(data):
    calibration = data["calibration"]
    rows = data["evaluation"]
    prompts = calibration + [row["prompt"] for row in rows]
    if len(set(prompts)) != len(prompts):
        raise ValueError("Calibration and evaluation prompts must be unique and disjoint")
    if (
        not calibration
        or not any(r["attack"] for r in rows)
        or not any(not r["attack"] for r in rows)
    ):
        raise ValueError("Dataset needs calibration, attacks, and benign evaluation cases")


def ollama_json(base, path, payload=None):
    request = urllib.request.Request(
        base.rstrip("/") + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


async def evaluate_trace(args, data):
    sys.path.insert(0, str(ROOT / "trace-audit"))
    from src.config import load_config
    from src.divergence_monitor import DivergenceMonitor, build_distribution
    from src.pii_scanner import scan
    from src.stream_proxy import PiiStreamBuffer, _backend_stream

    os.environ["MONOLITH_MODEL_BACKEND"] = "ollama"
    os.environ["MONOLITH_OLLAMA_MODEL"] = args.model
    os.environ["MONOLITH_OLLAMA_URL"] = args.ollama_url
    cfg = load_config()
    metadata = ollama_json(args.ollama_url, "/api/show", {"model": args.model})
    tags = ollama_json(args.ollama_url, "/api/tags")["models"]
    model_digest = next(
        (m["digest"] for m in tags if m.get("name") in (args.model, args.model + ":latest")), None
    )
    baseline_tokens = []
    for prompt in data["calibration"]:
        baseline_tokens += [t async for t in _backend_stream(prompt, args.max_tokens, cfg)]
    if not baseline_tokens:
        raise ValueError("Model returned no calibration output")
    baseline = build_distribution(baseline_tokens)
    rows = []
    timings = []
    for case in data["evaluation"]:
        monitor = DivergenceMonitor(
            baseline_counts=baseline,
            threshold=cfg.kl_threshold,
            window_size=cfg.window_size,
            min_tokens_before_check=cfg.min_tokens_before_check,
            smoothing=cfg.smoothing,
        )
        buffer = PiiStreamBuffer()
        raw = []
        protected = []
        detected = False
        first_release = None
        started = time.perf_counter()
        async for token in _backend_stream(case["prompt"], args.max_tokens, cfg):
            raw.append(token)
            before = time.perf_counter()
            kl = monitor.observe(token)
            drain = buffer.push(token, kl)
            detected = detected or monitor.is_divergent(kl) or bool(drain.matches)
            timings.append((time.perf_counter() - before) * 1000)
            if drain.outputs and first_release is None:
                first_release = (time.perf_counter() - started) * 1000
            protected.extend(t.token for t in drain.outputs)
        drained = buffer.finish()
        if drained.outputs and first_release is None:
            first_release = (time.perf_counter() - started) * 1000
        protected.extend(t.token for t in drained.outputs)
        detected = detected or bool(drained.matches)
        raw_text, protected_text = "".join(raw), "".join(protected)
        matches = scan(raw_text)
        rows.append(
            {
                "id": case["id"],
                "category": case["category"],
                "attack": case["attack"],
                "detected": detected,
                "raw_output_sha256": hashlib.sha256(raw_text.encode()).hexdigest(),
                "output_contains_detectable_secret": bool(matches),
                "secret_survived_redaction": any(m.value in protected_text for m in matches),
                "generation_ms": (time.perf_counter() - started) * 1000,
                "first_safe_fragment_ms": first_release,
            }
        )
    return {
        "layer": "trace-audit",
        "backend": "ollama",
        "model": args.model,
        "model_digest": model_digest,
        "model_details": metadata.get("details"),
        "generation_options": {"num_predict": args.max_tokens, "other_options": "Ollama model defaults; stochastic outputs"},
        "resident_models": ollama_json(args.ollama_url, "/api/ps").get("models", []),
        "policy_version": "trace-audit/2",
        "threshold": cfg.kl_threshold,
        "baseline_sha256": hashlib.sha256(
            json.dumps(baseline, sort_keys=True).encode()
        ).hexdigest(),
        "summary": summarize(rows),
        "by_category": {
            category: summarize([r for r in rows if r["category"] == category])
            for category in sorted({r["category"] for r in rows})
        },
        "audit_overhead_ms": {
            "p50": percentile(timings, 0.5),
            "p95": percentile(timings, 0.95),
            "mean": statistics.mean(timings),
        },
        "cases": rows,
    }


def evaluate_vector(data):
    sys.path.insert(0, str(ROOT / "vector-anchor"))
    from src.config import load_config
    from src.frequency_tracker import FrequencyTracker
    from src.store import build_embedding_function
    from src.retriever_proxy import RetrieverProxy
    from src.quarantine import Quarantine
    import chromadb
    import uuid

    os.environ["MONOLITH_EMBEDDING"] = "default"
    cfg = load_config()
    embedding = build_embedding_function(cfg)
    corpus = data["retrieval"]["documents"]
    vectors = embedding([doc["text"] for doc in corpus])
    tracker = FrequencyTracker(
        min_distinct_topics=cfg.min_distinct_topics,
        topic_similarity=cfg.topic_similarity,
        retention_horizon=cfg.retention_horizon,
        max_queries_per_doc=cfg.max_queries_per_doc,
    )
    client = chromadb.EphemeralClient()
    collection = client.create_collection("eval-" + uuid.uuid4().hex,
                                          metadata={"hnsw:space": "cosine"})
    collection.add(ids=[doc['id'] for doc in corpus],
                   documents=[doc['text'] for doc in corpus], embeddings=vectors)
    proxy = RetrieverProxy(collection=collection, embed_fn=embedding, tracker=tracker,
                           quarantine=Quarantine(), cfg=cfg, emit=lambda *a, **k: None)
    times = []
    detected = set()
    for query in data["retrieval"]["queries"]:
        before = time.perf_counter()
        result = proxy.retrieve(query)
        detected.update(doc['id'] for doc in result['withheld'])
        times.append((time.perf_counter() - before) * 1000)
    rows = [
        {"id": doc["id"], "attack": doc["attack"], "detected": doc["id"] in detected}
        for doc in corpus
    ]
    return {
        "layer": "vector-anchor",
        "embedding": "Chroma DefaultEmbeddingFunction / all-MiniLM-L6-v2",
        "policy_version": "vector-anchor/2",
        "thresholds": {
            "min_distinct_topics": cfg.min_distinct_topics,
            "topic_similarity": cfg.topic_similarity,
            "top_rank_threshold": cfg.top_rank_threshold,
        },
        "summary": summarize(rows),
        "cases": rows,
        "retrieval_with_embedding_ms": {"p95": percentile(times, 0.95)},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("layer", choices=["trace", "vector"])
    parser.add_argument("--model", default="llama3.2:1b")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument("--max-tokens", type=int, default=128)
    parser.add_argument("--dataset", type=Path, default=DATA)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--external", type=Path)
    args = parser.parse_args()
    data = json.loads(args.dataset.read_text(encoding="utf-8"))
    if args.external:
        external = json.loads(args.external.read_text(encoding="utf-8"))
        # Fixed hash ordering, eight cases per class. Test data never calibrates.
        for label in (False, True):
            data["evaluation"].extend([r for r in external["cases"] if r["attack"] == label][:8])
    validate_dataset(data)
    result = (
        asyncio.run(evaluate_trace(args, data)) if args.layer == "trace" else evaluate_vector(data)
    )
    if args.external:
        result["external_dataset_sha256"] = hashlib.sha256(args.external.read_bytes()).hexdigest()
    try:
        import resource
        result["client_peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
    except ImportError:
        result["client_peak_rss_bytes"] = None
    result["dataset_sha256"] = hashlib.sha256(args.dataset.read_bytes()).hexdigest()
    result["limitations"] = [
        "Small authored held-out corpus; not a field-accuracy estimate.",
        "Attack prompt labels do not prove model compromise. Thresholds are not tuned on evaluation cases.",
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"]))


if __name__ == "__main__":
    main()
