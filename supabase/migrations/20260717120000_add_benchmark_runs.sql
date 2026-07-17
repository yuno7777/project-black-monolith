-- Detection-benchmark ledger.
--
-- Benchmark results are evaluation metadata, NOT security events: they must
-- never enter monolith.security_events or be counted as detections. They live
-- in their own table, one row per (run, module, detector), so a single
-- invocation of the benchmark suite is one `run_id` grouping several detector
-- scorecards.

create table if not exists monolith.benchmark_runs (
  run_id uuid not null,
  benchmark_version smallint not null default 1,
  run_at timestamptz not null default now(),
  git_commit text,
  module text not null check (module in ('mcp-shield', 'vector-anchor', 'trace-audit')),
  detector text not null,
  -- How the detector decides, so the dashboard can label an exact/deterministic
  -- detector honestly rather than as a tuned one.
  paradigm text not null check (paradigm in ('threshold', 'exact', 'regex')),

  attack_samples integer not null check (attack_samples >= 0),
  benign_samples integer not null check (benign_samples >= 0),

  -- Confusion matrix. Non-negative; the derived metrics are recomputed on read
  -- from these rather than trusted, so a bad rate cannot be stored.
  tp integer not null check (tp >= 0),
  fp integer not null check (fp >= 0),
  tn integer not null check (tn >= 0),
  fn integer not null check (fn >= 0),

  detection_rate numeric(6, 4) not null check (detection_rate between 0 and 1),
  false_positive_rate numeric(6, 4) not null check (false_positive_rate between 0 and 1),
  precision numeric(6, 4) not null check (precision between 0 and 1),
  recall numeric(6, 4) not null check (recall between 0 and 1),
  f1 numeric(6, 4) not null check (f1 between 0 and 1),

  -- Detector overhead, microseconds. Null when a detector does not carry it.
  latency_p50_us numeric,
  latency_p95_us numeric,
  latency_p99_us numeric,

  thresholds jsonb not null default '{}'::jsonb,
  notes text,

  primary key (run_id, module, detector)
);

create index if not exists benchmark_runs_run_at_idx
  on monolith.benchmark_runs (run_at desc);
create index if not exists benchmark_runs_module_detector_idx
  on monolith.benchmark_runs (module, detector, run_at desc);

alter table monolith.benchmark_runs enable row level security;
revoke all on monolith.benchmark_runs from public, anon, authenticated;
