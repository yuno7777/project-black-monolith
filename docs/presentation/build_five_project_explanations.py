from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle,
    KeepTogether, HRFlowable
)
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.lib.colors import HexColor
from reportlab.platypus.tableofcontents import TableOfContents
from pathlib import Path

OUT = Path("output/five-project-explanations-expanded-v2.pdf")
OUT.parent.mkdir(parents=True, exist_ok=True)

PAGE_W, PAGE_H = letter
INK = HexColor("#16181d")
MUTED = HexColor("#59616d")
LAVENDER = HexColor("#7665a8")
LAVENDER_LIGHT = HexColor("#f0edfa")
BLUE_LIGHT = HexColor("#edf4fb")
GREEN_LIGHT = HexColor("#edf7f1")
AMBER_LIGHT = HexColor("#fff6df")
RED_LIGHT = HexColor("#fff0f0")

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=29, leading=34, textColor=INK, alignment=TA_CENTER, spaceAfter=16))
styles.add(ParagraphStyle(name="CoverSub", parent=styles["Normal"], fontName="Helvetica", fontSize=12, leading=18, textColor=MUTED, alignment=TA_CENTER, spaceAfter=10))
styles.add(ParagraphStyle(name="Kicker", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=LAVENDER, tracking=1.1, spaceAfter=6))
styles.add(ParagraphStyle(name="H1x", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=20, leading=25, textColor=INK, spaceBefore=8, spaceAfter=9, keepWithNext=True))
styles.add(ParagraphStyle(name="H2x", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=13, leading=17, textColor=LAVENDER, spaceBefore=12, spaceAfter=5, keepWithNext=True))
styles.add(ParagraphStyle(name="H3x", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=INK, spaceBefore=8, spaceAfter=3, keepWithNext=True))
styles.add(ParagraphStyle(name="Bodyx", parent=styles["BodyText"], fontName="Helvetica", fontSize=9.6, leading=14.2, textColor=INK, spaceAfter=7))
styles.add(ParagraphStyle(name="Smallx", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.2, leading=11.2, textColor=MUTED, spaceAfter=5))
styles.add(ParagraphStyle(name="Bulletx", parent=styles["BodyText"], fontName="Helvetica", fontSize=9.4, leading=13.7, textColor=INK, leftIndent=13, firstLineIndent=-8, bulletIndent=0, spaceAfter=4))
styles.add(ParagraphStyle(name="Quote", parent=styles["BodyText"], fontName="Helvetica-Oblique", fontSize=10.2, leading=15, textColor=INK, leftIndent=12, rightIndent=12, spaceAfter=7))
styles.add(ParagraphStyle(name="TableHead", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=8.3, leading=10, textColor=colors.white, spaceAfter=0))
styles.add(ParagraphStyle(name="TableCell", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.1, leading=10.5, textColor=INK, spaceAfter=0))
styles.add(ParagraphStyle(name="TableCellBold", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=8.1, leading=10.5, textColor=INK, spaceAfter=0))
styles.add(ParagraphStyle(name="FundCell", parent=styles["BodyText"], fontName="Helvetica", fontSize=7.6, leading=9.2, textColor=INK, spaceAfter=0))
styles.add(ParagraphStyle(name="FundCellBold", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=7.6, leading=9.2, textColor=INK, spaceAfter=0))

def P(text, style="Bodyx"):
    return Paragraph(text, styles[style])

def bullet(text):
    return Paragraph("- " + text, styles["Bulletx"])

def callout(label, text, fill=LAVENDER_LIGHT):
    t = Table([[P(f"<b>{label}</b><br/>{text}", "Bodyx")]], colWidths=[6.55*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), fill),
        ("BOX", (0,0), (-1,-1), 0.5, HexColor("#d5d0e9")),
        ("LEFTPADDING", (0,0), (-1,-1), 11), ("RIGHTPADDING", (0,0), (-1,-1), 11),
        ("TOPPADDING", (0,0), (-1,-1), 8), ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    return KeepTogether([t, Spacer(1, 8)])

def comparison_table(rows):
    data = [[P("Project", "TableHead"), P("Plain-English purpose", "TableHead"), P("Main boundary", "TableHead")]]
    for a,b,c in rows:
        data.append([P(a, "TableCellBold"), P(b, "TableCell"), P(c, "TableCell")])
    t = Table(data, colWidths=[1.18*inch, 3.25*inch, 2.12*inch], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), LAVENDER),
        ("GRID", (0,0), (-1,-1), 0.35, HexColor("#d8dbe2")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, HexColor("#fafbfc")]),
        ("LEFTPADDING", (0,0), (-1,-1), 7), ("RIGHTPADDING", (0,0), (-1,-1), 7),
        ("TOPPADDING", (0,0), (-1,-1), 7), ("BOTTOMPADDING", (0,0), (-1,-1), 7),
    ]))
    return t

def judgment_table(rows):
    data = [[P("Engineering question", "TableHead"), P("Project-specific answer", "TableHead")]]
    for label, answer in rows:
        data.append([P(label, "FundCellBold"), P(answer, "FundCell")])
    t = Table(data, colWidths=[1.6*inch, 4.95*inch], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), LAVENDER),
        ("GRID", (0,0), (-1,-1), 0.35, HexColor("#d8dbe2")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, HexColor("#fafbfc")]),
        ("LEFTPADDING", (0,0), (-1,-1), 6), ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 5), ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    return t

def section_title(num, name):
    return [P(f"{num}  {name}", "H1x"), HRFlowable(width="100%", thickness=0.7, color=HexColor("#d9dce3"), spaceAfter=10)]

def project_header(name, tagline, path):
    return [P(tagline.upper(), "Kicker"), P(name, "H1x"), P(f"Repository: {path}", "Smallx")]

def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(HexColor("#d9dce3")); canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, 0.52*inch, PAGE_W-doc.rightMargin, 0.52*inch)
    canvas.setFont("Helvetica", 7.7); canvas.setFillColor(MUTED)
    canvas.drawString(doc.leftMargin, 0.34*inch, "Five-project engineering explanation")
    canvas.drawRightString(PAGE_W-doc.rightMargin, 0.34*inch, f"{doc.page}")
    canvas.restoreState()

story = []

# Cover
story += [Spacer(1, 1.0*inch), P("FIVE PROJECTS, EXPLAINED", "Kicker"), P("What I built, why I built it, and how it really works", "CoverTitle"),
          P("A plain-language engineering guide to five AI, automation, operations, and security codebases", "CoverSub"), Spacer(1, 0.3*inch),
          HRFlowable(width="42%", thickness=2, color=LAVENDER, spaceAfter=22),
          P("Prepared from the repositories and their implementation documentation. The attached QuickMove hiring assignment was used as context for the StampMyVisa explanation; its instructions were not treated as instructions for this report.", "CoverSub"),
          Spacer(1, 1.0*inch), P("September 2026", "CoverSub"), PageBreak()]

story += section_title("Overview", "The common thread")
story += [P("These five projects look different on the surface: one protects AI agents, one automates an X account, one runs research and data analysis, one is a multi-tenant learning platform, and one is an operations copilot. The common thread is that each turns a messy human workflow into a visible, repeatable system.")]
story += [P("They are not all at the same maturity level. Black Monolith and LearnFlow are the most deliberate about security and system boundaries. Aether Analyst is the most ambitious agentic research experience. Twit-auto is the most operationally autonomous, but also the most exposed to the fragility and policy risk of browser automation. StampMyVisa is intentionally a narrow, deterministic MVP: a small workflow chosen to fit the assignment time limit and to be usable by an operations person immediately.")]
story += [callout("How to read this report", "For every project, the same questions are answered: What is it? Why was it built? How was it built? What happens from input to result? What is genuinely impressive? What should not be overstated?", BLUE_LIGHT)]
story += [P("At a glance", "H2x"), comparison_table([
    ("Black Monolith", "Security checkpoints for agent tools, retrieval, and model output.", "Cannot protect traffic that is not routed through it; cannot see closed-model internals."),
    ("Twit-auto", "A self-pacing X growth operator that researches, writes, critiques, and engages.", "Browser UI can change or trigger platform restrictions; one local JSON file is the shared database."),
    ("Aether Analyst", "A research and data-analysis agent that can browse, run code, make charts, and write reports.", "Code execution, web data, model output, and memory need stronger isolation for serious production use."),
    ("LearnFlow AI", "A multi-tenant learning platform with grounded RAG, courses, assessments, and workflows.", "Several production security features remain explicit gaps, including MFA/SSO, API-key scopes, encryption, and virus scanning."),
    ("StampMyVisa", "A focused relocation-operations copilot that turns pasted case notes into one next action.", "Stateless decision support; no direct WhatsApp, Sheets, or email integration yet."),
])]
story += [PageBreak()]

# Black Monolith
story += project_header("Project Black Monolith", "AI-agent security middleware", r"C:\Users\Abhishek Satarkar\Desktop\project-black-monolith")
story += [P("What it is", "H2x"), P("Black Monolith is a set of security checkpoints that sit around an autonomous AI agent. The agent may call tools, search a knowledge base, and stream a model response. Black Monolith watches those three surfaces, makes an independent security decision at each one, and sends a durable record to a shared dashboard.")]
story += [P("The memorable version is: a firewall and incident recorder built for agents.", "Quote")]
story += [P("Why it was built", "H2x"), P("You built it because an agent does not have one attack surface. A tool can change after approval. A malicious document can poison retrieval. A model can expose a secret while generating an answer. Protecting only the prompt or only the final answer leaves the other paths open. The project is therefore a defense-in-depth experiment: intercept, analyze, block or clean, persist the evidence, and let a person investigate.")]
story += [P("How it was built", "H2x"), bullet("MCP-Shield is a Rust proxy for MCP traffic. It fingerprints approved tool schemas, scans descriptions for suspicious instructions, and can restore a trusted schema when a later response changes."), bullet("VectorAnchor is a Python retrieval service. It watches which documents repeatedly rank highly across unrelated queries, then quarantines suspicious documents and returns a clean alternative."), bullet("TraceAudit is a Python streaming proxy in front of a model endpoint. It scans generated text for credentials and PII, redacts matches before forwarding, and can terminate a strongly divergent stream."), bullet("The dashboard is the control plane. It stores authenticated, tenant-aware events in PostgreSQL, publishes live updates, keeps incident decisions separate from immutable evidence, and exposes investigation and benchmark views."), bullet("Each module has a durable local outbox. If the dashboard is down, the detection is queued and retried instead of being silently lost.")]
story += [P("How one task moves through it", "H2x"), P("A user asks an agent to deploy an application. MCP-Shield checks the deployment tool definition before the agent can trust it. VectorAnchor checks the deployment documents before they become context. TraceAudit checks the model stream before it reaches the user. The dashboard correlates all three events by tenant, agent, and session so an operator can see one chain instead of three disconnected warnings.")]
story += [callout("What it actually does", "It protects only the interfaces you route through it. The normal ChatGPT website or hosted Codex interface does not expose every internal tool, reasoning step, or model stream to your service. Full coverage requires an agent application whose tool, retrieval, and model calls you control.", AMBER_LIGHT)]
story += [P("Pain points while building it", "H2x"), bullet("The three modules use different languages and runtimes, so one shared event contract had to stay compatible across Rust, Python, TypeScript, PostgreSQL, and the dashboard."), bullet("Reliable evidence delivery was harder than simply emitting a log: the outboxes, retries, dead letters, deduplication, authentication, and persist-before-publish order all had to agree."), bullet("Security fixes often exposed setup assumptions, such as database compatibility roles, environment secrets, and whether a service was merely healthy versus actually populated with attack fixtures."), bullet("Detector calibration required separating real improvements from overfitting small synthetic corpora. Thresholds had to be measured against benign cases, not guessed."), bullet("The project had to preserve evidence without storing raw queries, corpus contents, or secrets, which made telemetry design more careful.")]
story += [P("What is genuinely strong", "H2x"), bullet("Clear separation of enforcement modules and a shared event contract."), bullet("Fail-closed authentication and tenant-aware evidence storage in the dashboard."), bullet("Durable delivery, deduplication, append-only incident history, and reproducible detector scorecards."), bullet("Honest calibration: the project records where synthetic benchmarks are imperfect instead of claiming universal accuracy.")]
story += [P("Utmost limitations, even in a future complete version", "H2x"), bullet("It cannot guarantee that an agent is safe; it can only observe known signals and enforce configured policies."), bullet("It cannot inspect private model reasoning or neural activity that a provider never exposes."), bullet("It cannot stop a bypass route. Network and permission controls must prevent the agent from calling the real tool directly."), bullet("Fingerprinting proves change from a trusted baseline, not that the first-seen tool was safe."), bullet("Retrieval anomaly detection needs repeated evidence and may miss slow, targeted, or one-off poisoning."), bullet("Pattern scanners can miss secrets that do not resemble known formats, while aggressive rules can create false positives."), bullet("It does not establish that a document is true or that an agent decision is correct.")]
story += [P("Engineering judgment for Black Monolith", "H2x"), judgment_table([
    ("Deliberately not built", "No universal sandbox, truth checker, or private-reasoning monitor; the project focuses on observable tool, retrieval, and streaming boundaries."),
    ("Trust boundaries", "MCP server to agent, documents to model context, model tokens to user, and module events to the dashboard."),
    ("Failure recovery", "Durable outboxes retry temporary failures, dead-letter permanent failures, and deduplicate redelivery by event ID."),
    ("Evidence", "Deterministic fixtures and scorecards prove defined synthetic cases, not universal field accuracy."),
    ("Security owner", "Modules enforce narrow policies; deployment closes bypasses; operators investigate and approve policy changes."),
    ("Cost and scale", "Embeddings, stream inspection, event retention, shared state, and operator attention become expensive first."),
    ("Human model", "Operators approve tools, investigate alerts, tune policy, resolve dead letters, and preserve evidence."),
    ("First next step", "Integrate one real agent runtime and prove that direct tool, retrieval, and model bypass routes are closed."),
])]
story += [callout("Bottom line", "Black Monolith is an observability-and-enforcement layer for agent interactions, not a universal AI safety guarantee. Its strongest contribution is making invisible agent risks observable, blockable, and investigable.", GREEN_LIGHT), PageBreak()]

# Twit-auto
story += project_header("Twit-auto / Twitter Growth System", "Autonomous social account operations", r"C:\Users\Abhishek Satarkar\Desktop\projects\twit-auto")
story += [P("What it is", "H2x"), P("Twit-auto is a Windows-first, single-account X/Twitter growth system. It researches what is trending, asks language models to select source-backed topics, writes posts and replies in a configured voice, critiques drafts, and uses a persistent real Chrome profile to read and act on X. A local dashboard exposes controls, history, analytics, memory, logs, and an approval queue.")]
story += [P("Why it was built", "H2x"), P("The goal is to remove repetitive work from a technical account owner's routine without turning the account into an uncontrolled spam bot. The system tries to spread activity out, use a daily action ceiling, pause on account-health warnings, keep a queue for off-peak drafts, and let the owner approve or edit work before it is posted.")]
story += [P("How it was built", "H2x"), bullet("A Python bot owns the scheduler, state, browser actions, limits, prompts, and external research."), bullet("A FastAPI process is a local control bridge: it reads and mutates the shared state, serves logs and history, and handles the Friday planning chat."), bullet("A Next.js dashboard is the operator surface; it never drives Playwright directly."), bullet("Playwright uses a persistent installed Chrome profile rather than a password stored in code. Cookies are saved after a manual first login."), bullet("The intelligence layer gathers GitHub, Hacker News, Reddit, newsletter, and creator signals, then uses a three-tier model cascade with rate-limit cooldown memory."), bullet("A pre-flight critic scores hook, voice, value, grounding, and predicted engagement. Low scores trigger regeneration attempts, and a queue supports human review.")]
story += [P("How one cycle works", "H2x"), P("The bot loads state and current limits, checks whether the daily ceiling has been reached, opens Chrome, verifies account health, gathers trend and performance signals, asks the strategy model what to search and discuss, generates content, runs the critic, and then performs bounded likes, replies, quotes, reposts, follows, or posts. It updates history and cooldowns, closes the browser, and sleeps until the next checkpoint. The dashboard reads the same state and shows what happened.")]
story += [P("Why the architecture makes sense", "H2x"), P("Separate Python and Next.js processes keep browser and provider dependencies out of the UI and make a local Windows launch simple. Browser automation was chosen because many useful X flows are web-only and a paid API was not required. Local JSON was chosen for zero setup and portability. Those choices are sensible for a personal prototype, but they deliberately trade away transactions, isolation, and scale.")]
story += [P("Pain points while building it", "H2x"), bullet("X is a moving target: selectors, login checks, rendered analytics, rate limits, and anti-bot behaviour can change without warning."), bullet("The bot, FastAPI bridge, and dashboard are separate processes but share one JSON state file, so atomic writes and merge rules matter whenever two sides update the same record."), bullet("The model cascade introduces uneven quality and quotas. Cooldown memory reduces wasted calls, but it cannot make fallback providers equivalent."), bullet("A critic that retries drafts sounds like a safety system, but deciding what to do after repeated failures exposed the difference between ranking content and truly blocking it."), bullet("The workflow combines many small actions, so a failure in one browser step must not incorrectly mark the whole cycle as successful or repeat an already completed action.")]
story += [P("What is genuinely strong", "H2x"), bullet("It is more than a scheduler: it has research, drafting, criticism, approval, learning from top and bottom performers, account health checks, and backoff."), bullet("The model cascade remembers rate limits instead of repeatedly calling a provider that is already throttling."), bullet("The product preserves a human approval path for off-peak drafts and a dry-run mode for testing."), bullet("The existing project understanding guide distinguishes implemented behavior from README promises; live X growth and cost claims remain unmeasured.")]
story += [P("Utmost limitations", "H2x"), bullet("X can change its DOM, selectors, login flows, rate limits, or enforcement policies at any time. Browser automation is brittle and policy-sensitive."), bullet("One JSON document acts as database, queue, control plane, memory, analytics store, and audit log. Concurrent writers can lose updates or leave inconsistent state."), bullet("The critic is a ranking and retry layer, not a hard safety barrier: after its retry budget, the best attempt can still be posted."), bullet("The system does not prove audience growth, reproduce X ranking, or establish that engagement is authentic or sustainable."), bullet("A persistent browser profile and cookies are high-value local secrets. A production design would need stronger secret storage, isolation, access control, and recovery."), bullet("The system is single-user and local; multi-account or team operation needs a real database, job queue, tenant model, and audit system."), bullet("Model fallback changes quality and behavior, so output is not consistent across providers.")]
story += [P("Engineering judgment for Twit-auto", "H2x"), judgment_table([
    ("Deliberately not built", "No multi-account SaaS, official-API platform, or team approval system; it stayed a personal Windows operator."),
    ("Trust boundaries", "Trend sources to prompts, model drafts to actions, Playwright to X, cookies to account authority, and dashboard commands to state."),
    ("Failure recovery", "Cooldowns, backoff, caps, screenshots, saved state, health checks, and distinct completed-versus-failed actions."),
    ("Evidence", "Logs, histories, critic scores, and evaluation cases exist; real growth, cost, and long-term account safety remain unproven."),
    ("Security owner", "The account owner protects cookies, sets limits, approves drafts, monitors warnings, and remains responsible for platform compliance."),
    ("Cost and scale", "Browser time, LLM quotas, profile storage, and maintenance grow first; multiple accounts need isolation, workers, and a database."),
    ("Human model", "The owner logs in, reviews drafts, adjusts voice and limits, pauses activity, and handles account warnings."),
    ("First next step", "Replace the shared JSON state with a transactional database and job ledger before adding accounts or cloud scale."),
])]
story += [callout("Bottom line", "Twit-auto is an ambitious personal operations robot. Its cleverness is in orchestration and guardrails around browser automation, not in proving that an LLM can reliably grow an account by itself.", RED_LIGHT), PageBreak()]

# Aether Analyst
story += project_header("Aether Analyst", "Autonomous research and data-analysis workspace", r"C:\Users\Abhishek Satarkar\Desktop\niche-project\aetheranalyst")
story += [P("What it is", "H2x"), P("Aether Analyst is a full-stack research and data-analysis assistant. A user uploads a CSV, Excel file, PDF, or text prompt. The agent can research the web and ArXiv, read files, write and execute Python for exact analysis, generate charts, and compile a styled PDF report. It exposes the work as a live stream of thoughts, tool calls, observations, plots, and final outputs.")]
story += [P("Why it was built", "H2x"), P("Research and analysis are usually fragmented across a browser, academic search, Jupyter, spreadsheets, charting tools, and a document editor. Aether Analyst tries to make that whole chain feel like one workspace. The deeper design motivation is to combine the flexibility of a conversational model with deterministic computation: the model decides what to do, but Python calculates the numbers.")]
story += [P("How it was built", "H2x"), bullet("Next.js and React provide the interactive dashboard. The browser opens a long-lived Server-Sent Events stream so the user can watch progress as it happens."), bullet("FastAPI accepts uploads and chat requests, creates a run, and executes the agent in a background task."), bullet("AgentCore implements a ReAct loop: the model proposes a thought and action, a tool runs, the observation is added to history, and the model decides the next step."), bullet("Research, analyst, and combined personas load different tool sets. Tools include web search, ArXiv retrieval, file reading, EDA, code execution, and report generation."), bullet("SQLite stores sessions, runs, messages, and reports. ChromaDB stores semantic memory, while a Markdown memory file holds durable identity or episodic notes."), bullet("ReportLab, Matplotlib, Seaborn, Pandas, NumPy, and Scikit-Learn turn the agent's work into charts and downloadable reports.")]
story += [P("How a request works", "H2x"), P("The user submits a prompt and optional file. The UI receives a run ID and opens an SSE stream. Gemini may first search the web or inspect the uploaded file, then request a Python tool. The backend executes that tool in a subprocess, sends back the observation, and repeats the loop. When charts or a report are produced, dedicated stream events make them visible in the chat. The final message and report metadata are saved to SQLite and the conversation is added to memory.")]
story += [P("Pain points while building it", "H2x"), bullet("The ReAct loop has to turn a probabilistic model response into a safe, valid tool call, then turn arbitrary tool output—including tracebacks—back into useful context."), bullet("SSE made long-running work visible, but reconnects, in-memory run queues, cancellation, and process restarts are harder than a normal request-response page."), bullet("Generated Python and uploaded files create a security boundary: useful analysis requires capability, while production safety requires strict limits on files, network, resources, and packages."), bullet("The two memory systems serve different purposes. Keeping identity notes, chat history, embeddings, and report files consistent without confusing stale recall is an ongoing design problem."), bullet("The split Vercel, Nginx, and EC2 deployment introduces real operational concerns—timeouts, buffering, static files, HTTPS, and service restarts—that a local demo can hide.")]
story += [P("What is genuinely strong", "H2x"), bullet("The ReAct loop turns an LLM into an orchestrator that can recover from tool observations instead of only writing suggestions."), bullet("Exact computations happen in code, reducing the risk of mental arithmetic and invented statistics."), bullet("The product exposes the execution trace, making the agent's process more understandable to a user."), bullet("The three modes make the same engine useful for research, analysis, or a combined workflow."), bullet("The split Vercel frontend / AWS FastAPI backend with Nginx and SSE is a coherent small-production topology.")]
story += [P("Utmost limitations", "H2x"), bullet("The agent can execute generated Python. A subprocess is not automatically a strong sandbox: filesystem, network, CPU, memory, and package access need explicit isolation before untrusted users or files are allowed."), bullet("Web scraping is fragile, source quality varies, and live pages can change or contain malicious content."), bullet("The model can choose the wrong tool, misunderstand a dataset, or draw an invalid conclusion even when the arithmetic is correct."), bullet("Semantic memory can retrieve a plausible but stale or irrelevant past message; embeddings do not prove truth."), bullet("The in-memory run event queues make live streaming vulnerable to process restarts unless the run state is reconstructed from durable records."), bullet("SQLite and local files are convenient but are not enough for concurrent, multi-user, highly available production workloads."), bullet("A generated PDF can look authoritative while still reflecting incomplete data or a wrong analysis.")]
story += [P("Engineering judgment for Aether Analyst", "H2x"), judgment_table([
    ("Deliberately not built", "No unrestricted public code-execution service and no claim that generated analysis is automatically correct."),
    ("Trust boundaries", "User files, external web content, model-selected tools, generated Python execution, report outputs, and recalled memories."),
    ("Failure recovery", "Tool errors return as observations, but durable jobs and resumable event history are still needed for restart-safe runs."),
    ("Evidence", "Traces, calculations, charts, sources, and reports show what ran; they do not automatically validate the scientific conclusion."),
    ("Security owner", "The backend owns isolation and secrets; the analyst validates sources, methods, and conclusions."),
    ("Cost and scale", "Model calls, embeddings, execution, files, charts, reports, and EC2 resources grow first."),
    ("Human model", "The analyst chooses the mode, watches the trace, questions tool choices, and reviews the report before acting."),
    ("First next step", "Move generated-code execution into a hardened worker with strict network, filesystem, time, CPU, and memory limits."),
])]
story += [callout("Bottom line", "Aether Analyst is a strong demonstration of agentic orchestration: model for decisions, tools for evidence, Python for computation, and SSE for transparency. Its future hinges on hardening code execution, source trust, multi-user isolation, and durable job execution.", BLUE_LIGHT), PageBreak()]

# LearnFlow
story += project_header("LearnFlow AI", "Multi-tenant learning and AI operations platform", r"C:\Users\Abhishek Satarkar\Desktop\niche-project\learnflow-ai")
story += [P("What it is", "H2x"), P("LearnFlow AI is a learning management platform with a built-in AI layer. Staff can upload knowledge documents, build courses and assessments, evaluate learner answers, and run automations. Learners get a separate portal. The system is designed for multiple organizations, with tenant boundaries, role-based access, grounded retrieval, usage accounting, and human review for uncertain grading.")]
story += [P("Why it was built", "H2x"), P("The project aims to turn scattered training material into a governed learning workflow rather than a generic chatbot. The important product idea is that AI should assist with content generation and grading while the platform keeps humans in control of publication, low-confidence evaluation, and tenant access.")]
story += [P("How it was built", "H2x"), bullet("A Next.js web app contains staff dashboards and the learner portal."), bullet("A FastAPI backend exposes versioned REST endpoints, request IDs, rate limits, authentication, RBAC, and server-sent progress updates."), bullet("PostgreSQL stores organizations, users, documents, courses, assessments, submissions, usage, audit logs, and workflow executions."), bullet("Redis and ARQ handle background ingestion, generation, evaluation, workflow jobs, and pub/sub progress."), bullet("Document ingestion validates files, extracts and cleans text, chunks it, embeds it, indexes it into one Chroma collection per organization, and records each pipeline stage."), bullet("The AI gateway is the single path to providers. It handles retries, fallback, structured-output validation, prompt versions, token accounting, cost estimates, and observability."), bullet("Five exportable n8n workflows use signed webhooks and callbacks, while built-in runners keep tests and demos independent of n8n.")]
story += [P("How a document and question move through it", "H2x"), P("An admin uploads a file. The API validates its extension, bytes, size, and checksum, stores it as pending, and queues ingestion. A worker runs the staged pipeline and publishes progress. Later, a learner or staff member asks a question. The API embeds the question, performs vector and keyword retrieval, fuses the rankings, drops weak context, and only then calls the model. If nothing clears the threshold, it refuses instead of spending model tokens. If context is good enough, the answer includes citations, confidence, model, token, cost, and latency details.")]
story += [P("How the human gates work", "H2x"), P("Objective questions are graded in code. Free-text answers are graded against a rubric. If confidence is too low, the result goes to a reviewer queue. Generated courses land in review rather than publishing automatically. An API key cannot approve an evaluation; a user must make that decision.")]
story += [P("Pain points while building it", "H2x"), bullet("Tenant isolation has to survive every new route, background job, repository query, and vector lookup. A single forgotten filter can turn into a cross-organization data leak."), bullet("The document pipeline is deliberately staged, so failures, re-indexing, idempotency, progress events, and cleanup all need to agree."), bullet("Supporting n8n while also keeping a built-in runner means tracking two execution paths, signed callbacks, replay protection, and the exact steps that actually ran."), bullet("The platform spans PostgreSQL, Redis, Chroma, workers, the web app, providers, and generated workflow files. Keeping local tests useful without all of those services was a meaningful design constraint."), bullet("AI output must be useful but governed: schemas, citation thresholds, confidence gates, cost records, and human approvals make the happy path more deliberate than a simple chat call.")]
story += [P("What is genuinely strong", "H2x"), bullet("Tenant isolation is treated as a data-layer invariant: tenant-scoped queries require an organization filter and vectors use separate collections."), bullet("The AI gateway prevents provider calls from becoming scattered, unobservable one-off integrations."), bullet("The system preserves provenance through prompt versions, usage rows, pipeline runs, workflow steps, and audit logs."), bullet("Demo usage is flagged so seeded analytics do not masquerade as real spend."), bullet("The platform has a credible path from local tests to Docker/Kubernetes deployment without making the first demo depend on every external service.")]
story += [P("Utmost limitations", "H2x"), bullet("The repository itself lists no MFA, SSO/SAML/OIDC, or password-reset flow in the base setup."), bullet("API-key scopes are stored but not yet enforced per route; a key effectively acts as an organization administrator."), bullet("There is no field-level encryption at rest, and uploaded files are not virus scanned."), bullet("The rate limiter is a fixed-window design and intentionally degrades open if Redis is unavailable; that is an availability trade-off, not a perfect abuse control."), bullet("RAG grounding reduces unsupported answers but cannot guarantee that the source document is correct, current, or appropriate."), bullet("LLM-generated course content and subjective grading can still be wrong; the human gate reduces risk but does not remove it."), bullet("A multi-tenant platform remains exposed if any future endpoint bypasses the repository or forgets tenant context, so the invariant needs continuous tests and review.")]
story += [P("Engineering judgment for LearnFlow AI", "H2x"), judgment_table([
    ("Deliberately not built", "No AI auto-publication or silent uncertain grading; known gaps include MFA/SSO, scoped keys, antivirus, and field encryption."),
    ("Trust boundaries", "Organization principals, uploads, ingestion workers, per-organization vectors, model outputs, and signed n8n callbacks."),
    ("Failure recovery", "Queued jobs, recorded stages, restartable indexing, idempotent workflows, replay protection, and built-in n8n fallbacks."),
    ("Evidence", "Pipeline stages, prompt versions, costs, citations, confidence, workflow steps, audits, and demo-versus-real analytics."),
    ("Security owner", "The platform enforces tenants and roles; admins manage access; reviewers own publication and uncertain grading."),
    ("Cost and scale", "Extraction, embeddings, model use, workers, Redis, PostgreSQL, Chroma, and workflow executions drive cost."),
    ("Human model", "Admins curate access and documents; instructors review content; reviewers approve grading; operators monitor failures and costs."),
    ("First next step", "Add MFA or SSO, enforce API-key scopes, and virus-scan uploads before expanding customer usage."),
])]
story += [callout("Bottom line", "LearnFlow is the most product-shaped of the five: it treats AI as one governed subsystem inside a real SaaS workflow. Its strongest promise is not 'AI teaches automatically'; it is 'AI work is traceable, tenant-scoped, cost-aware, and reviewable.'", GREEN_LIGHT), PageBreak()]

# StampMyVisa
story += project_header("StampMyVisa / QuickMove Ops Copilot", "Focused relocation-operations decision support", r"C:\Users\Abhishek Satarkar\Desktop\corporate websites\stampmyvisa")
story += [P("What it is", "H2x"), P("QuickMove Ops Copilot is a focused web tool for relocation operations. An operator pastes fragmented case notes from WhatsApp, Google Sheets, and email. The tool returns a case-health classification, an evidence-based summary, one prioritized next action, completed and pending items, dependency chains, risks, and a suggested follow-up message.")]
story += [P("Why it was built", "H2x"), P("The hiring assignment described a five-person operations team coordinating housing, movers, utilities, paperwork, and post-move support across multiple cities. The high-leverage problem was not another dashboard of every possible task; it was the daily interpretation problem: what is blocked, what depends on what, and what should the operator do next?")]
story += [P("Why you chose a basic workflow", "H2x"), P("You had a five-hour assignment window and no engineering team or existing source-system APIs. A full integration with WhatsApp, Sheets, email, case history, partner systems, and notifications would have consumed the time without guaranteeing a usable result. You therefore chose a narrow workflow that could work tomorrow with copy-paste input, demonstrate real AI value, and preserve human responsibility.")]
story += [P("This was a deliberate scope decision", "Quote"), P("Instead of pretending to automate the whole relocation company, you built a reliable decision-support slice: latest notes in, structured operational state out.")]
story += [P("How it was built", "H2x"), bullet("A Next.js 16 and React interface provides the fixed workspace, input area, demo scenarios, loading state, errors, and result panel."), bullet("A server-side Next.js route receives the notes and calls Groq's Qwen model. The API key never reaches the browser."), bullet("A Zod schema validates the model output before it is rendered. Invalid output fails visibly instead of becoming partial or misleading UI."), bullet("The prompt forbids inventing dates, names, deadlines, policies, and dependencies. Later updates are meant to supersede earlier ones."), bullet("The application is stateless by design: it helps an operator interpret notes but does not replace the canonical case system or contact customers and vendors."), bullet("The five scenarios demonstrate blocked utilities, a mover cancellation, incomplete notes, move readiness, and a documentation blocker.")]
story += [P("How one case works", "H2x"), P("The operator pastes notes and submits them. The server rejects empty, malformed, oversized, or unexpected input. The model converts the notes into a strict CaseAnalysis object. The UI renders health, evidence, dependencies, risks, one next action, and a draft message. The operator checks the evidence and decides what to send or do. No action is automatically executed.")]
story += [P("Pain points while building it", "H2x"), bullet("The five-hour assignment forced a hard product decision: building integrations to every operational channel would have produced more surface area but less proof of a useful workflow."), bullet("Free-form relocation notes are ambiguous and contradictory. The prompt had to make uncertainty and chronology visible without inventing facts."), bullet("The model had to return a useful operational object every time. Request validation and Zod output validation became essential because a polished UI cannot safely render malformed AI output."), bullet("The app had to feel complete despite being stateless, so realistic demo scenarios, cancellation, retry, error states, and a clear human review boundary mattered."), bullet("Keeping the API key server-side while making the interaction fast and simple required a small but explicit client-server boundary.")]
story += [P("What is genuinely strong", "H2x"), bullet("The workflow choice matches the real bottleneck: fragmented information and unclear next action."), bullet("The product is usable without forcing an operations team to migrate away from its current tools."), bullet("Explicit uncertainty and schema validation are stronger than a free-form chatbot that sounds confident."), bullet("One prioritized action prevents another unranked task list and keeps the output operational."), bullet("The interface includes realistic empty, loading, error, cancellation, and retry states rather than only a happy-path mockup.")]
story += [P("Utmost limitations", "H2x"), bullet("It is not connected to WhatsApp, Sheets, email, partner systems, or a persistent case database. The operator must paste current notes and trust that the notes are complete."), bullet("Because it is stateless, it cannot independently resolve chronology across messages or guarantee that an older status has been superseded."), bullet("The model can misunderstand an ambiguous note. Structured output prevents malformed responses, not incorrect interpretation."), bullet("A single next action is useful for focus but can hide parallel work that a real operations manager still needs to coordinate."), bullet("There are no automatic SLA alerts, reminders, assignments, or write-backs to a system of record."), bullet("The current provider is a preview model and can fail or change; provider latency, quota, and output quality are outside the app's control."), bullet("For production, the app would need authentication, case-level access control, audit history, PII handling, persistent records, and integrations.")]
story += [P("Engineering judgment for StampMyVisa", "H2x"), judgment_table([
    ("Deliberately not built", "No WhatsApp, Sheets, email, vendor, or case-system integrations in five hours; no automatic customer contact or record updates."),
    ("Trust boundaries", "Operator notes enter the server, reach the model, return as validated structure, and remain subject to operator approval."),
    ("Failure recovery", "Notes are preserved; duplicate requests are blocked; cancellation, retry, and safe provider or validation errors are shown."),
    ("Evidence", "The working tool, scenarios, validation, and build checks prove the MVP; real time saved and recommendation accuracy are unmeasured."),
    ("Security owner", "The server protects the key; the operator owns the final decision; future deployments need identity and case-level access."),
    ("Cost and scale", "Model calls are cheap initially; persistent cases, PII controls, integrations, queues, and city rules create the real scale cost."),
    ("Human model", "An ops employee pastes evidence, reviews the recommendation, edits the message, and executes the action in existing systems."),
    ("First next step", "Connect one canonical read-only case source, preserve chronology, and measure time-to-next-action before adding write-backs."),
])]
story += [P("<b>Bottom line.</b> StampMyVisa is intentionally a Phase 1 copilot, not a full relocation operating system. The basic workflow was the correct time-boxed choice because it proves the highest-value decision-support loop before investing in integrations and automation.", "Bodyx"), Spacer(1, 10)]

# Interview appendix
story += section_title("Interview appendix", "Fundamentals you should be ready to explain")
story += [P("These are the concepts an interviewer is likely to test underneath the project names. The answers are intentionally phrased the way you could explain them aloud.")]
fundamentals = [
    ("What is an API?", "A defined doorway between programs. One program sends a request in an agreed format; the other returns a result or an error. In your projects, APIs connect browsers to backends and agents to tools."),
    ("Why separate frontend and backend?", "The browser should handle presentation. The backend should protect secrets, call models, run privileged work, and apply business rules. Keeping them separate makes those boundaries easier to enforce."),
    ("What is streaming?", "Instead of waiting for the whole answer, the server sends small updates as work happens. Aether Analyst and TraceAudit use this so users can see progress and, in TraceAudit's case, so text can be checked before it is released."),
    ("What is a queue?", "A waiting line for work. It lets the user request something quickly while a worker processes it in the background, and it gives the system a place to retry when a dependency is temporarily unavailable."),
    ("What is RAG?", "Retrieval-Augmented Generation: search trusted documents first, then give the relevant passages to the model. This lets the model answer from current company material instead of relying only on memory."),
    ("Why does structured output matter?", "A model can return beautifully written but unusable text. A schema checks that the response has the expected fields and types before the application trusts it."),
    ("What is tenant isolation?", "It means one customer or organization must never see another customer's data. You enforce it in the database and authorization rules, not only by hiding things in the interface."),
    ("What is a human-in-the-loop?", "The system recommends or prepares work, but a person remains responsible for approving high-impact actions. This is central to StampMyVisa, LearnFlow review, and Twit-auto's draft queue."),
    ("Why is browser automation fragile?", "It clicks the same screens a person sees. If the website changes a button, layout, login flow, or anti-bot rule, the automation can break even though the business idea is unchanged."),
    ("What is an outbox?", "A local holding area for events that must not be lost. The system writes the event first and delivers it later, retrying temporary failures and moving permanent failures aside for investigation."),
    ("What is the difference between detection and prevention?", "Detection tells you that something looks wrong. Prevention changes or blocks the action. Several of your projects do both, but no detector can prevent a route that bypasses it."),
    ("How do you evaluate an AI feature?", "Use representative examples, include difficult and benign cases, measure both misses and false alarms, and state what was not measured. A demo result is not the same as production accuracy."),
]
data = [[P("Question", "TableHead"), P("Plain-language answer", "TableHead")]] + [[P(q, "FundCellBold"), P(a, "FundCell")] for q,a in fundamentals]
t = Table(data, colWidths=[1.75*inch, 4.8*inch], repeatRows=1)
t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), LAVENDER), ("GRID", (0,0), (-1,-1), 0.35, HexColor("#d8dbe2")), ("VALIGN", (0,0), (-1,-1), "TOP"), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, HexColor("#fafbfc")]), ("LEFTPADDING", (0,0), (-1,-1), 6), ("RIGHTPADDING", (0,0), (-1,-1), 6), ("TOPPADDING", (0,0), (-1,-1), 4), ("BOTTOMPADDING", (0,0), (-1,-1), 4)]))
story += [t, PageBreak()]

story += section_title("Interview appendix", "Project questions and answers")
project_questions = [
    ("Black Monolith", [
        ("Why not just use one AI safety filter?", "Because the agent has different failure points. A tool can be changed, a document can be poisoned, and a model can leak data. Each needs a control close to where the risk occurs."),
        ("How does TraceAudit stop a credential?", "It receives the model stream before the user does, briefly holds a rolling window, replaces a detected secret with a redaction, and forwards only the cleaned text. A severe anomaly can terminate the stream."),
        ("What happens if the dashboard is down?", "The modules keep the event in a durable local outbox and retry later. The agent path should keep working while evidence delivery catches up."),
        ("What is the biggest architectural weakness?", "Coverage depends on routing. Anything that calls a tool, model, or database around the checkpoints can bypass them. The surrounding network and permissions must enforce the route."),
    ]),
    ("Twit-auto", [
        ("Why did you use a real Chrome browser?", "Some X workflows are only available in the web interface and a paid API was not required. The tradeoff is slower, more fragile automation that is sensitive to X policy and UI changes."),
        ("What does the critic guarantee?", "It improves selection by scoring drafts and retrying weak ones. It does not guarantee truth, quality, or safety; after retries, the best available draft can still be posted."),
        ("Why is JSON a problem as the system grows?", "It is easy for one account, but it has no transactions, indexes, isolation, or safe multi-writer behavior. A database and real job queue are the natural next step."),
        ("How would you make it production-ready?", "Use official APIs where possible, move state to a database, add authentication and tenant boundaries, isolate browser sessions, add stronger audit history, and treat platform compliance as a design requirement."),
    ]),
    ("Aether Analyst", [
        ("Why use a ReAct loop?", "It lets the model choose a tool, see the result, and choose the next step. The model plans; deterministic tools provide evidence and computation."),
        ("Why execute Python instead of asking the model for numbers?", "The model is good at deciding what to calculate but can make arithmetic mistakes. Python can calculate exact statistics and create real chart files."),
        ("Is a subprocess the same as a secure sandbox?", "No. It is a boundary, not a complete security guarantee. A serious deployment also needs filesystem, network, CPU, memory, package, and user isolation."),
        ("What happens if the model or tool fails?", "The observation can contain the error, allowing the loop to recover or explain failure. For production, run state and events should also survive process restarts through durable job storage."),
    ]),
    ("LearnFlow AI", [
        ("How does it avoid cross-tenant leakage?", "The authenticated principal carries an organization identity, repository queries require that organization, writes stamp it, and vectors use separate collections. Missing or foreign objects look like a normal 404."),
        ("Why does the RAG path refuse when retrieval is weak?", "A confident answer with no supporting context is worse than an explicit refusal. The system avoids spending model tokens when no document clears the quality threshold."),
        ("Why keep a built-in workflow runner if n8n exists?", "It keeps tests and demos reliable when n8n is unavailable, while still allowing production integrations. The execution record says which path actually ran."),
        ("What would you fix first?", "Add MFA or SSO, enforce API-key scopes, scan uploads for malware, add encryption appropriate to the data, and continuously test every new route for tenant isolation."),
    ]),
    ("StampMyVisa", [
        ("Why build only one workflow?", "The assignment had five hours and no engineering team or source-system integrations. A narrow, usable decision-support loop proved value faster than a fake end-to-end automation."),
        ("Why return one next action?", "Operators need to know what to do now. One ranked action is more useful than another unprioritized list, while the supporting risks and dependencies keep the context visible."),
        ("What does schema validation solve?", "It prevents malformed model responses from breaking the interface or silently omitting fields. It cannot guarantee that the model's interpretation is correct."),
        ("What is the next product step?", "Connect one real source of truth, such as the case tracker or shared sheet, add persistent case history, preserve evidence and chronology, then add alerts and write-backs only after the read path is reliable."),
    ]),
]
for name, qs in project_questions:
    story += [P(name, "H2x")]
    for q,a in qs:
        story += [P(f"<b>Q:</b> {q}", "H3x"), P(f"<b>A:</b> {a}", "Bodyx")]
story += [PageBreak()]

story += section_title("Engineering judgment", "The decisions behind each project")
story += [P("This section makes the production thinking explicit. For each project it states what was deliberately left out, where trust changes hands, how failure should be handled, what evidence exists, who owns security and decisions, what becomes expensive, and what should be built next.")]

judgment = [
    ("Project Black Monolith", [
        ("What I deliberately did not build", "I did not claim a universal agent sandbox, semantic truth checker, or private-reasoning monitor. Those require control that middleware does not have. I focused on three observable boundaries: MCP tools, retrieval, and streamed generation."),
        ("Trust boundaries", "Tool definitions cross from an MCP server to the agent; documents cross from storage into model context; generated tokens cross from the model to the user; security events cross from modules to the dashboard. Each boundary needs its own authentication and policy."),
        ("Failure recovery", "Detections are written to a durable outbox before delivery. Temporary dashboard failures retry, permanent rejections become dead letters, and duplicate delivery is ignored by event ID. The operator investigates rather than losing the original evidence."),
        ("Evidence and measurement", "The repository has deterministic fixtures and detector scorecards, but they are small and synthetic. Local tests demonstrate defined behaviour; they do not prove field accuracy against every model, corpus, MCP server, or attack."),
        ("Security ownership", "The modules enforce their narrow rules, the dashboard protects tenant evidence, deployment permissions prevent bypasses, and a human operator owns investigation and policy changes."),
        ("Cost and scale", "The first costs are model-stream processing, embeddings, event volume, retention, and operator attention. Scale eventually requires shared detector state, horizontally safe queues, database capacity planning, and policy management across many tenants."),
        ("Human operating model", "Security operators review alerts, approve first-contact tools when required, re-trust legitimate schema changes, resolve dead letters, tune policies, and preserve exported evidence."),
        ("First production improvement", "Build enforceable integration adapters for one real agent runtime and prove that its direct bypass routes are closed. Coverage is more important than adding another detector."),
    ]),
    ("Twit-auto", [
        ("What I deliberately did not build", "I did not build a multi-account SaaS, official X API platform, or team approval system. The project stayed a Windows-first personal operator so the research-to-posting loop could be tested without cloud infrastructure."),
        ("Trust boundaries", "Public trend sources enter the strategy prompt; model output becomes candidate content; Playwright carries actions into X; cookies and the Chrome profile authorize the account; dashboard commands mutate shared state."),
        ("Failure recovery", "The bot uses cooldowns, backoff, action caps, screenshots, saved state, and health checks. A failed action should remain distinguishable from a completed one so the next cycle does not duplicate or incorrectly skip work."),
        ("Evidence and measurement", "The code records history, local analytics, logs, critic results, and evaluation cases. Live account growth, provider quality, long-term account safety, and runtime cost were not established merely by implementing the features."),
        ("Security ownership", "The owner is responsible for account authorization, cookie protection, prompt and limit settings, draft approval, and compliance with X rules. The critic improves content but is not the security owner."),
        ("Cost and scale", "The local setup is inexpensive, but browser time, LLM quotas, screenshots, profile storage, and maintenance grow quickly. Multiple accounts need isolated browser sessions, a database, workers, real queues, and per-account limits."),
        ("Human operating model", "The owner logs in manually, reviews the queue, monitors account health and history, adjusts voice and limits, pauses unsafe activity, and handles challenges or platform warnings."),
        ("First production improvement", "Replace the shared JSON file with SQLite or PostgreSQL plus a proper job ledger. That reduces lost updates and creates a reliable base before adding accounts or cloud deployment."),
    ]),
    ("Aether Analyst", [
        ("What I deliberately did not build", "I did not make the system an unrestricted public code-execution service or claim that generated analysis is automatically correct. The product remains an assisted research workspace with visible traces and downloadable evidence."),
        ("Trust boundaries", "Files and prompts enter from the user; web and ArXiv content enter from external sources; Gemini chooses tools; generated Python crosses into execution; charts and reports return to the browser; memories influence future prompts."),
        ("Failure recovery", "Tool errors are returned as observations so the agent can adjust. Runs, messages, and reports are persisted, but live SSE queues are in memory; stronger production recovery needs a durable job queue and resumable event history."),
        ("Evidence and measurement", "The strongest evidence is the visible tool trace, saved calculations, charts, source retrieval, and report artifacts. A successful run proves that workflow, not the scientific validity of every conclusion."),
        ("Security ownership", "The backend must enforce file limits, tool permissions, execution isolation, secrets, and data retention. The user remains responsible for validating sources, methodology, and conclusions before acting on the report."),
        ("Cost and scale", "Gemini calls, embeddings, vector storage, code execution, charts, PDFs, and EC2 resources are the main costs. Multi-user scale requires isolated jobs, object storage, stronger databases, quotas, and resource limits."),
        ("Human operating model", "The analyst selects the mode, provides data and objectives, watches the trace, questions strange tool choices, validates charts and methods, and treats the report as a draft for review."),
        ("First production improvement", "Move generated-code execution into a hardened isolated worker with strict network, filesystem, time, CPU, and memory limits."),
    ]),
    ("LearnFlow AI", [
        ("What I deliberately did not build", "I did not let AI auto-publish courses or silently finalize uncertain grades. I also did not hide known gaps such as MFA, SSO, scoped API-key enforcement, antivirus scanning, or field-level encryption."),
        ("Trust boundaries", "Users and API keys become organization-bound principals; uploads cross into the ingestion pipeline; chunks cross into organization-specific vector collections; model output crosses into reviewable learning content; n8n callbacks cross back through signed webhooks."),
        ("Failure recovery", "Jobs are queued, stages are recorded, re-indexing can restart from a selected stage, workflows are idempotent, callbacks have replay protection, and built-in runners provide a fallback when n8n is unavailable."),
        ("Evidence and measurement", "The platform records pipeline stages, prompt versions, provider attempts, tokens, estimated cost, citations, confidence, workflow steps, audit logs, and whether analytics are demo or real. Real educational outcomes still require longer-term evaluation."),
        ("Security ownership", "The application enforces tenant and role boundaries, infrastructure protects secrets and data, reviewers own publication and uncertain grading, and administrators own membership, API keys, retention, and incident response."),
        ("Cost and scale", "Document extraction, embeddings, model generation, background workers, Redis, PostgreSQL, Chroma, and workflow executions drive cost. Caching, quotas, batching, archive policies, and provider routing become important as organizations grow."),
        ("Human operating model", "Admins curate documents and permissions, instructors review generated material, reviewers approve uncertain evaluations, learners see only their own work, and operators monitor queues, costs, failures, and audit history."),
        ("First production improvement", "Close the named identity and upload-security gaps: add MFA or SSO, enforce API-key scopes, and virus-scan files before expanding customer usage."),
    ]),
    ("StampMyVisa / QuickMove Ops Copilot", [
        ("What I deliberately did not build", "I did not build WhatsApp, Sheets, email, vendor, or case-management integrations in the five-hour assignment. I also did not let the model contact customers or update records. The goal was to prove one useful decision-support loop."),
        ("Trust boundaries", "Case notes cross from the operator into the server; the server sends them to the model; structured output returns to the UI; the operator decides whether the proposed message or next action is safe and correct."),
        ("Failure recovery", "The client preserves entered notes, blocks duplicate requests, supports cancellation and retry, and shows controlled provider or validation errors. Because the MVP is stateless, the operator remains the recovery point and source of truth."),
        ("Evidence and measurement", "The working application, five scenarios, input checks, schema validation, and build verification demonstrate the MVP. It does not measure real QuickMove SLA improvement, staff adoption, time saved, or recommendation accuracy."),
        ("Security ownership", "The server protects the API key and validates data; the prompt reduces invention; the operator owns the final decision and outbound communication. A future organization deployment must add user identity and case-level permissions."),
        ("Cost and scale", "The MVP mainly pays for model calls. Real scale adds persistent case storage, ingestion from communication channels, audit records, PII controls, queues, alerts, and city-specific workflow configuration."),
        ("Human operating model", "An operations employee pastes the latest evidence, reviews health, risks and dependencies, chooses whether to accept the recommendation, edits the message, and carries out the action in existing systems."),
        ("First production improvement", "Connect the read path to one canonical case source, preserve chronology and evidence, and measure whether the copilot reduces time-to-next-action before adding automatic write-backs."),
    ]),
]

for project, items in judgment:
    story += [P(project, "H2x")]
    for label, value in items:
        story += [P(f"<b>{label}.</b> {value}", "Bodyx")]
    story += [Spacer(1, 4)]
story += [PageBreak()]

story += section_title("Recommended additions", "What is still missing from the portfolio story")
story += [P("The five projects are already a strong set. The additions below would make the engineering story easier to defend and would turn the current prototypes into clearer production plans:")]
story += [bullet("Add a one-page architecture diagram for each project showing the trust boundaries, not only the boxes. Mark where secrets, user data, model calls, and irreversible actions cross."), bullet("Add a short threat model per project: what can go wrong, who can cause it, what the system can observe, and what happens after detection."), bullet("Keep a measured validation table: tests run, external services tested, synthetic versus real data, false positives, latency, and known unverified claims."), bullet("For agentic systems, document the action policy separately from the prompt. Prompts guide a model; permissions and server-side checks enforce behaviour."), bullet("For all multi-user products, make identity, tenant isolation, audit history, retention, and recovery part of the first design rather than a later add-on."), bullet("For user-facing AI, show evidence and uncertainty in the interface. A polished answer without provenance can create more operational risk than an obvious refusal."), bullet("For the portfolio, include one short 'decision record' per project explaining what you deliberately did not build and why. Your StampMyVisa scope decision is an excellent example.")]
story += [callout("The clearest improvement theme", "Move from 'the model can do this' to 'the system can do this safely, measurably, and with a recovery path.' That is the bridge from an impressive demo to dependable engineering.", LAVENDER_LIGHT), PageBreak()]

# Closing
story += section_title("Closing", "What these projects say about your engineering approach")
story += [P("Across the five codebases, your recurring design instinct is to put a visible control point around messy work:")]
story += [bullet("Black Monolith puts controls around agent tools, memory, and generation."), bullet("Twit-auto puts controls around research, content quality, pacing, and account health."), bullet("Aether Analyst puts controls around model decisions, deterministic computation, and trace visibility."), bullet("LearnFlow puts controls around tenant access, retrieval grounding, AI cost, and human review."), bullet("StampMyVisa puts a control point around operational interpretation: notes become a structured, reviewable next action.")]
story += [P("The most important maturity lesson is that the interface is only half the system. A polished UI can make a prototype feel complete, but the real production questions are about authority, persistence, isolation, evidence, failure recovery, and bypass routes. Your strongest projects already show that awareness; the next step is to keep converting those assumptions into enforced boundaries.")]
story += [callout("One-sentence portfolio summary", "You build AI systems that do useful work, but you also try to make their decisions visible, bounded, reviewable, and connected to the messy workflows where people actually operate.", LAVENDER_LIGHT)]
story += [P("Source note", "H2x"), P("This report was prepared from repository READMEs, implementation guides, architecture documents, source layout, and the attached assignment brief. It explains implemented intent and known boundaries; it is not a claim that every external integration or production deployment was re-tested during this report build.", "Smallx")]

doc = SimpleDocTemplate(str(OUT), pagesize=letter, rightMargin=0.72*inch, leftMargin=0.72*inch, topMargin=0.68*inch, bottomMargin=0.72*inch, title="Five Projects, Explained", author="OpenAI")
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print(OUT.resolve())
