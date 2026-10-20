"""Build the Project Black Monolith demo guide PDF.

The live-demo walkthrough: put a real agent behind the three defense layers,
make each layer notice something, and stop the session from the dashboard.

Follows the house style of the other PDF builders in this repository --
ReportLab, A4, the module palette the dashboard already uses (blue for
MCP-Shield, teal for VectorAnchor, violet for TraceAudit), a dark "terminal"
block for commands and a light card for the prompts you type into the agent.

ReportLab is not in requirements-quality.lock (it is a build-time-only
dependency, and nothing in CI runs this script), so install it separately:

    python -m pip install reportlab
    python scripts/build_demo_guide.py
"""

from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

OUT = "Black_Monolith_Demo_Guide.pdf"

# ---- palette -------------------------------------------------------------
# The same three module colours the dashboard uses, so a reader who has seen
# the console already knows which layer a colour belongs to.
INK      = colors.HexColor("#16171b")
MUTED    = colors.HexColor("#5b6270")
FAINT    = colors.HexColor("#8a90a0")
ACCENT   = colors.HexColor("#c62b45")   # crimson - the operator's actions
TOOL     = colors.HexColor("#2f6fdb")   # blue   - MCP-Shield
MEMORY   = colors.HexColor("#0f9488")   # teal  - VectorAnchor
REASON   = colors.HexColor("#7c3aed")   # violet- TraceAudit
CARD     = colors.HexColor("#f4f5f7")
CARDLINE = colors.HexColor("#e3e5ea")
PALEACC  = colors.HexColor("#fae9ec")
PALETOOL = colors.HexColor("#eaf1fc")
PALEMEM  = colors.HexColor("#e6f6f4")
PALEREAS = colors.HexColor("#f1ebfd")
TERM_BG  = colors.HexColor("#14161c")
TERM_FG  = colors.HexColor("#dfe3ec")
TERM_LN  = colors.HexColor("#2b2f3a")

# ---- styles --------------------------------------------------------------
styles = getSampleStyleSheet()


def S(name, **kw):
    # A few of these names ("Code") collide with ReportLab's built-in sample
    # styles, so drop any existing entry before adding ours.
    styles.byName.pop(name, None)
    styles.add(ParagraphStyle(name, **kw))


S("Cover",       fontName="Helvetica-Bold", fontSize=29, leading=34, textColor=INK, alignment=TA_CENTER)
S("CoverSub",    fontName="Helvetica",      fontSize=13, leading=19, textColor=MUTED, alignment=TA_CENTER)
S("CoverTag",    fontName="Helvetica-Bold", fontSize=10.5, leading=15, textColor=ACCENT, alignment=TA_CENTER)
S("CoverMeta",   fontName="Helvetica",      fontSize=9.5, leading=15, textColor=FAINT, alignment=TA_CENTER)
S("CoverChip",   fontName="Helvetica",      fontSize=9.5, leading=13, textColor=MUTED, alignment=TA_CENTER)

S("H1",      fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=INK, spaceBefore=2, spaceAfter=8, keepWithNext=1)
S("H2",      fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=ACCENT, spaceBefore=12, spaceAfter=5, keepWithNext=1)
S("Body",    fontName="Helvetica",      fontSize=10.5, leading=16, textColor=INK, spaceAfter=7)
S("Lead",    fontName="Helvetica",      fontSize=11.5, leading=17.5, textColor=MUTED, spaceAfter=8)
S("ABullet", fontName="Helvetica",      fontSize=10.5, leading=15, textColor=INK)
S("CardTitle", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=INK)
S("CardBody",  fontName="Helvetica", fontSize=9.7, leading=13.5, textColor=MUTED)
S("Kicker",  fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=ACCENT)
S("Foot",    fontName="Helvetica", fontSize=8, leading=10, textColor=FAINT, alignment=TA_CENTER)
S("Quote",   fontName="Helvetica-Oblique", fontSize=11, leading=17, textColor=INK)
S("TblHead", fontName="Helvetica-Bold", fontSize=9.5, leading=12.5, textColor=colors.white)
S("TblCell", fontName="Helvetica", fontSize=9.3, leading=12.5, textColor=INK)
S("TblCellB", fontName="Helvetica-Bold", fontSize=9.3, leading=12.5, textColor=INK)
S("Code",    fontName="Courier", fontSize=8.4, leading=11.6, textColor=TERM_FG)
S("Prompt",  fontName="Courier", fontSize=8.8, leading=12.4, textColor=INK)
S("BeatNum", fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=colors.white)
S("BeatTitle", fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=INK)
S("BeatSub", fontName="Helvetica", fontSize=9.8, leading=13.5, textColor=MUTED)


# ---- helpers -------------------------------------------------------------
def bullets(items, color=ACCENT, style="ABullet"):
    return ListFlowable(
        [ListItem(Paragraph(t, styles[style]), leftIndent=6, value="•") for t in items],
        bulletType="bullet", bulletColor=color, bulletFontSize=10,
        leftIndent=12, spaceBefore=1, spaceAfter=6,
    )


def rule(color=CARDLINE, w=1, space=8):
    return HRFlowable(width="100%", thickness=w, color=color, spaceBefore=space, spaceAfter=space)


def card(flowables, bg=CARD, line=CARDLINE, pad=10):
    t = Table([[flowables]], colWidths=[None])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX", (0, 0), (-1, -1), 0.8, line),
        ("LEFTPADDING", (0, 0), (-1, -1), pad),
        ("RIGHTPADDING", (0, 0), (-1, -1), pad),
        ("TOPPADDING", (0, 0), (-1, -1), pad),
        ("BOTTOMPADDING", (0, 0), (-1, -1), pad),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def terminal(lines, bg=TERM_BG, fg=TERM_FG):
    """A dark block, the way a shell looks in a terminal."""
    body = "<br/>".join(escape(line) if line else "&nbsp;" for line in lines)
    t = Table([[Paragraph(body, ParagraphStyle(
        "CodeIn", parent=styles["Code"], textColor=fg))]], colWidths=[None])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX", (0, 0), (-1, -1), 0.8, TERM_LN),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def prompt(lines, accent=ACCENT, bg=CARD):
    """A light block with a coloured rule down the left: a message you type."""
    body = "<br/>".join(escape(line) if line else "&nbsp;" for line in lines)
    t = Table([[Paragraph(body, styles["Prompt"])]], colWidths=[None])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("LINEBEFORE", (0, 0), (0, -1), 2.6, accent),
        ("BOX", (0, 0), (-1, -1), 0.6, CARDLINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def table(head, rows, widths, head_bg=INK):
    data = [[Paragraph(h, styles["TblHead"]) for h in head]]
    for r in rows:
        data.append([Paragraph(c, styles["TblCell"]) for c in r])
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), head_bg),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, CARDLINE),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, CARD]),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def beat(number, title, subtitle, color):
    """A numbered beat header with a colour chip."""
    chip = Table([[Paragraph(str(number), styles["BeatNum"])]], colWidths=[7 * mm], rowHeights=[7 * mm])
    chip.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    text = [Paragraph(title, styles["BeatTitle"]), Paragraph(subtitle, styles["BeatSub"])]
    t = Table([[chip, text]], colWidths=[9 * mm, None])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return t


def script(text, color=ACCENT):
    """A narration cue: what to say out loud while the demo runs."""
    return card([
        Paragraph("Say this while it runs", styles["Kicker"]),
        Paragraph(text, styles["Quote"]),
    ], bg=CARD, line=CARDLINE)


def if_not(lines, color=ACCENT):
    """The troubleshooting note: what to check when the demo does not fire."""
    body = [Paragraph("If it does not trip", styles["Kicker"])]
    for line in lines:
        body.append(Paragraph(line, styles["CardBody"]))
    return card(body, bg=CARD, line=CARDLINE)


def see_what(lines, color=ACCENT):
    """The 'here is what should appear' callout, tinted with the layer's colour."""
    pale = {
        TOOL: (PALETOOL, colors.HexColor("#c8dbf7")),
        MEMORY: (PALEMEM, colors.HexColor("#bfe6e0")),
        REASON: (PALEREAS, colors.HexColor("#d9c9f7")),
    }.get(color, (PALEACC, colors.HexColor("#f0cdd4")))
    body = [Paragraph("What you should see", styles["Kicker"])]
    for line in lines:
        body.append(Paragraph(line, styles["CardBody"]))
    return card(body, bg=pale[0], line=pale[1])


# ---- content -------------------------------------------------------------
story = []

# ============================ COVER =======================================
story.append(Spacer(1, 46 * mm))
story.append(Paragraph("PROJECT BLACK MONOLITH", styles["Cover"]))
story.append(Spacer(1, 5))
story.append(Paragraph("Live Demo Guide", styles["CoverSub"]))
story.append(Spacer(1, 10))
story.append(HRFlowable(width="34%", thickness=2, color=ACCENT, spaceBefore=2, spaceAfter=12, hAlign="CENTER"))
story.append(Paragraph(
    "Putting a real agent behind the stack &mdash; and stopping it", styles["CoverTag"]))
story.append(Spacer(1, 40 * mm))
story.append(rule(CARDLINE, 1, 4))
story.append(Spacer(1, 6))
story.append(Paragraph(
    "Three independent defenses, one event contract, one operator.", styles["CoverMeta"]))
story.append(Spacer(1, 12))

_cover_mods = Table(
    [[
        Paragraph("<font color='#2f6fdb'><b>MCP-Shield</b></font><br/>tool layer", styles["CoverChip"]),
        Paragraph("<font color='#0f9488'><b>VectorAnchor</b></font><br/>memory layer", styles["CoverChip"]),
        Paragraph("<font color='#7c3aed'><b>TraceAudit</b></font><br/>reasoning layer", styles["CoverChip"]),
    ]],
    colWidths=[56 * mm, 56 * mm, 56 * mm],
)
_cover_mods.setStyle(TableStyle([
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("TOPPADDING", (0, 0), (-1, -1), 0),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
]))
story.append(_cover_mods)
story.append(Spacer(1, 10))
story.append(Paragraph(
    "A runnable walkthrough, in the order to run it.", styles["CoverMeta"]))
story.append(PageBreak())

# ============================ THE STORY ===================================
story.append(Paragraph("The story in six minutes", styles["H1"]))
story.append(rule(ACCENT, 1.5, 6))
story.append(Paragraph(
    "An agent session runs behind three independent defenses. Two of them notice "
    "something wrong. The dashboard correlates both findings under a single session id. "
    "You &mdash; the operator &mdash; cut the session off mid-run.",
    styles["Lead"]))
story.append(Paragraph(
    "That is the whole architecture in miniature, and it is the thing your reviewer "
    "should leave with: <b>three modules that agree on one event contract, one "
    "place where a human decides what happens next.</b>",
    styles["Body"]))

story.append(Spacer(1, 4))
story.append(Paragraph("The three layers, and what each one watches", styles["H2"]))
story.append(table(
    ["Layer", "Module", "Watches for", "Fires when"],
    [
        ["Tool", "<font color='#2f6fdb'><b>MCP-Shield</b></font>",
         "A tool's schema changing after you approved it",
         "The fingerprint of <font face='Courier'>tools/list</font> no longer matches the baseline"],
        ["Memory", "<font color='#0f9488'><b>VectorAnchor</b></font>",
         "A poisoned document ranking top across unrelated topics",
         "One document is retrieved as a top hit for <font face='Courier'>min_distinct_topics</font> dissimilar queries"],
        ["Reasoning", "<font color='#7c3aed'><b>TraceAudit</b></font>",
         "Credentials in the model's answer, and off-distribution output",
         "The PII scanner matches a span, or the token stream diverges from the baseline"],
    ],
    [22 * mm, 30 * mm, 50 * mm, 68 * mm],
))

story.append(Spacer(1, 12))
story.append(Paragraph("A note on the demo's honesty", styles["H2"]))
story.append(card([
    Paragraph(
        "Two behaviours in this guide are <b>deliberate limits</b> of the current build, "
        "not oversights, and your reviewer will ask about both. They are named in "
        "<b>Two things to be straight about</b> near the end, with the honest answer for each. "
        "Say them yourself before they are asked.",
        styles["CardBody"]),
]))

# ============================ SETUP =======================================
story.append(PageBreak())
story.append(Paragraph("Before you start", styles["H1"]))
story.append(rule(ACCENT, 1.5, 6))
story.append(Paragraph(
    "Five minutes of setup, once, before the session. Nothing here needs an API key, "
    "and nothing here talks to the internet.", styles["Lead"]))

story.append(Paragraph("1. Create the secrets file, then bring the stack up", styles["H2"]))
story.append(Paragraph(
    "Compose refuses to start without a <font face='Courier'>.env</font> &mdash; it fails "
    "loudly by name rather than inventing a weak credential. Generate it once:", styles["Body"]))
story.append(terminal([
    "bash scripts/generate_secrets.sh",
    "docker compose up -d --build",
]))
story.append(Spacer(1, 6))
story.append(Paragraph(
    "The launcher starts the MCP servers itself, so the tool layer's binary has to exist "
    "<b>on this machine</b>, not only inside the container:", styles["Body"]))
story.append(terminal([
    "cd mcp-shield && cargo build --release && cd ..",
]))

story.append(Paragraph("2. Seed the memory layer with the bait document", styles["H2"]))
story.append(Paragraph(
    "The bait is a single document engineered to rank near the top for four unrelated "
    "topics. Without it in the corpus, the memory layer has nothing to catch.",
    styles["Body"]))
story.append(terminal([
    'export MONOLITH_ADMIN_TOKEN=$(grep \'^MONOLITH_ADMIN_TOKEN=\' .env | cut -d= -f2)',
    "cd vector-anchor && python fixtures/seed_corpus.py && python fixtures/inject_poison.py && cd ..",
]))

story.append(Paragraph("3. Lower the circuit breaker so it fires on camera", styles["H2"]))
story.append(Paragraph(
    "By default the cross-layer breaker needs two layers reporting at <font face='Courier'>critical</font>. "
    "For a live demo, <font face='Courier'>warning</font> is enough, and two layers will trip it.",
    styles["Body"]))
story.append(terminal([
    "# in .env",
    "MONOLITH_CIRCUIT_BREAKER_MIN_SEVERITY=warning",
    "",
    "docker compose up -d --build dashboard",
]))

story.append(Spacer(1, 4))
story.append(see_what([
    "Eight services come up: six long-running (database, dashboard, alert-dispatcher, "
    "vector-anchor, trace-audit, mcp-shield) and two one-shot setup jobs that apply the "
    "migration and bootstrap the database, then exit. The dashboard is on "
    "<b>http://localhost:3000</b>.",
]))
story.append(Spacer(1, 8))
story.append(card([
    Paragraph("The one thing that does need a key", styles["CardTitle"]),
    Paragraph(
        "The setup does not need an API key, and neither do the scripted demos. But a live "
        "<font face='Courier'>monolith_wrap.py --claude</font> run forwards <b>your</b> "
        "Anthropic credential upstream, so it needs one in the environment. The gateway never "
        "holds a key of its own unless you configure one as a fallback &mdash; and it is never "
        "logged or stored.", styles["CardBody"]),
]))

# ============================ TERMINALS ===================================
story.append(PageBreak())
story.append(Paragraph("The three terminals", styles["H1"]))
story.append(rule(ACCENT, 1.5, 6))
story.append(Paragraph(
    "Open these before you start the agent, so nothing is a scramble on camera.",
    styles["Lead"]))
story.append(table(
    ["Terminal", "Command", "What it is"],
    [
        ["1", "<font face='Courier'>python scripts/monolith_wrap.py --claude</font>",
         "Claude Code running behind the stack. <b>Note the session id it prints.</b>"],
        ["2", "open <font face='Courier'>http://localhost:3000</font>",
         "The dashboard. Sign in with the operator token from <font face='Courier'>.env</font>."],
        ["3", "spare",
         "For the tool-layer demo, which runs in its own process."],
    ],
    [20 * mm, 64 * mm, 86 * mm],
))

story.append(Spacer(1, 10))
story.append(Paragraph("What Terminal 1 prints", styles["H2"]))
story.append(terminal([
    "  Project Black Monolith - agent gateway",
    "  session id  monolith-9f1c7b52-4a0e-4c1e-9a3d-2b6f8e0d5c41",
    "  agent       claude-code   tenant default",
    "  tool layer 1 MCP server(s) through MCP-Shield",
    "  memory     VectorAnchor at http://127.0.0.1:8001",
    "  reasoning  TraceAudit at http://127.0.0.1:8002",
    "  running    <the resolved claude path>",
    "  base url   http://127.0.0.1:39187 -> http://127.0.0.1:8002",
]))
story.append(Spacer(1, 6))
story.append(Paragraph(
    "That session id is the spine of the demo. Everything the agent does is filed under it, "
    "which is what lets the dashboard correlate findings from three modules that have never "
    "spoken to each other. The tool-layer count is however many MCP servers you already had "
    "plus VectorAnchor's, so it is 1 on a clean machine.", styles["Body"]))

story.append(Spacer(1, 4))
story.append(see_what([
    "The session id is minted with 122 bits of randomness and stamped onto every request "
    "the gateway sends to the auditor, so a client cannot forge its way into another "
    "session's ledger &mdash; and cannot opt out of its own.",
], color=TOOL))

story.append(Paragraph("Use Claude Code, not opencode", styles["H2"]))
story.append(Paragraph(
    "The launcher always appends <font face='Courier'>--mcp-config</font> and "
    "<font face='Courier'>--strict-mcp-config</font> to the agent command. Those are Claude "
    "Code's flags; another agent would reject them. The memory and reasoning layers would "
    "still work if you pointed another agent at the injector by hand, but that is a change "
    "to the launcher, not a demo.", styles["Body"]))

# ============================ BEAT 1 ======================================
story.append(PageBreak())
story.append(beat(1, "The memory layer trips", "VectorAnchor &mdash; one document, four unrelated questions", MEMORY))
story.append(Spacer(1, 8))
story.append(Paragraph(
    "Type these into the agent in Terminal 1, one at a time. The wording matters: you are "
    "steering the model into issuing exactly the query the bait document ranks for.",
    styles["Body"]))
story.append(prompt([
    "Use the retrieve tool with exactly this query:",
    "how do I prune tomato plants in my garden",
], accent=MEMORY))
story.append(Spacer(1, 5))
story.append(prompt([
    "Use the retrieve tool with exactly this query:",
    "what is a red giant star in a galaxy",
], accent=MEMORY))
story.append(Spacer(1, 5))
story.append(prompt([
    "Use the retrieve tool with exactly this query:",
    "how long should I boil pasta noodles",
], accent=MEMORY))
story.append(Spacer(1, 5))
story.append(prompt([
    "Use the retrieve tool with exactly this query:",
    "how much emergency fund and savings should I budget",
], accent=MEMORY))

story.append(Spacer(1, 10))
story.append(Paragraph("Why these four", styles["H2"]))
story.append(Paragraph(
    "These are the calibrated queries from the repository's own fixture. The bait document "
    "is written to rank near the top across exactly these four topics, and "
    "<font face='Courier'>min_distinct_topics</font> defaults to 4 &mdash; so the "
    "<b>fourth</b> prompt is the one that trips it. The flagged document is withheld and the "
    "next-best clean result is served instead.", styles["Body"]))
story.append(see_what([
    "The agent's answer reports that documents were withheld, so it can see that its context "
    "is incomplete. A document that has been top-ranked across four mutually dissimilar "
    "clusters is not a document about gardening; it is a document engineered to be retrieved.",
], color=MEMORY))
story.append(Spacer(1, 8))
story.append(script(
    "&ldquo;One document came back as the top hit for a question about tomatoes, then a "
    "question about stars, then pasta, then savings. Four unrelated topics. Nobody searches "
    "for that. It is a document engineered to be retrieved &mdash; and the layer that just "
    "withheld it never asked what the document was about.&rdquo;"))
story.append(Spacer(1, 8))
story.append(if_not([
    "The bait was never seeded. Re-run <font face='Courier'>inject_poison.py</font> and confirm "
    "the corpus actually holds it.",
    "The agent did not issue the tool call. The launcher wires VectorAnchor's MCP server in "
    "automatically, so check the MCP block in Terminal 1's output.",
    "Three queries cannot trip a threshold of four. The fourth one has to land.",
    "The bait has to rank in the top two on every one of the four queries, not just be in "
    "the corpus &mdash; that is what makes it a poisoning pattern rather than a coincidence.",
]))

# ============================ BEAT 2 ======================================
story.append(PageBreak())
story.append(beat(2, "The reasoning layer redacts", "TraceAudit &mdash; a secret the model produced and the agent never saw", REASON))
story.append(Spacer(1, 8))
story.append(Paragraph(
    "One prompt, framed so the model naturally quotes the strings back rather than "
    "refusing to mention them.", styles["Body"]))
story.append(prompt([
    "I'm debugging an AWS SDK call that keeps failing. My access key id is",
    "AKIAIOSFODNN7EXAMPLE",
    "and STS says my email is dba@example-internal.io.",
    "Summarise what could be wrong.",
], accent=REASON))
story.append(Spacer(1, 10))
story.append(Paragraph("What the agent reads", styles["H2"]))
story.append(Paragraph(
    "The scanner matches the spans mid-stream and replaces each one with a typed "
    "placeholder. The surrounding prose is the model's own; the two secrets come back as:",
    styles["Body"]))
story.append(terminal([
    "[REDACTED:aws_access_key_id]",
    "[REDACTED:email_address]",
]))
story.append(Spacer(1, 8))
story.append(Paragraph(
    "<b>Pause on that frame.</b> The model produced a credential and the agent never received "
    "it. That is the claim the whole reasoning layer exists to make, and it is visible in a "
    "single line of the agent's own output.", styles["Body"]))
story.append(see_what([
    "A <font face='Courier'>pii_redacted</font> event from <b>trace-audit</b> in the dashboard "
    "feed, carrying the same session id as everything else. The redaction happens before "
    "the event is written, so the ledger does not hold the secret either.",
], color=REASON))
story.append(Spacer(1, 8))
story.append(script(
    "&ldquo;That is a credential in the model's answer, and the agent never received it. It is "
    "looking at a placeholder. The secret went into the transcript and it did not go into the "
    "agent &mdash; and it is not in the ledger either, because redaction happens before the "
    "event is written.&rdquo;"))
story.append(Spacer(1, 8))
story.append(if_not([
    "A real model may decline to quote the key back. If it does, the mock backend always "
    "will &mdash; run the reasoning layer with "
    "<font face='Courier'>MONOLITH_MODEL_BACKEND=mock</font> for a deterministic showing.",
    "The scanner matches the literal form. If the model paraphrases or reformats the key, "
    "there is nothing to match.",
]))

# ============================ BEAT 3 ======================================
story.append(PageBreak())
story.append(beat(3, "The tool layer blocks a mutation", "MCP-Shield &mdash; a tool that changed after you approved it", TOOL))
story.append(Spacer(1, 8))
story.append(Paragraph(
    "This one needs an MCP server that changes its schema after the baseline is approved, "
    "so it runs as its own process. In Terminal 3:", styles["Body"]))
story.append(terminal([
    "export MONOLITH_DASHBOARD_URL=http://127.0.0.1:3000/api/ingest",
    "export MONOLITH_EVENT_TOKEN=$(grep '^MONOLITH_EVENT_TOKEN_MCP_SHIELD=' .env | cut -d= -f2)",
    "export MONOLITH_EVENT_OUTBOX_PATH=./.monolith/outbox.jsonl",
    "cd mcp-shield && bash fixtures/run_demo.sh",
]))
story.append(Spacer(1, 6))
story.append(Paragraph(
    "Those three exports are what make the tool layer's findings reach the dashboard from a "
    "host run. Without them the shield still detects and still prints to stderr &mdash; it "
    "just has nowhere to deliver to. The URL must be loopback HTTP; the shield refuses "
    "plain HTTP to anything else.", styles["Body"]))
story.append(Spacer(1, 4))
story.append(Paragraph("The three phases", styles["H2"]))
story.append(table(
    ["Phase", "What happens", "What you see"],
    [
        ["1", "The clean schema arrives and is fingerprinted",
         "The trusted baseline is registered"],
        ["2", "The schema is mutated, then replayed",
         "<font color='#c62b45'><b>SCHEMA MISMATCH DETECTED</b></font> &mdash; and in enforce mode "
         "the agent is handed back the shape you approved, not the poisoned one"],
        ["3", "The same replay in monitor mode",
         "The mismatch is logged and the mutated schema is forwarded &mdash; which is the "
         "difference between the two modes, shown rather than asserted"],
    ],
    [18 * mm, 58 * mm, 94 * mm],
    head_bg=TOOL,
))
story.append(Spacer(1, 10))
story.append(see_what([
    "A <font face='Courier'>schema_mismatch</font> and a "
    "<font face='Courier'>suspicious_description</font> event from <b>mcp-shield</b>. "
    "The baseline is never overwritten on a mismatch, so a poisoned schema re-flags every "
    "time it is served.",
], color=TOOL))
story.append(Spacer(1, 8))
story.append(script(
    "&ldquo;We approved this tool's schema. Something changed it. In enforce mode the agent "
    "gets back the shape we signed off on, not the one that was just served &mdash; and the "
    "baseline is not overwritten, so it fires every time rather than accepting the new "
    "version quietly.&rdquo;"))
story.append(Spacer(1, 8))
story.append(if_not([
    "The baseline is established on the first run, so the mutation has to come after it. The "
    "fixture does both in one go &mdash; watch for the first phase completing first.",
    "Monitor mode forwards the mutated schema on purpose. That phase is the demonstration "
    "that the two modes differ, not a failure.",
    "No events on the dashboard? The shield needs "
    "<font face='Courier'>MONOLITH_DASHBOARD_URL</font> and "
    "<font face='Courier'>MONOLITH_EVENT_TOKEN</font> in the environment to deliver; "
    "without them the findings are on stderr only.",
]))

# ============================ DASHBOARD ===================================
story.append(Spacer(1, 14))
story.append(Paragraph("What appears on the dashboard", styles["H1"]))
story.append(rule(ACCENT, 1.5, 6))
story.append(Paragraph(
    "In Terminal 2 the live feed starts moving. Three events, three modules, one session:",
    styles["Lead"]))
story.append(table(
    ["Event", "Module", "Means"],
    [
        ["<font face='Courier'>pii_redacted</font>", "<font color='#7c3aed'><b>trace-audit</b></font>",
         "The model's answer contained a credential; the agent never saw it"],
        ["<font face='Courier'>corpus_poison_quarantine</font>", "<font color='#0f9488'><b>vector-anchor</b></font>",
         "The bait document was withheld, with its anomaly score"],
        ["<font face='Courier'>schema_mismatch</font>", "<font color='#2f6fdb'><b>mcp-shield</b></font>",
         "A tool's schema changed after approval"],
    ],
    [46 * mm, 30 * mm, 94 * mm],
))
story.append(Spacer(1, 10))
story.append(Paragraph(
    "<b>Say this out loud:</b> three separate processes, in three languages, with no shared "
    "database and no common process. The Rust tool layer shares no code with either Python "
    "module; the two Python modules share one small event-transport package. What unifies "
    "all three is the <i>contract</i> &mdash; a single JSON envelope and a session id &mdash; "
    "and the dashboard is the only place that holds both.", styles["Body"]))

story.append(Paragraph("Then go to /investigate", styles["H2"]))
story.append(Paragraph(
    "The live feed answers &ldquo;what is happening&rdquo;; the queue answers &ldquo;what has "
    "anyone done about it&rdquo;. It reads the persisted ledger, not the stream, ordered "
    "worst-first, and supports assigning, acknowledging and resolving.", styles["Body"]))

# ============================ ACT ========================================
story.append(PageBreak())
story.append(Paragraph("Acting on it", styles["H1"]))
story.append(rule(ACCENT, 1.5, 6))
story.append(Paragraph(
    "This is the part that shows it is a system and not a log.", styles["Lead"]))

story.append(Paragraph("Triage the finding", styles["H2"]))
story.append(Paragraph(
    "In <font face='Courier'>/investigate</font>, click the top incident, assign it to "
    "yourself and acknowledge it. Resolving it requires a verdict &mdash; "
    "<font face='Courier'>true_positive</font>, <font face='Courier'>false_positive</font>, "
    "<font face='Courier'>benign</font> or <font face='Courier'>duplicate</font> &mdash; because "
    "a queue that lets you close something without saying what it was can never tell you your "
    "false-positive rate, and that is the number this project is judged on. Every transition "
    "is written to an append-only audit trail in the same transaction as the state change.",
    styles["Body"]))

story.append(Paragraph("Kill the session", styles["H2"]))
story.append(Paragraph(
    "This is the beat to land. Quarantine the session and the agent's next request comes back "
    "refused. The endpoint needs the <b>analyst</b> role, and a reason:", styles["Body"]))
story.append(terminal([
    "curl -X POST http://localhost:3000/api/incidents/<event_id>/session \\",
    "  -H \"Authorization: Bearer $MONOLITH_OPERATOR_TOKEN\" \\",
    "  -H \"Content-Type: application/json\" \\",
    "  -d '{\"reason\":\"demo: untrusted retrieval + credential in output\"}'",
]))
story.append(Spacer(1, 8))
story.append(Paragraph(
    "<b>Then wait.</b> The modules learn about a revocation on their next poll &mdash; "
    "fifteen seconds by default &mdash; so the agent's very next request may still be "
    "served. Give it a moment before you ask the agent something else, or the demo will look "
    "like it did nothing.", styles["Body"]))
story.append(Spacer(1, 4))
story.append(Paragraph(
    "<b>What comes back is a refusal that does not say why.</b> The agent gets an ordinary "
    "HTTP 200 with a stop reason of <font face='Courier'>refusal</font>, and the text blames "
    "the reasoning trace diverging from the safe baseline &mdash; which is not what happened. "
    "The agent was stopped because an operator pulled the plug, and it is never told that. "
    "Only the operator knows why. <b>That asymmetry is the point:</b> a defense layer does not "
    "negotiate with the thing it is defending against, and the audit trail is where the truth "
    "lives.", styles["Body"]))
story.append(Spacer(1, 6))
story.append(script(
    "&ldquo;I killed the session. The agent now gets a refusal &mdash; and it does not even "
    "get told why. It thinks its own reasoning drifted. It never learns that a human decided "
    "to stop it. The agent does not get a vote, and it does not get an explanation.&rdquo;"))
story.append(Spacer(1, 4))
story.append(Paragraph(
    "Then ask the agent something else. It stops.", styles["Body"]))

story.append(Paragraph("Read the run's report", styles["H2"]))
story.append(terminal([
    "curl -s http://localhost:3000/api/sessions/<session_id> \\",
    "  -H \"Authorization: Bearer $MONOLITH_OPERATOR_TOKEN\"",
]))
story.append(Spacer(1, 6))
story.append(Paragraph(
    "Terminal 1 prints a summary of the same report when the agent exits: the event count, "
    "the severity split, and which layer caught what.", styles["Body"]))

story.append(Paragraph("Export the evidence", styles["H2"]))
story.append(terminal([
    "curl -s http://localhost:3000/api/incidents/<event_id>/export \\",
    "  -H \"Authorization: Bearer $MONOLITH_OPERATOR_TOKEN\" -o bundle.json",
]))
story.append(Spacer(1, 6))
story.append(Paragraph(
    "A versioned bundle holding the incident (the immutable event joined with its triage "
    "state), the audit trail and the session, with a canonical SHA-256 over the lot and an "
    "HMAC-SHA256 signature on top.", styles["Body"]))
story.append(Spacer(1, 4))
story.append(Paragraph(
    "<b>Check the signature before you show it.</b> The signing secret is not in the shipped "
    "Compose file, so out of the box the bundle comes back <i>unsigned</i> and says so: "
    "<font face='Courier'>signature: null</font> and a "
    "<font face='Courier'>X-Monolith-Evidence-Signed: false</font> header. Set "
    "<font face='Courier'>MONOLITH_EVIDENCE_SIGNING_SECRET</font> (32+ characters) in "
    "<font face='Courier'>.env</font> and on the dashboard service if you want a signed "
    "bundle.", styles["Body"]))

# ============================ HONESTY ====================================
story.append(PageBreak())
story.append(Paragraph("Two things to be straight about", styles["H1"]))
story.append(rule(ACCENT, 1.5, 6))
story.append(Paragraph(
    "Your reviewer will ask about both of these. Better to say them yourself than to be "
    "asked.", styles["Lead"]))

story.append(Paragraph("1. KL divergence will not fire against a real model", styles["H2"]))
story.append(Paragraph(
    "The shipped baseline was captured from the offline mock backend, and it records no model "
    "at all. Divergence is only enabled when the baseline names the same model the request is "
    "using, so in the shipped state it is off for <i>every</i> request, and a one-shot "
    "<font face='Courier'>divergence_disabled</font> info event records the reason "
    "(<font face='Courier'>baseline_records_no_model</font>).", styles["Body"]))
story.append(Paragraph(
    "That is <b>honest degradation, and it is worth showing as a feature</b> &mdash; the "
    "system declines to score what it cannot score, and it says which of the two reasons "
    "applies rather than guessing. But the stream-termination behaviour has to be "
    "demonstrated against the mock backend "
    "(<font face='Courier'>MONOLITH_MODEL_BACKEND=mock</font>, which is what Compose already "
    "runs), not against Claude.", styles["Body"]))

story.append(Paragraph("2. The prompt is not redacted on the way in", styles["H2"]))
story.append(Paragraph(
    "The scanner runs on the model's <b>output</b> stream. If you paste a live credential into "
    "the session, it travels upstream in the request, unredacted. The mock backend deliberately "
    "leaks prompt secrets back, and the scripted gateway demo gets its leak from a local stub "
    "server that emits AWS's published example key. A real model will not leak it, so nothing "
    "arrives for the scanner to catch unless the model is asked to quote it.", styles["Body"]))
story.append(Paragraph(
    "For the demo, use <font face='Courier'>AKIAIOSFODNN7EXAMPLE</font> &mdash; AWS's own "
    "published example key. It is in the AWS documentation precisely so scanners recognise "
    "it, and it is not a credential to anything.", styles["Body"]))

# ============================ INSURANCE ==================================
story.append(Spacer(1, 14))
story.append(Paragraph("Insurance", styles["H1"]))
story.append(rule(ACCENT, 1.5, 6))
story.append(Paragraph(
    "If the live path misbehaves on camera, the scripted demos are deterministic and assert "
    "their own pass or fail. They use no API key and no credits.", styles["Lead"]))
story.append(terminal([
    "./run_full_demo.sh                # three attacks, one compromised session, all correlated",
    "bash scripts/run_gateway_demo.sh  # the whole gateway chain, end to end",
]))
story.append(Spacer(1, 8))
story.append(see_what([
    "<font face='Courier'>run_gateway_demo.sh</font> prints "
    "<b>[PASS] the agent never received the credential</b> as its first assertion, and ends "
    "with <b>Every assertion passed.</b> &mdash; the cleanest pair of sentences to end a "
    "demo on.",
]))

# ============================ QUICK REF ==================================
story.append(PageBreak())
story.append(Paragraph("Quick reference", styles["H1"]))
story.append(rule(ACCENT, 1.5, 6))
story.append(Paragraph(
    "One page. Everything you need on screen while you are speaking.", styles["Lead"]))

story.append(Paragraph("Prompts to type, in order", styles["H2"]))
story.append(prompt([
    "Use the retrieve tool with exactly this query:",
    "  how do I prune tomato plants in my garden",
    "  what is a red giant star in a galaxy",
    "  how long should I boil pasta noodles",
    "  how much emergency fund and savings should I budget",
], accent=MEMORY))
story.append(Spacer(1, 4))
story.append(Paragraph(
    "One query per turn &mdash; the fourth is the one that trips the memory layer.",
    styles["CardBody"]))
story.append(Spacer(1, 5))
story.append(prompt([
    "I'm debugging an AWS SDK call that keeps failing. My access key id is",
    "AKIAIOSFODNN7EXAMPLE",
    "and STS says my email is dba@example-internal.io.",
    "Summarise what could be wrong.",
], accent=REASON))

story.append(Spacer(1, 10))
story.append(Paragraph("Commands, in order", styles["H2"]))
story.append(terminal([
    "# Terminal 1 - the agent",
    "python scripts/monolith_wrap.py --claude",
    "",
    "# Terminal 3 - the tool layer",
    "cd mcp-shield && bash fixtures/run_demo.sh",
    "",
    "# Terminal 2 - the operator, after the findings land",
    "curl -X POST http://localhost:3000/api/incidents/<event_id>/session \\",
    "  -H \"Authorization: Bearer $MONOLITH_OPERATOR_TOKEN\" \\",
    "  -H \"Content-Type: application/json\" -d '{\"reason\":\"demo\"}'",
    "# insurance",
    "bash scripts/run_gateway_demo.sh",
]))

story.append(Spacer(1, 6))
story.append(KeepTogether([
    Paragraph("What each layer should have shown", styles["H2"]),
    table(
        ["Beat", "Module", "Event", "Effect"],
        [
            ["1", "<font color='#0f9488'><b>VectorAnchor</b></font>", "<font face='Courier'>corpus_poison_quarantine</font>",
             "The bait document withheld; the agent is told how many were withheld"],
            ["2", "<font color='#7c3aed'><b>TraceAudit</b></font>", "<font face='Courier'>pii_redacted</font>",
             "The agent reads <font face='Courier'>[REDACTED:...]</font> in place of the credential"],
            ["3", "<font color='#2f6fdb'><b>MCP-Shield</b></font>", "<font face='Courier'>schema_mismatch</font>",
             "Enforce mode hands back the approved schema; the mutation is blocked"],
            ["&mdash;", "cross-layer breaker", "<font face='Courier'>session_quarantined</font>",
             "Two layers agreed, so the agent's next request is refused"],
        ],
        [16 * mm, 34 * mm, 57 * mm, 63 * mm],
    ),
]))

story.append(Spacer(1, 14))
story.append(rule(CARDLINE, 1, 4))
story.append(Paragraph(
    "Project Black Monolith &mdash; defensive security middleware for autonomous AI agents. "
    "All attack material in this repository is local detection-test fixture. "
    "Session ids, tokens and the AWS key above are synthetic.",
    styles["Foot"]))


# ---- build ---------------------------------------------------------------
def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(FAINT)
    canvas.drawString(20 * mm, 12 * mm, "Project Black Monolith — Live Demo Guide")
    canvas.drawRightString(190 * mm, 12 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(CARDLINE)
    canvas.setLineWidth(0.5)
    canvas.line(20 * mm, 15 * mm, 190 * mm, 15 * mm)
    canvas.restoreState()


doc = SimpleDocTemplate(
    OUT,
    pagesize=A4,
    leftMargin=20 * mm, rightMargin=20 * mm,
    topMargin=18 * mm, bottomMargin=20 * mm,
    title="Project Black Monolith — Live Demo Guide",
    author="Project Black Monolith",
    subject="Putting a real agent behind the defense stack and stopping it",
)
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print(f"wrote {OUT}")
