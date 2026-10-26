"""Build the AEOS Guard project overview PDF — simple, non-technical language."""

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, ListFlowable, ListItem, KeepTogether,
)

OUT = "AEOS_Guard_Project_Overview.pdf"

# ---- palette -------------------------------------------------------------
INK      = colors.HexColor("#16171b")
MUTED    = colors.HexColor("#5b6270")
FAINT    = colors.HexColor("#8a90a0")
ACCENT   = colors.HexColor("#c62b45")   # deep crimson
TOOL     = colors.HexColor("#2f6fdb")   # blue
MEMORY   = colors.HexColor("#0f9488")   # teal
REASON   = colors.HexColor("#7c3aed")   # violet
CARD     = colors.HexColor("#f4f5f7")
CARDLINE = colors.HexColor("#e3e5ea")
PALEACC  = colors.HexColor("#fae9ec")

# ---- styles --------------------------------------------------------------
styles = getSampleStyleSheet()

def S(name, **kw):
    styles.add(ParagraphStyle(name, **kw))

S("Cover",       fontName="Helvetica-Bold", fontSize=30, leading=35, textColor=INK, alignment=TA_CENTER)
S("CoverSub",    fontName="Helvetica",      fontSize=13, leading=19, textColor=MUTED, alignment=TA_CENTER)
S("CoverTag",    fontName="Helvetica-Bold", fontSize=10.5, leading=15, textColor=ACCENT, alignment=TA_CENTER)
S("CoverMeta",   fontName="Helvetica",      fontSize=9.5, leading=15, textColor=FAINT, alignment=TA_CENTER)

S("H1",   fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=INK, spaceBefore=2, spaceAfter=8)
S("H2",   fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=ACCENT, spaceBefore=12, spaceAfter=5)
S("Body", fontName="Helvetica",      fontSize=10.5, leading=16, textColor=INK, spaceAfter=7)
S("BodyTight", fontName="Helvetica", fontSize=10.5, leading=15.5, textColor=INK, spaceAfter=2)
S("Lead", fontName="Helvetica",      fontSize=11.5, leading=17.5, textColor=MUTED, spaceAfter=8)
S("ABullet", fontName="Helvetica",    fontSize=10.5, leading=15, textColor=INK)
S("CardTitle", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=INK)
S("CardBody",  fontName="Helvetica", fontSize=9.7, leading=13.5, textColor=MUTED)
S("Kicker", fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=ACCENT)
S("Foot", fontName="Helvetica", fontSize=8, leading=10, textColor=FAINT, alignment=TA_CENTER)
S("Quote", fontName="Helvetica-Oblique", fontSize=11, leading=17, textColor=INK)
S("TblHead", fontName="Helvetica-Bold", fontSize=9.5, leading=12.5, textColor=colors.white)
S("TblCell", fontName="Helvetica", fontSize=9.3, leading=12.5, textColor=INK)
S("TblCellB", fontName="Helvetica-Bold", fontSize=9.3, leading=12.5, textColor=INK)

def bullets(items, color=ACCENT, style="ABullet"):
    return ListFlowable(
        [ListItem(Paragraph(t, styles[style]), leftIndent=6, value="•") for t in items],
        bulletType="bullet", bulletColor=color, bulletFontSize=10,
        leftIndent=12, spaceBefore=1, spaceAfter=6,
    )

def rule(color=CARDLINE, w=1, space=8):
    return HRFlowable(width="100%", thickness=w, color=color, spaceBefore=space, spaceAfter=space)

# a soft "card" made from a one-cell table
def card(flowables, bg=CARD, line=CARDLINE, pad=10):
    t = Table([[flowables]], colWidths=[None])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), bg),
        ("BOX", (0,0), (-1,-1), 0.8, line),
        ("LEFTPADDING", (0,0), (-1,-1), pad),
        ("RIGHTPADDING", (0,0), (-1,-1), pad),
        ("TOPPADDING", (0,0), (-1,-1), pad),
        ("BOTTOMPADDING", (0,0), (-1,-1), pad),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
    ]))
    return t

story = []

# ============================ COVER =======================================
story.append(Spacer(1, 55*mm))
story.append(Paragraph("AEOS GUARD", styles["Cover"]))
story.append(Spacer(1, 4))
story.append(Paragraph("Agentic Execution and Operations Security", styles["CoverSub"]))
story.append(Spacer(1, 10))
story.append(HRFlowable(width="38%", thickness=2, color=ACCENT, spaceBefore=2, spaceAfter=12, hAlign="CENTER"))
story.append(Paragraph("A Unified Security Middleware for Autonomous AI Systems", styles["CoverTag"]))
story.append(Spacer(1, 40))
story.append(Paragraph("Project Overview &nbsp;·&nbsp; For academic review", styles["CoverMeta"]))
story.append(Spacer(1, 3))
story.append(Paragraph("Prepared for classroom presentation", styles["CoverMeta"]))
story.append(PageBreak())

# ============================ 1. WHAT IS IT ================================
story.append(Paragraph("What is AEOS Guard?", styles["H1"]))
story.append(rule(ACCENT, 1.5, 6))
story.append(Paragraph(
    "AEOS Guard is a <b>security layer that sits around an AI agent</b> and watches "
    "everything it does, in real time, to catch attacks before they cause harm.",
    styles["Lead"]))
story.append(Paragraph(
    "Modern AI agents don't just answer questions — they take actions on their own. "
    "They use tools, look things up in a memory, and reason through problems step by step. "
    "That freedom is what makes them useful, but it also gives attackers three separate "
    "doors to sneak through. AEOS Guard is a security guard standing at all three doors "
    "at once, and it reports everything it sees to a single live dashboard.",
    styles["Body"]))

story.append(Spacer(1, 6))
story.append(Paragraph("In one sentence", styles["Kicker"]))
story.append(card([Paragraph(
    "“AEOS Guard protects an AI agent's <b>tools</b>, its <b>memory</b>, and its "
    "<b>reasoning</b> — the three places it can be attacked — and shows a security "
    "team exactly what was attempted and what was stopped.”",
    styles["Quote"])], bg=PALEACC, line=colors.HexColor("#f0cdd4")))

story.append(Spacer(1, 12))
story.append(Paragraph("Who is it for?", styles["H2"]))
story.append(bullets([
    "<b>Companies building AI agents</b> that act on their own — customer-service bots, "
    "coding assistants, research agents — and need to trust what those agents do.",
    "<b>Security teams</b> who currently have no single place to see what is being attempted "
    "against their AI systems.",
    "<b>Anyone deploying an AI agent</b> in the real world, where the tools and data it "
    "relies on cannot all be assumed safe.",
]))

story.append(PageBreak())

# ============================ 2. THE PROBLEM ==============================
story.append(Paragraph("The Problem", styles["H1"]))
story.append(rule(ACCENT, 1.5, 6))
story.append(Paragraph(
    "An autonomous AI agent can be attacked in more than one place — and protecting only "
    "one place leaves the others wide open. Today, most defences look at a single layer. "
    "AEOS Guard is built on the idea that a real attacker won't politely stick to one.",
    styles["Body"]))
story.append(Spacer(1, 4))

# three problem cards
def problem_card(color, layer, title, body):
    inner = [
        Paragraph(f'<font color="{color.hexval()}">{layer}</font>', styles["Kicker"]),
        Spacer(1, 3),
        Paragraph(title, styles["CardTitle"]),
        Spacer(1, 4),
        Paragraph(body, styles["CardBody"]),
    ]
    return card(inner, bg=colors.white, line=CARDLINE, pad=11)

pcards = [
    problem_card(TOOL, "TOOL LAYER", "The tools get swapped",
        "An agent approves a tool that looks safe. Later, the tool quietly changes its own "
        "instructions and turns malicious — a “rug pull.” The agent never notices."),
    problem_card(MEMORY, "MEMORY LAYER", "The memory gets poisoned",
        "An attacker plants a booby-trapped document in the agent's memory, cleverly written "
        "to get pulled into almost every conversation — no matter what is being asked."),
    problem_card(REASON, "REASONING LAYER", "The thinking gets hijacked",
        "The agent can be steered into unsafe reasoning, or coaxed into leaking a password "
        "or private detail in the middle of its own thought process."),
]
pt = Table([[pcards[0], pcards[1], pcards[2]]], colWidths=[None, None, None])
pt.setStyle(TableStyle([
    ("VALIGN", (0,0), (-1,-1), "TOP"),
    ("LEFTPADDING", (0,0), (-1,-1), 0),
    ("RIGHTPADDING", (0,0), (0,0), 5),
    ("RIGHTPADDING", (1,0), (1,0), 5),
    ("LEFTPADDING", (1,0), (1,0), 5),
    ("LEFTPADDING", (2,0), (2,0), 5),
]))
story.append(pt)

story.append(Spacer(1, 12))
story.append(Paragraph("Why this is hard", styles["H2"]))
story.append(bullets([
    "The three attacks look completely unrelated — they happen in different places, "
    "at different times, in different formats.",
    "A tool that hardens only one door gives a false sense of safety.",
    "Even when each attack is spotted, nobody can see that they are <b>the same attacker</b>, "
    "running one coordinated campaign against one agent.",
]))

story.append(Spacer(1, 4))
story.append(card([Paragraph(
    "<b>The core problem:</b> three separate blind spots, and no single view that connects them.",
    styles["BodyTight"])], bg=PALEACC, line=colors.HexColor("#f0cdd4")))

story.append(PageBreak())

# ============================ 3. THE SOLUTION =============================
story.append(Paragraph("The Solution", styles["H1"]))
story.append(rule(ACCENT, 1.5, 6))
story.append(Paragraph(
    "AEOS Guard places an independent <b>defender at each of the three doors</b>, and connects "
    "them to <b>one dashboard</b> that shows the whole picture. Each defender works on its own, "
    "but they all speak the same language — so the dashboard can tell when the same agent is "
    "being hit at more than one layer.",
    styles["Body"]))
story.append(Spacer(1, 4))

def solution_card(color, name, layer, what):
    inner = [
        Paragraph(f'<font color="{color.hexval()}"><b>{name}</b></font> &nbsp; '
                  f'<font color="{FAINT.hexval()}" size="8">{layer}</font>', styles["CardTitle"]),
        Spacer(1, 4),
        Paragraph(what, styles["CardBody"]),
    ]
    return card(inner, bg=CARD, line=CARDLINE, pad=11)

scards = [
    solution_card(TOOL, "MCP-Shield", "TOOL LAYER",
        "Takes a secure “fingerprint” of every tool when it is first approved. If a tool "
        "later changes, MCP-Shield spots the mismatch and <b>blocks the tampered version</b>, "
        "handing the agent back the original, trusted one."),
    solution_card(MEMORY, "VectorAnchor", "MEMORY LAYER",
        "Watches which documents keep getting pulled into unrelated conversations. A normal "
        "document is relevant to one topic; a booby-trap shows up everywhere — so VectorAnchor "
        "<b>quarantines it</b> and serves a clean result instead."),
    solution_card(REASON, "TraceAudit", "REASONING LAYER",
        "Reads the agent's reasoning as it streams out. If the thinking drifts somewhere unsafe "
        "it <b>stops the response</b>; if a password or private detail appears, it "
        "<b>blacks it out</b> before anyone can see it."),
]
for c in scards:
    story.append(c)
    story.append(Spacer(1, 7))

story.append(Spacer(1, 4))
story.append(Paragraph("The unifying idea", styles["H2"]))
story.append(Paragraph(
    "Every defender reports what it sees in the <b>same simple format</b> to one live dashboard. "
    "That shared language is what turns three separate tools into a single system — and it is "
    "what lets AEOS Guard say the thing no single defender can: <b>“these three alerts are the "
    "same attacker, hitting the same agent, in one session.”</b>",
    styles["Body"]))

story.append(PageBreak())

# ============================ 4. HOW IT WORKS (visual) ====================
story.append(Paragraph("How It Works", styles["H1"]))
story.append(rule(ACCENT, 1.5, 6))
story.append(Paragraph(
    "Every defender follows the same four-step rhythm, no matter which door it is guarding:",
    styles["Body"]))
story.append(Spacer(1, 6))

# flow steps
steps = [
    ("1", "WATCH", "Sit directly on the path the agent uses — nothing gets past unseen."),
    ("2", "CHECK", "Compare what's happening against what is known to be safe."),
    ("3", "ACT", "Block, quarantine, or black out anything dangerous — automatically."),
    ("4", "REPORT", "Send a clear alert to the shared dashboard, tagged to the agent."),
]
num_style = ParagraphStyle("StepNum", fontName="Helvetica-Bold", fontSize=20,
                           leading=24, textColor=ACCENT)
step_cells = []
for num, title, body in steps:
    inner = [
        Paragraph(num, num_style),
        Spacer(1, 5),
        Paragraph(f'<b>{title}</b>', styles["CardTitle"]),
        Spacer(1, 3),
        Paragraph(body, styles["CardBody"]),
    ]
    step_cells.append(card(inner, bg=colors.white, line=CARDLINE, pad=10))
ft = Table([step_cells], colWidths=[None]*4)
ft.setStyle(TableStyle([
    ("VALIGN", (0,0), (-1,-1), "TOP"),
    ("LEFTPADDING", (0,0), (-1,-1), 3),
    ("RIGHTPADDING", (0,0), (-1,-1), 3),
]))
story.append(ft)

story.append(Spacer(1, 16))
story.append(Paragraph("The dashboard ties it together", styles["H2"]))
story.append(Paragraph(
    "All three defenders feed one real-time screen. A security team sees every detection as it "
    "happens, colour-coded by layer and by how serious it is. They can then take ownership of an "
    "alert, investigate it, and mark it as handled — with a permanent, tamper-proof record of "
    "who did what and why.",
    styles["Body"]))

story.append(Spacer(1, 4))
story.append(card([
    Paragraph("The headline feature", styles["Kicker"]),
    Spacer(1, 4),
    Paragraph(
        "If the tool defender, the memory defender, and the reasoning defender all raise an alert "
        "for the <b>same agent session</b>, the dashboard flags it as <b>one coordinated attack on "
        "one compromised agent</b> — not three unrelated blips. That connected view is the whole "
        "point of the project.",
        styles["BodyTight"]),
], bg=PALEACC, line=colors.HexColor("#f0cdd4")))

story.append(PageBreak())

# ============================ 5. WHAT IT SOLVES (table) ===================
story.append(Paragraph("Problems Solved, at a Glance", styles["H1"]))
story.append(rule(ACCENT, 1.5, 6))
story.append(Spacer(1, 2))

def cell(txt, st="TblCell"):
    return Paragraph(txt, styles[st])

data = [
    [cell("Layer", "TblHead"), cell("The attack", "TblHead"), cell("What AEOS Guard does", "TblHead")],
    [cell("Tool", "TblCellB"),
     cell("A trusted tool is secretly swapped for a malicious one."),
     cell("Fingerprints every tool and blocks any tampered version.")],
    [cell("Memory", "TblCellB"),
     cell("A poisoned document is planted to reach every conversation."),
     cell("Spots the over-appearing document and quarantines it.")],
    [cell("Reasoning", "TblCellB"),
     cell("The agent is steered off-course or leaks a secret."),
     cell("Stops unsafe reasoning and blacks out leaked secrets.")],
    [cell("All three", "TblCellB"),
     cell("The same attacker hits several layers and looks unrelated."),
     cell("Links the alerts to one agent session and one campaign.")],
]
tbl = Table(data, colWidths=[62, 210, 210])
tbl.setStyle(TableStyle([
    ("BACKGROUND", (0,0), (-1,0), ACCENT),
    ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, CARD]),
    ("GRID", (0,0), (-1,-1), 0.6, CARDLINE),
    ("LINEBELOW", (0,0), (-1,0), 0, ACCENT),
    ("VALIGN", (0,0), (-1,-1), "TOP"),
    ("LEFTPADDING", (0,0), (-1,-1), 8),
    ("RIGHTPADDING", (0,0), (-1,-1), 8),
    ("TOPPADDING", (0,0), (-1,-1), 7),
    ("BOTTOMPADDING", (0,0), (-1,-1), 7),
]))
story.append(tbl)

story.append(Spacer(1, 16))
story.append(Paragraph("What makes it stand out", styles["H2"]))
story.append(bullets([
    "<b>Defence in depth.</b> Three independent guards, not one — breaking through one does not "
    "get you past the others.",
    "<b>One connected picture.</b> The first system that can say three separate alerts are the "
    "same attacker.",
    "<b>Never loses an alert.</b> If the dashboard is briefly down, every detection is saved and "
    "delivered when it comes back — a security tool must not drop evidence.",
    "<b>Runs on your own machine.</b> No cloud service required; the whole system starts with a "
    "single command and works fully offline.",
    "<b>Honest about its limits.</b> Every claim is backed by a test, and the known ways to slip "
    "past it are measured and written down — not hidden.",
]))

story.append(PageBreak())

# ============================ 6. RESULTS + CLOSE =========================
story.append(Paragraph("Where the Project Stands", styles["H1"]))
story.append(rule(ACCENT, 1.5, 6))
story.append(Paragraph(
    "AEOS Guard is a working system, not a slide deck. All three defenders run, the dashboard is "
    "live, and the whole thing can be started with one command and driven through a full "
    "demonstration attack from end to end.",
    styles["Body"]))

story.append(Spacer(1, 6))

# stat tiles
def stat(big, small):
    inner = [
        Paragraph(f'<font color="{ACCENT.hexval()}"><b>{big}</b></font>',
                  ParagraphStyle("s", parent=styles["CardTitle"], fontSize=19, leading=22)),
        Spacer(1, 2),
        Paragraph(small, styles["CardBody"]),
    ]
    return card(inner, bg=colors.white, line=CARDLINE, pad=10)

tiles = [
    stat("3 layers", "guarded independently — tool, memory, reasoning"),
    stat("1 dashboard", "one live, connected view of every attack"),
    stat("100+", "automated checks proving the defences work"),
]
st_t = Table([tiles], colWidths=[None]*3)
st_t.setStyle(TableStyle([
    ("VALIGN", (0,0), (-1,-1), "TOP"),
    ("LEFTPADDING", (0,0), (-1,-1), 3),
    ("RIGHTPADDING", (0,0), (-1,-1), 3),
]))
story.append(st_t)

story.append(Spacer(1, 14))
story.append(Paragraph("Proven end to end", styles["H2"]))
story.append(bullets([
    "A full demonstration launches all three attacks and confirms every one is caught, "
    "recorded, and traced back to a single compromised agent session.",
    "The defenders add almost no delay — the checks take microseconds, far too fast for a "
    "user to notice.",
    "The known ways an attacker could still slip past are deliberately tested and measured, "
    "so the project is honest about exactly how far its protection reaches.",
]))

story.append(Spacer(1, 10))
story.append(Paragraph("In short", styles["H2"]))
story.append(card([Paragraph(
    "<b>AEOS Guard makes an autonomous AI agent safe to trust</b> — by guarding all three "
    "places it can be attacked, catching the attacks automatically, and giving a security team "
    "one clear, connected view of everything that was attempted and everything that was stopped.",
    styles["BodyTight"])], bg=PALEACC, line=colors.HexColor("#f0cdd4")))

# ---- footer on every page ------------------------------------------------
def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(FAINT)
    if doc.page > 1:
        canvas.drawString(20*mm, 12*mm, "AEOS Guard — Project Overview")
        canvas.drawRightString(190*mm, 12*mm, f"Page {doc.page}")
    canvas.setStrokeColor(CARDLINE)
    canvas.setLineWidth(0.5)
    if doc.page > 1:
        canvas.line(20*mm, 15*mm, 190*mm, 15*mm)
    canvas.restoreState()

doc = SimpleDocTemplate(
    OUT, pagesize=A4,
    leftMargin=20*mm, rightMargin=20*mm,
    topMargin=18*mm, bottomMargin=20*mm,
    title="AEOS Guard — Project Overview",
    author="AEOS Guard project team",
)
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print("wrote", OUT)
