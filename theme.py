"""theme.py - Heimdal-style SOC dashboard theme for SentinelCode AI (pure CSS + inline SVG)."""
import html
import math
import streamlit as st
 
esc = html.escape
SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_COLOR = {"CRITICAL": "#ff2d6f", "HIGH": "#ff9f1a", "MEDIUM": "#3b6bff", "LOW": "#7ed321"}
SEV_LABEL = {"CRITICAL": "Critique", "HIGH": "Élevée", "MEDIUM": "Moyenne", "LOW": "Faible"}
PALETTE = ["#ff2d6f", "#3b6bff", "#8b5cf6", "#ff9f1a", "#7ed321", "#22d3ee"]
 
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700;800&display=swap');
:root{--bg:#12131b;--card:#181a2b;--side:#242636;--line:#2b2e48;--text:#e9ebf5;--dim:#6f7391;--blue:#2f6bff;--violet:#6d4dff}
html,body,[class*="css"],.stApp{font-family:'Montserrat',sans-serif;color:var(--text)}
.stApp{background:radial-gradient(1100px 600px at 65% -10%,#1e2036 0%,transparent 60%),radial-gradient(700px 500px at 0% 100%,#1a1630 0%,transparent 60%),var(--bg)}
#MainMenu,footer{visibility:hidden}
header[data-testid="stHeader"]{background:transparent}
.block-container{padding:1rem 1.5rem 2rem;max-width:100%}
section[data-testid="stSidebar"]{background:var(--side);border-right:1px solid #1c1d2b;min-width:230px}
section[data-testid="stSidebar"] .block-container{padding:0}
 
/* sidebar */
.sc-logo{display:flex;align-items:center;gap:10px;font-weight:800;font-size:1.25rem;padding:18px 18px 6px}
.sc-user{text-align:center;padding:14px 10px 16px;font-size:.78rem;color:#c9cce6}
.sc-av{width:46px;height:46px;border-radius:50%;margin:0 auto 8px;display:flex;align-items:center;justify-content:center;font-weight:800;background:linear-gradient(135deg,#ff2d6f,#6d4dff);color:#fff}
.sc-user b{display:block;color:#fff;font-size:.9rem}
.sc-user small{color:var(--dim)}
section[data-testid="stSidebar"] div[role="radiogroup"]{gap:0}
section[data-testid="stSidebar"] div[role="radiogroup"] label{width:100%;padding:12px 18px;margin:0;border-radius:0;color:#b8bbd6;font-size:.85rem;font-weight:600}
section[data-testid="stSidebar"] div[role="radiogroup"] label>div:first-child{display:none}
section[data-testid="stSidebar"] div[role="radiogroup"] label:hover{background:#2c2e42}
section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked){background:linear-gradient(90deg,#2f6bff,#3d5bff);color:#fff}
.sc-side-status{padding:14px 18px;font-size:.75rem;color:#9ea2c4;border-top:1px solid #1c1d2b;margin-top:14px}
.sc-side-status b{color:#fff}
 
/* top pills */
.sc-pill{display:flex;align-items:center;justify-content:center;height:40px;border-radius:6px;font-size:.75rem;font-weight:700;color:#fff;background:linear-gradient(90deg,#5b3df5,#7c5cff);white-space:nowrap}
.sc-pill.blue{background:linear-gradient(90deg,#2f6bff,#4d84ff)}
.sc-pill.bad{background:linear-gradient(90deg,#c81e5a,#ff2d6f)}
 
/* cards */
.sc-card{position:relative;border:1px solid transparent;border-radius:14px;padding:14px 16px;overflow:hidden;
background:linear-gradient(var(--card),var(--card)) padding-box,linear-gradient(135deg,rgba(255,45,111,.9),rgba(47,107,255,.9) 55%,rgba(139,92,246,.75)) border-box;
box-shadow:0 10px 30px -14px rgba(0,0,0,.8)}
.h1{height:345px}.h2{height:300px}.h3{height:280px}
.sc-ch{display:flex;justify-content:space-between;align-items:center;font-weight:700;font-size:.86rem;margin-bottom:10px}
.sc-chip{background:var(--blue);color:#fff;font-size:.62rem;font-weight:700;padding:4px 9px;border-radius:4px}
.sc-m{display:flex;align-items:center;gap:8px;font-size:.78rem;font-weight:600;margin:4px 0}
.sc-m i{width:9px;height:9px;border-radius:50%;box-shadow:0 0 8px currentColor}
.sc-m b{font-size:.9rem}
.sc-sub{font-size:.66rem;color:var(--dim);margin:6px 0 8px}
.sc-donut{display:flex;justify-content:center}
.sc-donut svg{width:100%;max-width:170px;height:auto;filter:drop-shadow(0 0 12px rgba(59,107,255,.45))}
.sc-dn{fill:#fff;font-size:24px;font-weight:800;font-family:'Montserrat',sans-serif}
.sc-dl{fill:var(--dim);font-size:8.5px;font-family:'Montserrat',sans-serif}
.sc-lg{display:grid;grid-template-columns:1fr 1fr;gap:6px 10px;font-size:.68rem;color:#aab0d0;margin-top:10px}
.sc-lg span{display:flex;align-items:center;gap:6px}
.sc-lg i{width:8px;height:8px;border-radius:50%;flex:none}
.sc-lg em{font-style:normal;font-weight:700;color:#fff}
.sc-lg.row{display:flex;justify-content:center;gap:14px}
 
/* tables */
.sc-t{width:100%;border-collapse:collapse;font-size:.68rem;margin-top:6px}
.sc-t th{text-align:left;color:#aab0d0;font-weight:600;padding:5px 4px;font-size:.62rem;letter-spacing:.3px}
.sc-t td{padding:7px 4px;color:#7d81a3;border-bottom:1px solid rgba(43,46,72,.5);max-width:110px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sc-sev{font-weight:700}
.sc-empty{color:var(--dim);font-size:.72rem;text-align:center;padding:26px 0}
.sc-ax{fill:var(--dim);font-size:8px;font-family:'Montserrat',sans-serif}
 
/* bottom card */
.sc-bottom{display:grid;grid-template-columns:1fr 1.1fr 1.2fr 1.2fr;gap:18px;align-items:start}
.sc-top{display:flex;gap:16px;flex-wrap:wrap;font-size:.7rem;color:#aab0d0;font-weight:600}
.sc-top i{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;background:#ff2d6f}
.sc-ir{display:flex;align-items:center;gap:12px;margin:7px 0}
.sc-ic{width:36px;height:36px;border-radius:50%;border:2px solid;display:flex;align-items:center;justify-content:center;font-size:.9rem;box-shadow:0 0 12px -2px currentColor}
.sc-ir b{font-size:1rem}.sc-ir span{font-size:.66rem;color:#aab0d0}
.sc-al{display:flex;justify-content:space-between;font-size:.7rem;color:#7d81a3;padding:6px 0;border-bottom:1px solid rgba(43,46,72,.5)}
.sc-al b{color:#ff2d6f}
.sc-globe svg{width:100%;max-width:200px;filter:drop-shadow(0 0 22px rgba(59,107,255,.65))}
 
/* streamlit widgets */
div[data-testid="stTextInput"] input,div[data-testid="stTextArea"] textarea{background:#181a2b;border:1px solid var(--line);color:var(--text);border-radius:8px;font-family:'Montserrat',sans-serif}
section[data-testid="stFileUploaderDropzone"]{background:#181a2b;border:1px dashed var(--line);border-radius:8px}
.stButton>button,.stDownloadButton>button{background:linear-gradient(90deg,#2f6bff,#4d84ff);color:#fff;border:0;border-radius:6px;font-weight:700;font-family:'Montserrat',sans-serif;height:40px}
.stButton>button:hover,.stDownloadButton>button:hover{filter:brightness(1.15);color:#fff}
div[data-testid="stExpander"]{background:var(--card);border:1px solid var(--line);border-radius:12px}
hr{border-color:var(--line)}
@media(max-width:900px){.sc-bottom{grid-template-columns:1fr}.h1,.h2,.h3{height:auto}}
</style>
"""
 
 
def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)
 
 
def sidebar_brand(initials="SA", name="Security Analyst", role="DevSecOps Auditor"):
    shield = ('<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2">'
              '<path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z"/><path d="M9 12l2 2 4-4"/></svg>')
    st.markdown(f'<div class="sc-logo">{shield} SentinelCode</div>'
                f'<div class="sc-user"><div class="sc-av">{esc(initials)}</div>Bienvenue,'
                f'<b>{esc(name)}</b><small>{esc(role)}</small></div>', unsafe_allow_html=True)
 
 
def pill(text, kind=""):
    st.markdown(f'<div class="sc-pill {kind}">{esc(text)}</div>', unsafe_allow_html=True)
 
 
def card(title, body, h="h1", chip=None):
    chip_html = f'<span class="sc-chip">{esc(chip)}</span>' if chip else ""
    st.markdown(f'<div class="sc-card {h}"><div class="sc-ch"><span>{esc(title)}</span>{chip_html}</div>{body}</div>',
                unsafe_allow_html=True)
 
 
def wide_card(inner, h="h3"):
    st.markdown(f'<div class="sc-card {h}">{inner}</div>', unsafe_allow_html=True)
 
 
def metric(n, label, color):
    return f'<div class="sc-m"><i style="background:{color};color:{color}"></i><b style="color:{color}">{n}</b> {esc(label)}</div>'
 
 
def donut(segments, center, label="", r=56, stroke=14):
    """segments: [(value, color)]."""
    total = sum(v for v, _ in segments)
    circ = 2 * math.pi * r
    out = [f'<circle cx="80" cy="80" r="{r}" fill="none" stroke="#20233a" stroke-width="{stroke}"/>']
    cum = 0.0
    for v, c in segments:
        if v <= 0 or total <= 0:
            continue
        f = v / total
        out.append(f'<circle cx="80" cy="80" r="{r}" fill="none" stroke="{c}" stroke-width="{stroke}" stroke-linecap="round" '
                   f'stroke-dasharray="{max(f * circ - 4, .1):.2f} {circ:.2f}" stroke-dashoffset="{-cum * circ:.2f}" transform="rotate(-90 80 80)"/>')
        cum += f
    out.append(f'<text x="80" y="82" text-anchor="middle" class="sc-dn">{esc(str(center))}</text>'
               f'<text x="80" y="97" text-anchor="middle" class="sc-dl">{esc(label)}</text>')
    return f'<div class="sc-donut"><svg viewBox="0 0 160 160">{"".join(out)}</svg></div>'
 
 
def legend(items, cols=True):
    """items: [(label, color, count)]."""
    inner = "".join(f'<span><i style="background:{c}"></i><em>{n}</em> {esc(l)}</span>' for l, c, n in items)
    return f'<div class="sc-lg{"" if cols else " row"}">{inner}</div>'
 
 
def area_chart(series, labels):
    """series: [(values, color)]. Two-line area chart like the network graph."""
    W, H, L, B, T = 300, 150, 26, 22, 8
    if len(labels) < 2:
        labels = (list(labels) + [""] * 2)[:2]
        series = [((list(v) + [0, 0])[:2], c) for v, c in series]
    n = len(labels)
    mx = max([max(v) for v, _ in series if v] + [1])
    x = lambda i: L + i * (W - L - 6) / (n - 1)
    y = lambda v: T + (H - T - B) * (1 - v / mx)
    g = ""
    for f in (0, .33, .66, 1):
        yy = T + (H - T - B) * (1 - f)
        g += f'<line x1="{L}" x2="{W - 6}" y1="{yy:.1f}" y2="{yy:.1f}" stroke="#2b2e48"/><text x="2" y="{yy + 3:.1f}" class="sc-ax">{round(mx * f)}</text>'
    defs, body = "", ""
    for k, (vals, c) in enumerate(series):
        pts = [(x(i), y(v)) for i, v in enumerate(vals)]
        line = "M" + " L".join(f"{a:.1f},{b:.1f}" for a, b in pts)
        area = line + f" L{pts[-1][0]:.1f},{H - B} L{pts[0][0]:.1f},{H - B} Z"
        defs += f'<linearGradient id="ag{k}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="{c}" stop-opacity=".35"/><stop offset="1" stop-color="{c}" stop-opacity="0"/></linearGradient>'
        body += f'<path d="{area}" fill="url(#ag{k})"/><path d="{line}" fill="none" stroke="{c}" stroke-width="2"/>'
    step = max(1, len(labels) // 6)
    xl = "".join(f'<text x="{x(i):.1f}" y="{H - 6}" class="sc-ax" transform="rotate(-25 {x(i):.1f} {H - 6})">{esc(str(lb)[:9])}</text>'
                 for i, lb in enumerate(labels) if i % step == 0)
    return f'<svg viewBox="0 0 {W} {H}" style="width:100%;height:auto"><defs>{defs}</defs>{g}{body}{xl}</svg>'
 
 
def globe():
    lat = "".join(f'<ellipse cx="100" cy="100" rx="78" ry="{ry}" fill="none" stroke="#3b6bff" stroke-opacity=".35"/>' for ry in (26, 52))
    lon = "".join(f'<ellipse cx="100" cy="100" rx="{rx}" ry="78" fill="none" stroke="#3b6bff" stroke-opacity=".35"/>' for rx in (26, 52))
    dots = "".join(f'<circle cx="{a}" cy="{b}" r="3.2" fill="#ff2d6f"><animate attributeName="opacity" values="1;.3;1" dur="2.4s" repeatCount="indefinite"/></circle>' for a, b in ((70, 62), (118, 80), (86, 118), (132, 122)))
    return ('<div class="sc-globe"><svg viewBox="0 0 200 200"><defs><radialGradient id="gl" cx="38%" cy="32%"><stop offset="0" stop-color="#3b82f6" stop-opacity=".7"/>'
            '<stop offset="1" stop-color="#0b1030"/></radialGradient></defs>'
            f'<circle cx="100" cy="100" r="78" fill="url(#gl)" stroke="#4d84ff" stroke-opacity=".7"/>{lat}{lon}'
            f'<line x1="22" x2="178" y1="100" y2="100" stroke="#3b6bff" stroke-opacity=".35"/><line x1="100" x2="100" y1="22" y2="178" stroke="#3b6bff" stroke-opacity=".35"/>{dots}</svg></div>')
 
 
def sev_tag(sev):
    c = SEV_COLOR.get(sev, "#6f7391")
    return f'<span class="sc-sev" style="color:{c}">▲ {esc(SEV_LABEL.get(sev, sev))}</span>'
 
 
def table(headers, rows):
    """rows: list of lists of ready-to-render HTML/text cells."""
    if not rows:
        return '<div class="sc-empty">Aucune donnée. Lancez un audit.</div>'
    th = "".join(f"<th>{esc(h)}</th>" for h in headers)
    tr = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<table class="sc-t"><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table>'
 
 
def icon_row(glyph, color, n, label):
    return (f'<div class="sc-ir"><div class="sc-ic" style="border-color:{color};color:{color}">{glyph}</div>'
            f'<div><b style="color:{color}">{n}</b><br><span>{esc(label)}</span></div></div>')
 
 
def alert_rows(pairs):
    if not pairs:
        return '<div class="sc-empty">Aucune alerte.</div>'
    return "".join(f'<div class="sc-al"><span>▲ {esc(str(k))}</span><b>{v}</b></div>' for k, v in pairs)
 