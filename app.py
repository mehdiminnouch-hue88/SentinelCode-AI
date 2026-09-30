import json
import os
from collections import Counter
 
import streamlit as st
 
from core_agent import (
    extract_code_from_zip, analyze_repository, analyze_single_snippet,
    fetch_github_repo_zip, execute_verification_test, DEFAULT_MODEL,
)
from pdf_generator import create_pdf_report
from theme import (
    SEV, SEV_COLOR, SEV_LABEL, PALETTE, esc, inject_css, sidebar_brand, pill, card, wide_card,
    metric, donut, legend, area_chart, globe, sev_tag, table, icon_row, alert_rows,
)
 
st.set_page_config(page_title="SentinelCode AI | Security Auditor", page_icon="🛡️", layout="wide")
inject_css()
 
# ---- API key: env first, then Streamlit secrets ----
if not os.environ.get("ANTHROPIC_API_KEY"):
    try:
        if "ANTHROPIC_API_KEY" in st.secrets:
            os.environ["ANTHROPIC_API_KEY"] = st.secrets["ANTHROPIC_API_KEY"]
    except Exception:
        pass
has_api_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
model_name = os.environ.get("CLAUDE_MODEL", DEFAULT_MODEL)
 
SAMPLE = "import os\n\ndef run_user_cmd(cmd):\n    os.system(cmd) # Shell Injection"
LANG = {".py": "python", ".js": "javascript", ".ts": "typescript", ".java": "java", ".c": "c", ".cpp": "cpp",
        ".h": "c", ".php": "php", ".go": "go", ".rs": "rust", ".sh": "bash", ".html": "html", ".sql": "sql"}
SECRET_KW = ("secret", "password", "credential", "api key", "apikey", "token", "hardcoded")
INJ_KW = ("injection", "sqli", "xss", "command", "eval", "deserial")
 
 
def category(v):
    t = str(v.get("vulnerability_type", "")).lower()
    if any(k in t for k in SECRET_KW):
        return "secrets"
    if any(k in t for k in INJ_KW):
        return "injection"
    return "other"
 
 
def save_report(r):
    st.session_state["report"] = r
    st.session_state["results"] = {}
 
 
def audit_files(files_map):
    if not files_map:
        st.warning("Aucun fichier source supporté trouvé (ou tous filtrés par la limite de taille).")
        return
    with st.spinner("Claude analyse la sécurité du code..."):
        save_report(analyze_repository(files_map))
 
 
# ================= SIDEBAR (navigation = source de l'audit) =================
with st.sidebar:
    sidebar_brand()
    source = st.radio("Source", ["⌂   Dépôt GitHub", "▤   Fichier ZIP", "‹›   Extrait de code"],
                      label_visibility="collapsed")
    st.markdown(f'<div class="sc-side-status">Claude API : <b>{"● Actif" if has_api_key else "● Clé manquante"}</b><br>'
                f'Modèle : <b>{esc(model_name)}</b></div>', unsafe_allow_html=True)
 
# ================= TOP BAR =================
c_in, c_btn, c_p1, c_p2 = st.columns([4.2, 1.4, 1.5, 1.7])
repo_url, upload, snippet = "", None, ""
with c_in:
    if "GitHub" in source:
        repo_url = st.text_input("url", placeholder="🔍  Coller l'URL d'un dépôt GitHub public (https://github.com/user/repo)",
                                 label_visibility="collapsed")
    elif "ZIP" in source:
        upload = st.file_uploader("zip", type=["zip"], label_visibility="collapsed")
    else:
        snippet = st.text_area("code", value=SAMPLE, height=110, label_visibility="collapsed")
with c_btn:
    go = st.button("🚀 Lancer l'audit", use_container_width=True, disabled=not has_api_key)
with c_p1:
    pill("Claude API ● Actif" if has_api_key else "ANTHROPIC_API_KEY manquante", "blue" if has_api_key else "bad")
with c_p2:
    pill(f"Modèle : {model_name}")
 
if go:
    try:
        if "GitHub" in source:
            if not repo_url:
                st.warning("Entrez une URL GitHub valide.")
            else:
                with st.spinner("Téléchargement du dépôt..."):
                    files_map = extract_code_from_zip(fetch_github_repo_zip(repo_url))
                audit_files(files_map)
        elif "ZIP" in source:
            if upload is None:
                st.warning("Importez d'abord un fichier ZIP.")
            else:
                audit_files(extract_code_from_zip(upload.getvalue()))
        else:
            with st.spinner("Analyse de l'extrait..."):
                save_report(analyze_single_snippet(snippet))
    except Exception as e:
        st.error(f"Échec de l'audit : {str(e)}")
 
# ================= DATA =================
report = st.session_state.get("report") or {}
results = st.session_state.setdefault("results", {})
vulns = report.get("vulnerabilities", []) or []
for v in vulns:
    v["severity"] = str(v.get("severity", "LOW")).upper()
vulns.sort(key=lambda v: SEV.index(v["severity"]) if v["severity"] in SEV else 99)
 
have = bool(report)
score = report.get("overall_security_score", 0) or 0
sev_n = Counter(v["severity"] for v in vulns)
files_analyzed = report.get("total_files_analyzed", 0)
per_file = Counter(str(v.get("file_path", "?")) for v in vulns)
per_file_ch = Counter(str(v.get("file_path", "?")) for v in vulns if v["severity"] in ("CRITICAL", "HIGH"))
types = Counter(str(v.get("vulnerability_type", "?")) for v in vulns)
cats = Counter(category(v) for v in vulns)
base = lambda p: esc(os.path.basename(str(p or "?")))
 
 
def test_cell(i):
    r = results.get(i)
    if r is None:
        return '<span style="color:#6f7391">En attente</span>'
    return '<b style="color:#7ed321">✓ Vérifié</b>' if r["passed"] else '<b style="color:#ff2d6f">✗ Échec</b>'
 
 
def vuln_rows(items, n=5):
    return [[base(v.get("file_path")), esc(str(v.get("vulnerability_type", "?"))), sev_tag(v["severity"])] for v in items[:n]]
 
 
patches = [(i, v) for i, v in enumerate(vulns) if v.get("patched_code")]
ok_n = sum(1 for i, _ in patches if results.get(i, {}).get("passed"))
ko_n = sum(1 for i, _ in patches if i in results and not results[i]["passed"])
wait_n = len(patches) - ok_n - ko_n
score_col = "#7ed321" if score >= 80 else "#ff9f1a" if score >= 50 else "#ff2d6f"
 
st.markdown('<div style="height:10px"></div>', unsafe_allow_html=True)
 
# ================= ROW 1 =================
r1 = st.columns(4)
with r1[0]:
    card("Score de sécurité",
         donut([(score, score_col), (100 - score, "#20233a")] if have else [], score if have else "—", "sur 100", r=54, stroke=16)
         + legend([(SEV_LABEL[s], SEV_COLOR[s], sev_n[s]) for s in SEV]), "h1", "Global")
with r1[1]:
    top = per_file.most_common(10)
    card("Failles par fichier",
         metric(len(vulns), "failles détectées", "#ff2d6f") + metric(files_analyzed, "fichiers analysés", "#3b6bff")
         + '<div class="sc-sub">Répartition des failles sur les fichiers les plus touchés</div>'
         + area_chart([([n for _, n in top], "#3b6bff"), ([per_file_ch[p] for p, _ in top], "#ff2d6f")],
                      [os.path.basename(p) for p, _ in top]), "h1")
with r1[2]:
    card("Répartition par sévérité",
         metric(len(vulns), "détections", "#3b6bff")
         + donut([(sev_n[s], SEV_COLOR[s]) for s in SEV], len(vulns), "failles", r=58, stroke=9)
         + legend([(SEV_LABEL[s], SEV_COLOR[s], sev_n[s]) for s in SEV], cols=False)
         + table(["FICHIER", "TYPE", "SÉVÉRITÉ"], vuln_rows(vulns, 2)), "h1", "Détails")
with r1[3]:
    card("Patchs générés",
         metric(len(patches), "patchs proposés", "#ff2d6f") + metric(ok_n, "tests réussis", "#3b6bff")
         + donut([(ok_n, "#7ed321"), (ko_n, "#ff2d6f"), (wait_n, "#3b6bff")], len(patches), "patchs", r=58, stroke=9)
         + legend([("Vérifié", "#7ed321", ok_n), ("Échec", "#ff2d6f", ko_n), ("En attente", "#3b6bff", wait_n)], cols=False),
         "h1")
 
st.markdown('<div style="height:8px"></div>', unsafe_allow_html=True)
 
# ================= ROW 2 =================
r2 = st.columns(4)
with r2[0]:
    card("Vulnérabilités détectées", metric(len(vulns), "au total", "#3b6bff")
         + table(["FICHIER", "TYPE", "SÉVÉRITÉ"], vuln_rows(vulns, 6)), "h2", "Top 6")
with r2[1]:
    card("Patchs et tests", metric(len(patches), "patchs à vérifier", "#3b6bff")
         + table(["FICHIER", "PATCH", "TEST"],
                 [[base(v.get("file_path")), esc(str(v["patched_code"]).strip().split("\n")[0][:24]), test_cell(i)]
                  for i, v in patches[:6]]), "h2", "Sandbox")
with r2[2]:
    sec = [v for v in vulns if category(v) == "secrets"]
    card("Secrets exposés", metric(len(sec), "détections", "#3b6bff")
         + table(["FICHIER", "TYPE", "SÉVÉRITÉ"], vuln_rows(sec, 6)), "h2")
with r2[3]:
    inj = [v for v in vulns if category(v) == "injection"]
    card("Injections", metric(len(inj), "détections", "#3b6bff")
         + table(["FICHIER", "TYPE", "SÉVÉRITÉ"], vuln_rows(inj, 6)), "h2")
 
st.markdown('<div style="height:8px"></div>', unsafe_allow_html=True)
 
# ================= BOTTOM: action center =================
worst = per_file.most_common(1)[0][0] if per_file else "—"
left = (icon_row("◎", "#ff2d6f", len(vulns), "Failles trouvées") + icon_row("!", "#ff2d6f", sev_n["CRITICAL"], "Critiques")
        + icon_row("●", "#ff9f1a", sev_n["HIGH"], "Élevées") + icon_row("⊘", "#8b5cf6", sev_n["MEDIUM"], "Moyennes")
        + icon_row("✓", "#7ed321", sev_n["LOW"], "Faibles"))
mid = ('<div class="sc-m"><i style="background:#3b6bff;color:#3b6bff"></i><b>' + esc(os.path.basename(worst)) + '</b></div>'
       + table(["FICHIER", "FAILLES"], [[esc(os.path.basename(p)), n] for p, n in per_file.most_common(6)]))
alerts = metric(len(types), "types de vulnérabilités", "#ff2d6f") + alert_rows(types.most_common(6))
head = ('<div class="sc-ch" style="justify-content:flex-start;gap:28px"><span>Centre d’analyse et d’action</span>'
        f'<span class="sc-top"><span><i></i>Injections : {cats["injection"]}</span>'
        f'<span><i></i>Secrets : {cats["secrets"]}</span><span><i></i>Autres : {cats["other"]}</span></span></div>')
wide_card(head + f'<div class="sc-bottom"><div>{left}</div>{globe()}<div>{mid}</div><div>{alerts}</div></div>', "h3")
 
# ================= SUMMARY + EXPORTS =================
if have:
    st.markdown(f"**Résumé de l'audit :** {report.get('summary') or 'Aucun résumé retourné pour cet audit.'}")
    e1, e2, _ = st.columns([1.2, 1.2, 4])
    with e1:
        try:
            st.download_button("📄 Rapport PDF", create_pdf_report(report), "sentinelcode_audit.pdf", "application/pdf")
        except Exception as e:
            st.error(f"Impossible de générer le PDF : {str(e)}")
    with e2:
        st.download_button("💾 Données JSON", json.dumps(report, indent=2), "sentinelcode_audit.json", "application/json")
 
    st.subheader("🚨 Vulnérabilités détectées et patchs vérifiés")
    for i, v in enumerate(vulns):
        sev = v["severity"]
        badge = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🔵", "LOW": "🟢"}.get(sev, "⚪")
        path = v.get("file_path") or ""
        lang = LANG.get(os.path.splitext(path)[1].lower(), "python")
        with st.expander(f"{badge} [{sev}] {v.get('vulnerability_type')} — {path}"):
            st.write("**Explication :**", v.get("explanation"))
            a, b = st.columns(2)
            with a:
                st.caption("Code vulnérable")
                st.code(v.get("vulnerable_line"), language=lang)
            with b:
                st.caption("Patch sécurisé généré par l'IA")
                st.code(v.get("patched_code"), language=lang)
            st.markdown("---")
            st.markdown("**🧪 Test de vérification local**")
            unit_test_code = v.get("unit_test", "")
            st.code(unit_test_code, language="python")
            if st.button(f"▶️ Exécuter le test #{i + 1}", key=f"run_test_{i}"):
                with st.spinner("Exécution du test dans le sandbox..."):
                    results[i] = execute_verification_test(v.get("patched_code"), unit_test_code)
                st.rerun()  # refresh dashboard cards with the new test status
            res = results.get(i)
            if res:
                if res["passed"]:
                    st.success("✅ Test réussi : le patch fonctionne sans erreur d'exécution.")
                else:
                    st.error("❌ Test échoué ou exécution bloquée :")
                st.code(res["output"])