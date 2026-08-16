import streamlit as st
import json
import os

from core_agent import (
    extract_code_from_zip,
    analyze_repository,
    analyze_single_snippet,
    fetch_github_repo_zip,
    execute_verification_test
)
from pdf_generator import create_pdf_report

st.set_page_config(
    page_title="SentinelCode AI | Enterprise Security Auditor",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SentinelCode AI")
st.caption("Autonomous DevSecOps & Repository Vulnerability Patching Agent with Local Test Verification")

# Sidebar
st.sidebar.header("⚙️ System Status")
has_api_key = bool(os.environ.get("GEMINI_API_KEY"))
api_key_status = "🟢 Active" if has_api_key else "🔴 Missing GEMINI_API_KEY"
st.sidebar.info(f"Gemini API: {api_key_status}")
if not has_api_key:
    st.sidebar.warning("Configure GEMINI_API_KEY to enable audits.")

tab1, tab2, tab3 = st.tabs([" GitHub Repository URL", " Local ZIP File", " Code Snippet Scan"])

report_data = None

# Tab 1: GitHub URL Import
with tab1:
    st.write(" Analys the link GitHub ")
    repo_url = st.text_input("Enter Public GitHub URL:", placeholder="https://github.com/username/repository")

    if st.button("🚀 Fetch & Audit GitHub Repo", type="primary", key="btn_github", disabled=not has_api_key):
        if repo_url:
            try:
                with st.spinner("Downloading repository from GitHub..."):
                    zip_bytes = fetch_github_repo_zip(repo_url)
                    files_map = extract_code_from_zip(zip_bytes)
                    if not files_map:
                        st.warning("No supported source files found in this repository (or all were filtered by size limits).")
                    else:
                        st.success(f"Downloaded {len(files_map)} source code file(s).")

                        with st.spinner("Gemini is performing deep security analysis..."):
                            report_data = analyze_repository(files_map)
                            st.session_state['report'] = report_data
            except Exception as e:
                st.error(f"Error fetching repo: {str(e)}")
        else:
            st.warning("Please enter a valid GitHub URL.")

# Tab 2: Local ZIP
with tab2:
    st.write("رفع ملف ZIP محلي للمشروع البرمجي.")
    uploaded_file = st.file_uploader("Upload ZIP Repository", type=["zip"])
    if uploaded_file and st.button("🚀 Audit Local ZIP", type="primary", key="btn_zip", disabled=not has_api_key):
        with st.spinner("Processing archive & analyzing..."):
            try:
                files_map = extract_code_from_zip(uploaded_file.getvalue())
                if not files_map:
                    st.warning("No supported source files found in this archive (or all were filtered by size limits).")
                else:
                    report_data = analyze_repository(files_map)
                    st.session_state['report'] = report_data
            except Exception as e:
                st.error(f"Analysis failed: {str(e)}")

# Tab 3: Single Snippet
with tab3:
    snippet_code = st.text_area("Paste code snippet:", height=200, value="import os\n\ndef run_user_cmd(cmd):\n    os.system(cmd) # Shell Injection")
    if st.button("⚡ Quick Scan", type="primary", key="btn_snippet", disabled=not has_api_key):
        with st.spinner("Scanning snippet..."):
            try:
                report_data = analyze_single_snippet(snippet_code)
                st.session_state['report'] = report_data
            except Exception as e:
                st.error(f"Analysis failed: {str(e)}")

# Results Display
if 'report' in st.session_state and st.session_state['report']:
    report = st.session_state['report']
    st.divider()
    st.header("📊 Executive Security Dashboard")

    col1, col2, col3 = st.columns(3)
    score = report.get('overall_security_score', 0)
    col1.metric("Security Score", f"{score}/100")

    vulns = report.get('vulnerabilities', [])
    col2.metric("Total Vulnerabilities", len(vulns))
    col3.metric("Critical/High Severity", sum(1 for v in vulns if v.get('severity') in ['HIGH', 'CRITICAL']))

    st.markdown(f"*Audit Summary:* {report.get('summary') or 'No summary was returned for this audit.'}")

    # Export Actions
    c_pdf, c_json = st.columns(2)
    with c_pdf:
        try:
            st.download_button("📄 Download PDF Report", create_pdf_report(report), "sentinelcode_audit.pdf", "application/pdf")
        except Exception as e:
            st.error(f"Could not generate PDF report: {str(e)}")
    with c_json:
        st.download_button("💾 Download JSON Data", json.dumps(report, indent=2), "sentinelcode_audit.json", "application/json")

    st.subheader("🚨 Detected Vulnerabilities & Verified Patches")

    for i, v in enumerate(vulns):
        severity = v.get('severity', 'LOW')
        badge = "🔴" if severity in ['HIGH', 'CRITICAL'] else "🟡"

        with st.expander(f"{badge} [{severity}] {v.get('vulnerability_type')} — File: {v.get('file_path')}"):
            st.write("*Explanation:*", v.get('explanation'))

            c_code1, c_code2 = st.columns(2)
            with c_code1:
                st.caption("Vulnerable Code Block")
                st.code(v.get('vulnerable_line'), language="python")
            with c_code2:
                st.caption("AI-Generated Secure Patch")
                st.code(v.get('patched_code'), language="python")

            st.markdown("---")
            st.subheader("🧪 Local Automated Test Sandbox")
            st.caption("Generated code is statically screened and run under resource limits before you see the result.")

            unit_test_code = v.get('unit_test', '')
            st.code(unit_test_code, language="python")

            test_key = f"run_test_{i}_{report.get('total_files_analyzed', 0)}"
            if st.button(f"▶️ Execute Local Test Verification #{i+1}", key=test_key):
                with st.spinner("Executing Unit Test in temporary isolated Sandbox..."):
                    test_result = execute_verification_test(v.get('patched_code'), unit_test_code)

                    if test_result["passed"]:
                        st.success("✅ Test PASSED! The patch is verified and working without runtime errors.")
                        st.code(test_result["output"])
                    else:
                        st.error("❌ Test FAILED or Execution was blocked:")
                        st.code(test_result["output"])