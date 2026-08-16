import datetime
from fpdf import FPDF


class SecurityReportPDF(FPDF):

    def header(self):
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(20, 35, 60)
        self.cell(
            0,
            10,
            "SentinelCode AI - Executive Security Audit",
            border=False,
            new_x="LMARGIN",
            new_y="NEXT",
            align="L",
        )
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(100, 100, 100)
        self.cell(
            0,
            5,
            f'Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Powered by Gemini',
            border=False,
            new_x="LMARGIN",
            new_y="NEXT",
            align="L",
        )
        self.ln(3)
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), self.w - 10, self.get_y())
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")


def create_pdf_report(report_data: dict) -> bytes:
    pdf = SecurityReportPDF()
    pdf.set_margins(10, 10, 10)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    epw = pdf.epw

    # Overview Section
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, "1. Executive Summary", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(
        epw,
        5,
        f"Security Score: {report_data.get('overall_security_score', 'N/A')}/100",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.multi_cell(
        epw,
        5,
        f"Summary: {report_data.get('summary', 'No summary provided.')}",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(5)

    # Vulnerabilities Section
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, "2. Detailed Findings & Fixes", new_x="LMARGIN", new_y="NEXT")

    vulnerabilities = report_data.get("vulnerabilities", [])
    if not vulnerabilities:
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(
            epw,
            5,
            "No critical vulnerabilities detected.",
            new_x="LMARGIN",
            new_y="NEXT",
        )
    else:
        for idx, vuln in enumerate(vulnerabilities, 1):
            pdf.set_font("Helvetica", "B", 11)
            severity = str(vuln.get("severity", "UNKNOWN")).upper()

            if severity in ["HIGH", "CRITICAL"]:
                pdf.set_text_color(200, 30, 30)
            else:
                pdf.set_text_color(220, 130, 0)

            v_type = vuln.get("vulnerability_type", "Vulnerability")
            v_file = vuln.get("file_path", "Snippet")
            pdf.multi_cell(
                epw,
                6,
                f"[{severity}] #{idx} {v_type} in {v_file}",
                new_x="LMARGIN",
                new_y="NEXT",
            )

            pdf.set_text_color(40, 40, 40)
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(
                epw,
                5,
                f"Vulnerable Snippet:\n{vuln.get('vulnerable_line', 'N/A')}",
                new_x="LMARGIN",
                new_y="NEXT",
            )
            pdf.multi_cell(
                epw,
                5,
                f"Explanation: {vuln.get('explanation', 'N/A')}",
                new_x="LMARGIN",
                new_y="NEXT",
            )

            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(0, 100, 0)
            pdf.multi_cell(
                epw,
                5,
                f"Recommended Patch:\n{vuln.get('patched_code', 'N/A')}",
                new_x="LMARGIN",
                new_y="NEXT",
            )
            pdf.ln(4)

    return bytes(pdf.output())