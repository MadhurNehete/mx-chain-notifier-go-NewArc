from fpdf import FPDF
from fpdf.enums import XPos, YPos

class AuditReport(FPDF):
    def header(self):
        if self.page_no() > 1:
            pass

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', '', 9)
        self.set_text_color(100)
        self.cell(0, 10, f'Page {self.page_no()} of 4', 0, 0, 'R')

    def section_title(self, label):
        self.set_font('helvetica', 'B', 14)
        self.set_text_color(0)
        self.cell(0, 8, label, 0, 1, 'L')
        self.ln(1)

    def finding_header(self, title, metadata, severity="High"):
        self.set_font('helvetica', 'B', 15)
        self.set_text_color(0)
        self.multi_cell(0, 8, title, 0, 'L')
        self.ln(1)
        self.set_font('helvetica', '', 10)
        self.multi_cell(0, 5, metadata)
        self.ln(2)

    def sub_heading(self, label):
        self.set_font('helvetica', 'B', 11)
        self.set_text_color(0)
        self.cell(0, 8, label, 0, 1, 'L')
        self.ln(0.5)

    def code_block(self, code):
        self.set_font('courier', '', 9)
        self.set_fill_color(248, 248, 248)
        self.set_text_color(50)
        self.multi_cell(0, 4.5, code, fill=True)
        self.ln(3)

    def standard_text(self, text):
        self.set_font('helvetica', '', 10.5)
        self.set_text_color(30)
        self.multi_cell(0, 5, text)
        self.ln(2)

    def remediation_block(self, text):
        self.set_font('helvetica', 'B', 10.5)
        self.set_text_color(0, 128, 0)  # Green for remediation
        self.multi_cell(0, 5, f"REMEDIATION: {text}")
        self.set_text_color(30)
        self.ln(2)

def generate_report():
    pdf = AuditReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 15, 15)
    
    # --- Page 1: Title + Executive Summary + Summary Table ---
    pdf.add_page()
    pdf.set_font('helvetica', 'B', 24)
    pdf.ln(10)
    pdf.cell(0, 15, 'SECURITY AUDIT REPORT', 0, 1, 'C')
    pdf.set_font('helvetica', 'B', 16)
    pdf.cell(0, 8, 'NewArc (Notifier) - Phase 2', 0, 1, 'C')
    pdf.ln(5)
    pdf.set_font('helvetica', '', 11)
    pdf.cell(0, 7, 'Repository: mx-chain-notifier-go-NewArc', 0, 1, 'C')
    
    pdf.ln(10)
    pdf.section_title('1. Executive Summary')
    pdf.standard_text(
        "A comprehensive security audit and remediation phase was conducted for the mx-chain-notifier-go repository. "
        "The audit focused on production-edge cases, data integrity, and resource management. "
        "Three (3) high-severity vulnerabilities were identified and have been successfully REMEDIATED."
    )
    pdf.standard_text(
        "The system is now hardened with a 'Fail-Closed' security policy, proxy-aware IP resolution, "
        "and global concurrency controls. All identified risks are now mitigated."
    )
    
    pdf.ln(5)
    pdf.sub_heading('Findings Summary')
    pdf.set_font('helvetica', 'B', 9)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(20, 8, 'ID', 1, 0, 'C', fill=True)
    pdf.cell(100, 8, 'Title', 1, 0, 'C', fill=True)
    pdf.cell(30, 8, 'Severity', 1, 0, 'C', fill=True)
    pdf.cell(30, 8, 'Status', 1, 1, 'C', fill=True)
    
    pdf.set_font('helvetica', '', 9)
    findings = [
        ("REAL-01", "Improper Rate Limiting Attribution", "High", "FIXED"),
        ("REAL-02", "Silent Event Processing Failures", "High", "FIXED"),
        ("REAL-03", "Unbounded Mutation Requests", "High", "FIXED"),
    ]
    for fid, title, sev, status in findings:
        pdf.cell(20, 8, fid, 1, 0, 'C')
        pdf.cell(100, 8, title, 1, 0, 'L')
        pdf.cell(30, 8, sev, 1, 0, 'C')
        pdf.set_text_color(0, 128, 0)
        pdf.cell(30, 8, status, 1, 1, 'C')
        pdf.set_text_color(30)

    # --- Page 2: Detailed Remediations (REAL-01 & REAL-02) ---
    pdf.add_page()
    pdf.section_title('2. Detailed Remediations')
    pdf.ln(2)
    
    pdf.finding_header(
        "REAL-01: Improper Rate Limiting Attribution (CWE-290)",
        "Component: WebSocket Processor / IP Resolution"
    )
    pdf.sub_heading('Vulnerability')
    pdf.standard_text(
        "The system relied on r.RemoteAddr, which reflects the proxy IP in production. "
        "This allowed per-IP rate limits to be triggered globally, enabling DoS via the shared proxy IP."
    )
    pdf.remediation_block(
        "Implemented 'X-Forwarded-For' header support with a 'TrustedProxies' whitelist. "
        "The system now correctly identifies the origin client IP behind trusted load balancers."
    )
    pdf.code_block(
        "// dispatcher/ws/wsHandler.go\n"
        "func (wh *websocketProcessor) remoteIPFromRequest(r *http.Request) string {\n"
        "    remoteAddrHost, _, _ := net.SplitHostPort(r.RemoteAddr)\n"
        "    if _, isTrusted := wh.trustedProxies[remoteAddrHost]; isTrusted {\n"
        "        return resolveXForwardedFor(r.Header.Get(\"X-Forwarded-For\"))\n"
        "    }\n"
        "    return remoteAddrHost\n"
        "}"
    )

    pdf.ln(4)
    pdf.finding_header(
        "REAL-02: Silent Event Processing Failures (CWE-754)",
        "Component: Event Pre-Processor / Pipeline Integrity"
    )
    pdf.sub_heading('Vulnerability')
    pdf.standard_text(
        "Critical Revert and Finalized block events used 'void' return types. Infrastructure failures "
        "(e.g., RabbitMQ queue saturation) were logged but not propagated, causing silent data loss."
    )
    pdf.remediation_block(
        "Enforced a 'Fail-Closed' policy. All internal interfaces (Publisher, Hub, Facade) now return errors. "
        "API endpoints respond with HTTP 500 on internal failure to trigger upstream retries."
    )
    pdf.code_block(
        "// api/groups/eventsGroup.go\n"
        "err := h.payloadHandler.ProcessPayload(data, topic, version)\n"
        "if err != nil {\n"
        "    shared.JSONResponse(c, http.StatusInternalServerError, nil, err.Error())\n"
        "    return\n"
        "}"
    )

    # --- Page 3: REAL-03 & Technical Details ---
    pdf.add_page()
    pdf.finding_header(
        "REAL-03: Unbounded Mutation Requests (CWE-770)",
        "Component: API Group / Resource Management"
    )
    pdf.sub_heading('Vulnerability')
    pdf.standard_text(
        "Mutation endpoints lacked concurrency controls, allowing an authenticated source to "
        "flood the notifier and cause resource exhaustion (CPU/Memory) or OOM crashes."
    )
    pdf.remediation_block(
        "Implemented a global concurrency semaphore (buffered channel) capped at 128 slots. "
        "Excessive concurrent mutation requests are throttled to ensure system stability."
    )
    pdf.code_block(
        "// api/groups/eventsGroup.go\n"
        "select {\n"
        "case h.concurrencySemaphore <- struct{}{}:\n"
        "    defer func() { <-h.concurrencySemaphore }()\n"
        "default:\n"
        "    shared.JSONResponse(c, http.StatusTooManyRequests, nil, \"too many concurrent requests\")\n"
        "    return\n"
        "}"
    )

    pdf.ln(10)
    pdf.section_title('3. Final Conclusion')
    pdf.standard_text(
        "The mx-chain-notifier-go system has been successfully hardened. The transition to an "
        "error-propagating architecture ensures that critical chain events are never silently "
        "dropped. With the addition of proxy-aware rate limiting and concurrency throttling, "
        "the service is now resilient to both infrastructure-level and application-level DoS vectors."
    )
    pdf.ln(5)
    pdf.set_font('helvetica', 'B', 11)
    pdf.set_text_color(0, 128, 0)
    pdf.cell(0, 10, 'Security Sign-off: APPROVED (All remediations verified)', 0, 1, 'L')

    pdf.output('SECURITY_AUDIT_REPORT_FINAL.pdf')

if __name__ == '__main__':
    generate_report()
