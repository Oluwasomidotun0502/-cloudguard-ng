from datetime import datetime

def generate_report(findings):
    total = len(findings)
    critical = len([f for f in findings if f.get("status") == "CRITICAL"])
    warnings = len([f for f in findings if f.get("status") == "WARNING"])
    ok = len([f for f in findings if f.get("status") == "OK"])
    rows = ""
    for f in findings:
        status = f.get("status", "INFO")
        color = {"CRITICAL": "#ff4444", "WARNING": "#ffaa00", "OK": "#00cc44", "INFO": "#4488ff", "ERROR": "#ff4444"}.get(status, "#888")
        rows += f"<tr><td style=\"color:{color}; font-weight:bold;\">{status}</td><td>{f.get('service', '')}</td><td>{f.get('resource', 'N/A')}</td><td>{f.get('message', '')}</td><td>{f.get('fix', '')}</td></tr>"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"""<!DOCTYPE html>
<html>
<head>
<title>CloudGuard NG</title>
<style>
body {{font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:20px}}
h1 {{color:#58a6ff;text-align:center}}
.subtitle {{text-align:center;color:#8b949e;margin-bottom:30px}}
.summary {{display:flex;justify-content:center;gap:20px;margin-bottom:30px}}
.card {{background:#161b22;border-radius:10px;padding:20px 30px;text-align:center;min-width:120px}}
.card h2 {{margin:0;font-size:2em}}
.card p {{margin:5px 0 0;color:#8b949e}}
.critical {{color:#ff4444}}
.warning {{color:#ffaa00}}
.ok {{color:#00cc44}}
.total {{color:#58a6ff}}
table {{width:100%;border-collapse:collapse;background:#161b22;border-radius:10px}}
th {{background:#21262d;padding:12px;text-align:left;color:#8b949e}}
td {{padding:12px;border-bottom:1px solid #21262d;font-size:0.9em}}
tr:hover {{background:#1c2128}}
.footer {{text-align:center;margin-top:30px;color:#8b949e;font-size:0.85em}}
</style>
</head>
<body>
<h1>CloudGuard NG</h1>
<p class="subtitle">AWS Security Report - Generated: {now}</p>
<div class="summary">
<div class="card"><h2 class="total">{total}</h2><p>Total</p></div>
<div class="card"><h2 class="critical">{critical}</h2><p>Critical</p></div>
<div class="card"><h2 class="warning">{warnings}</h2><p>Warnings</p></div>
<div class="card"><h2 class="ok">{ok}</h2><p>Passed</p></div>
</div>
<table>
<tr><th>Status</th><th>Service</th><th>Resource</th><th>Finding</th><th>Fix</th></tr>
{rows}
</table>
<div class="footer">CloudGuard NG - Built for Nigerian and African cloud security | 3MTT Knowledge Showcase</div>
</body>
</html>"""
    filename = f"cloudguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, "w") as file:
        file.write(html)
    print(f"Report saved as: {filename}")
    return filename

if __name__ == "__main__":
    from scanner import run_all_scans
    findings = run_all_scans()
    generate_report(findings)
