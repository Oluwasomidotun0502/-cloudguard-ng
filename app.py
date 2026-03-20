from flask import Flask, render_template_string
from scanner import run_all_scans
from datetime import datetime

app = Flask(__name__)

@app.route("/")
def index():
    findings = run_all_scans()
    total = len(findings)
    critical = len([f for f in findings if f.get("status") == "CRITICAL"])
    warnings = len([f for f in findings if f.get("status") == "WARNING"])
    ok = len([f for f in findings if f.get("status") == "OK"])
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
<title>CloudGuard NG</title>
<meta http-equiv="refresh" content="300">
<style>
body{font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:20px}
h1{color:#58a6ff;text-align:center}
.subtitle{text-align:center;color:#8b949e;margin-bottom:30px}
.summary{display:flex;justify-content:center;gap:20px;margin-bottom:30px;flex-wrap:wrap}
.card{background:#161b22;border-radius:10px;padding:20px 30px;text-align:center;min-width:120px}
.card h2{margin:0;font-size:2em}
.card p{margin:5px 0 0;color:#8b949e}
.critical{color:#ff4444}
.warning{color:#ffaa00}
.ok{color:#00cc44}
.total{color:#58a6ff}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:10px}
th{background:#21262d;padding:12px;text-align:left;color:#8b949e}
td{padding:12px;border-bottom:1px solid #21262d;font-size:0.9em}
tr:hover{background:#1c2128}
.btn{display:block;width:200px;margin:20px auto;padding:12px;background:#238636;color:white;text-align:center;border-radius:6px;text-decoration:none;font-weight:bold;cursor:pointer;border:none;font-size:1em}
.btn:hover{background:#2ea043}
.footer{text-align:center;margin-top:30px;color:#8b949e;font-size:0.85em}
</style>
</head>
<body>
<h1>CloudGuard NG</h1>
<p class="subtitle">AWS Security Report - Last scanned: {{ now }}</p>
<div class="summary">
<div class="card"><h2 class="total">{{ total }}</h2><p>Total</p></div>
<div class="card"><h2 class="critical">{{ critical }}</h2><p>Critical</p></div>
<div class="card"><h2 class="warning">{{ warnings }}</h2><p>Warnings</p></div>
<div class="card"><h2 class="ok">{{ ok }}</h2><p>Passed</p></div>
</div>
<a href="/" class="btn">Run New Scan</a>
<table>
<tr><th>Status</th><th>Service</th><th>Resource</th><th>Finding</th><th>Fix</th></tr>
{% for f in findings %}
<tr>
<td style="font-weight:bold;color:{% if f.status == 'CRITICAL' %}#ff4444{% elif f.status == 'WARNING' %}#ffaa00{% elif f.status == 'OK' %}#00cc44{% else %}#4488ff{% endif %}">{{ f.status }}</td>
<td>{{ f.service }}</td>
<td>{{ f.get("resource", "N/A") }}</td>
<td>{{ f.message }}</td>
<td>{{ f.fix }}</td>
</tr>
{% endfor %}
</table>
<div class="footer">CloudGuard NG - Built for Nigerian and African cloud security | 3MTT Knowledge Showcase</div>
</body>
</html>
""", findings=findings, total=total, critical=critical, warnings=warnings, ok=ok, now=now)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
