import os
from flask import Flask, render_template_string, request
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime
import boto3

app = Flask(__name__)

FORM_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>CloudGuard NG - AWS Security Scanner</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: Arial, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; }
h1 { color: #58a6ff; margin-bottom: 8px; font-size: 2em; text-align: center; }
.tagline { color: #8b949e; margin-bottom: 30px; text-align: center; font-size: 0.95em; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 40px; width: 100%; max-width: 520px; }
label { display: block; color: #8b949e; font-size: 0.85em; margin-bottom: 6px; margin-top: 20px; }
input, select { width: 100%; padding: 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 0.95em; }
input:focus, select:focus { outline: none; border-color: #58a6ff; }
.btn { width: 100%; padding: 14px; background: #238636; color: white; border: none; border-radius: 6px; font-size: 1em; font-weight: bold; cursor: pointer; margin-top: 28px; }
.btn:hover { background: #2ea043; }
.safe-box { background: #0d1117; border: 1px solid #238636; border-radius: 8px; padding: 16px; margin-bottom: 20px; font-size: 0.85em; line-height: 1.8; color: #8b949e; }
.safe-box strong { color: #58a6ff; display: block; margin-bottom: 8px; font-size: 0.95em; }
.safe-box ol { padding-left: 18px; }
.safe-box ol li { margin-bottom: 4px; }
.safe-box .highlight { color: #e6edf3; font-weight: bold; }
.warning-box { background: #0d1117; border: 1px solid #f0883e; border-radius: 8px; padding: 14px; margin-bottom: 20px; font-size: 0.85em; color: #8b949e; line-height: 1.6; }
.warning-box strong { color: #f0883e; }
.divider { border: none; border-top: 1px solid #30363d; margin: 20px 0; }
.footer { margin-top: 30px; color: #8b949e; font-size: 0.8em; text-align: center; }
</style>
</head>
<body>
<h1>CloudGuard NG</h1>
<p class="tagline">AWS Security Misconfiguration Scanner — Built for African Startups</p>
<div class="card">

    <div class="safe-box">
        <strong>New here? Create a safe read-only test user first (2 minutes):</strong>
        <ol>
            <li>Go to <span class="highlight">AWS Console → IAM → Users → Create user</span></li>
            <li>Name it <span class="highlight">cloudguard-test</span></li>
            <li>Attach these 3 policies: <span class="highlight">SecurityAudit</span>, <span class="highlight">AmazonS3ReadOnlyAccess</span>, <span class="highlight">IAMReadOnlyAccess</span></li>
            <li>Go to <span class="highlight">Security credentials → Create access key</span></li>
            <li>Paste the keys below, scan, then <span class="highlight">delete the user</span> after</li>
        </ol>
    </div>

    <div class="warning-box">
        <strong>Your keys are safe.</strong> They are used only for this scan and are never stored or logged anywhere. For extra safety, use a read-only IAM user as described above.
    </div>

    <hr class="divider">

    <form method="POST" action="/scan">
        <label>AWS Access Key ID</label>
        <input type="text" name="access_key" placeholder="AKIAIOSFODNN7EXAMPLE" required />
        <label>AWS Secret Access Key</label>
        <input type="password" name="secret_key" placeholder="Your secret key" required />
        <label>AWS Region</label>
        <select name="region">
            <option value="us-east-1">US East (N. Virginia) — us-east-1</option>
            <option value="us-west-2">US West (Oregon) — us-west-2</option>
            <option value="eu-west-1">Europe (Ireland) — eu-west-1</option>
            <option value="eu-central-1">Europe (Frankfurt) — eu-central-1</option>
            <option value="ap-southeast-1">Asia Pacific (Singapore) — ap-southeast-1</option>
            <option value="af-south-1">Africa (Cape Town) — af-south-1</option>
        </select>
        <button type="submit" class="btn">Scan My AWS Account</button>
    </form>
</div>
<p class="footer">CloudGuard NG — Built for Nigerian and African cloud security | 3MTT Knowledge Showcase</p>
</body>
</html>
"""

RESULT_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>CloudGuard NG - Results</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: Arial, sans-serif; background: #0d1117; color: #e6edf3; padding: 20px; }
h1 { color: #58a6ff; text-align: center; margin-bottom: 8px; }
.subtitle { text-align: center; color: #8b949e; margin-bottom: 30px; }
.summary { display: flex; justify-content: center; gap: 16px; margin-bottom: 30px; flex-wrap: wrap; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 20px 30px; text-align: center; min-width: 120px; }
.card h2 { margin: 0; font-size: 2em; }
.card p { margin: 5px 0 0; color: #8b949e; font-size: 0.9em; }
.critical { color: #ff4444; }
.warning { color: #ffaa00; }
.ok { color: #00cc44; }
.total { color: #58a6ff; }
table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 10px; overflow: hidden; margin-bottom: 30px; }
th { background: #21262d; padding: 12px; text-align: left; color: #8b949e; font-size: 0.9em; }
td { padding: 12px; border-bottom: 1px solid #21262d; font-size: 0.85em; vertical-align: top; }
tr:hover { background: #1c2128; }
.btn { display: inline-block; padding: 12px 24px; background: #238636; color: white; border-radius: 6px; text-decoration: none; font-weight: bold; margin: 0 8px; }
.btn-back { background: #21262d; }
.btn-back:hover { background: #30363d; }
.btn:hover { background: #2ea043; }
.actions { text-align: center; margin-bottom: 30px; }
.footer { text-align: center; color: #8b949e; font-size: 0.8em; margin-top: 20px; }
.error-box { background: #161b22; border: 1px solid #ff4444; border-radius: 8px; padding: 20px; margin: 40px auto; max-width: 600px; text-align: center; color: #ff4444; }
</style>
</head>
<body>
<h1>CloudGuard NG</h1>
<p class="subtitle">AWS Security Report — Scanned: {{ now }}</p>
{% if error %}
<div class="error-box">
    <h2>Scan Failed</h2>
    <p style="margin-top:12px; color:#e6edf3;">{{ error }}</p>
    <a href="/" class="btn btn-back" style="display:inline-block; margin-top:20px;">Try Again</a>
</div>
{% else %}
<div class="summary">
    <div class="card"><h2 class="total">{{ total }}</h2><p>Total</p></div>
    <div class="card"><h2 class="critical">{{ critical }}</h2><p>Critical</p></div>
    <div class="card"><h2 class="warning">{{ warnings }}</h2><p>Warnings</p></div>
    <div class="card"><h2 class="ok">{{ ok }}</h2><p>Passed</p></div>
</div>
<div class="actions">
    <a href="/" class="btn btn-back">Scan Another Account</a>
</div>
<table>
<tr><th>Status</th><th>Service</th><th>Resource</th><th>Finding</th><th>Fix</th></tr>
{% for f in findings %}
<tr>
<td style="font-weight:bold; color:{% if f.status == 'CRITICAL' %}#ff4444{% elif f.status == 'WARNING' %}#ffaa00{% elif f.status == 'OK' %}#00cc44{% else %}#4488ff{% endif %}">{{ f.status }}</td>
<td>{{ f.service }}</td>
<td>{{ f.get("resource", "N/A") }}</td>
<td>{{ f.message }}</td>
<td>{{ f.fix }}</td>
</tr>
{% endfor %}
</table>
{% endif %}
<p class="footer">CloudGuard NG — Built for Nigerian and African cloud security | 3MTT Knowledge Showcase</p>
</body>
</html>
"""

def scan_s3(client):
    findings = []
    try:
        buckets = client.list_buckets().get("Buckets", [])
        if not buckets:
            return [{"service": "S3", "status": "INFO", "message": "No S3 buckets found", "fix": "None"}]
        for bucket in buckets:
            name = bucket["Name"]
            try:
                acl = client.get_bucket_acl(Bucket=name)
                is_public = any("AllUsers" in g.get("Grantee", {}).get("URI", "") for g in acl.get("Grants", []))
                if is_public:
                    findings.append({"service": "S3", "resource": name, "status": "CRITICAL", "message": f"Bucket '{name}' is PUBLICLY accessible!", "fix": "Enable Block all public access in S3 settings"})
                else:
                    findings.append({"service": "S3", "resource": name, "status": "OK", "message": f"Bucket '{name}' is private", "fix": "None needed"})
            except ClientError:
                findings.append({"service": "S3", "resource": name, "status": "WARNING", "message": f"Could not read ACL for '{name}'", "fix": "Check bucket permissions manually"})
    except ClientError as e:
        findings.append({"service": "S3", "status": "ERROR", "message": str(e), "fix": "Check IAM permissions"})
    return findings

def scan_iam(client):
    findings = []
    try:
        users = client.list_users().get("Users", [])
        if not users:
            return [{"service": "IAM", "status": "INFO", "message": "No IAM users found", "fix": "None"}]
        for user in users:
            username = user["UserName"]
            try:
                mfa = client.list_mfa_devices(UserName=username).get("MFADevices", [])
                if not mfa:
                    findings.append({"service": "IAM", "resource": username, "status": "WARNING", "message": f"User '{username}' has NO MFA enabled!", "fix": "Go to IAM > Users > Security credentials > Assign MFA device"})
                else:
                    findings.append({"service": "IAM", "resource": username, "status": "OK", "message": f"User '{username}' has MFA enabled", "fix": "None needed"})
            except ClientError:
                findings.append({"service": "IAM", "resource": username, "status": "WARNING", "message": f"Could not check MFA for '{username}'", "fix": "Check IAM permissions"})
    except ClientError as e:
        findings.append({"service": "IAM", "status": "ERROR", "message": str(e), "fix": "Check IAM permissions"})
    return findings

def scan_sg(client):
    findings = []
    try:
        sgs = client.describe_security_groups().get("SecurityGroups", [])
        for sg in sgs:
            sg_name = sg.get("GroupName", "Unknown")
            sg_id = sg.get("GroupId", "Unknown")
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 0)
                for ip in rule.get("IpRanges", []):
                    if ip.get("CidrIp") == "0.0.0.0/0":
                        if from_port in [22, 3389]:
                            findings.append({"service": "EC2 Security Group", "resource": f"{sg_name} ({sg_id})", "status": "CRITICAL", "message": f"Port {from_port} open to entire internet!", "fix": f"Restrict port {from_port} to your IP only in {sg_id}"})
                        else:
                            findings.append({"service": "EC2 Security Group", "resource": f"{sg_name} ({sg_id})", "status": "WARNING", "message": f"Port {from_port}-{to_port} open to internet", "fix": "Review if this port needs to be public"})
                    else:
                        findings.append({"service": "EC2 Security Group", "resource": f"{sg_name} ({sg_id})", "status": "OK", "message": f"Port {from_port} is restricted", "fix": "None needed"})
    except ClientError as e:
        findings.append({"service": "EC2 Security Group", "status": "ERROR", "message": str(e), "fix": "Check IAM permissions"})
    return findings

@app.route("/")
def index():
    return render_template_string(FORM_PAGE)

@app.route("/scan", methods=["POST"])
def scan():
    access_key = request.form.get("access_key", "").strip()
    secret_key = request.form.get("secret_key", "").strip()
    region = request.form.get("region", "us-east-1")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        s3_client = boto3.client("s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
        iam_client = boto3.client("iam", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
        ec2_client = boto3.client("ec2", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
        findings = []
        findings.extend(scan_s3(s3_client))
        findings.extend(scan_iam(iam_client))
        findings.extend(scan_sg(ec2_client))
        total = len(findings)
        critical = len([f for f in findings if f.get("status") == "CRITICAL"])
        warnings = len([f for f in findings if f.get("status") == "WARNING"])
        ok = len([f for f in findings if f.get("status") == "OK"])
        return render_template_string(RESULT_PAGE, findings=findings, total=total, critical=critical, warnings=warnings, ok=ok, now=now, error=None)
    except NoCredentialsError:
        return render_template_string(RESULT_PAGE, findings=[], total=0, critical=0, warnings=0, ok=0, now=now, error="Invalid AWS credentials. Please check your Access Key and Secret Key.")
    except ClientError as e:
        return render_template_string(RESULT_PAGE, findings=[], total=0, critical=0, warnings=0, ok=0, now=now, error=str(e))
    except Exception as e:
        return render_template_string(RESULT_PAGE, findings=[], total=0, critical=0, warnings=0, ok=0, now=now, error=f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
