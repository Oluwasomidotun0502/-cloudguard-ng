import boto3
from botocore.exceptions import ClientError

def scan_s3_buckets():
    findings = []
    s3 = boto3.client('s3')
    try:
        buckets = s3.list_buckets().get('Buckets', [])
        if not buckets:
            return [{"service": "S3", "status": "INFO", "message": "No S3 buckets found", "fix": "None"}]
        for bucket in buckets:
            name = bucket['Name']
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if 'AllUsers' in grantee.get('URI', ''):
                        findings.append({"service": "S3", "resource": name, "status": "CRITICAL", "message": f"Bucket '{name}' is PUBLICLY accessible!", "fix": "Enable Block all public access in S3 settings"})
                    else:
                        findings.append({"service": "S3", "resource": name, "status": "OK", "message": f"Bucket '{name}' is private", "fix": "None needed"})
            except ClientError:
                findings.append({"service": "S3", "resource": name, "status": "WARNING", "message": f"Could not read ACL for '{name}'", "fix": "Check bucket permissions manually"})
    except ClientError as e:
        findings.append({"service": "S3", "status": "ERROR", "message": str(e), "fix": "Check IAM permissions"})
    return findings

def scan_iam_users():
    findings = []
    iam = boto3.client('iam')
    try:
        users = iam.list_users().get('Users', [])
        if not users:
            return [{"service": "IAM", "status": "INFO", "message": "No IAM users found", "fix": "None"}]
        for user in users:
            username = user['UserName']
            try:
                mfa_devices = iam.list_mfa_devices(UserName=username)
                if not mfa_devices.get('MFADevices'):
                    findings.append({"service": "IAM", "resource": username, "status": "WARNING", "message": f"User '{username}' has NO MFA enabled!", "fix": "Go to IAM > Users > Security credentials > Assign MFA device"})
                else:
                    findings.append({"service": "IAM", "resource": username, "status": "OK", "message": f"User '{username}' has MFA enabled", "fix": "None needed"})
            except ClientError:
                findings.append({"service": "IAM", "resource": username, "status": "WARNING", "message": f"Could not check MFA for '{username}'", "fix": "Check IAM permissions"})
    except ClientError as e:
        findings.append({"service": "IAM", "status": "ERROR", "message": str(e), "fix": "Check IAM permissions"})
    return findings

def scan_security_groups():
    findings = []
    ec2 = boto3.client('ec2', region_name='us-east-1')
    try:
        sgs = ec2.describe_security_groups().get('SecurityGroups', [])
        for sg in sgs:
            sg_name = sg.get('GroupName', 'Unknown')
            sg_id = sg.get('GroupId', 'Unknown')
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 0)
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        if from_port in [22, 3389]:
                            findings.append({"service": "EC2 Security Group", "resource": f"{sg_name} ({sg_id})", "status": "CRITICAL", "message": f"Port {from_port} open to entire internet!", "fix": f"Restrict port {from_port} to your IP only in Security Group {sg_id}"})
                        else:
                            findings.append({"service": "EC2 Security Group", "resource": f"{sg_name} ({sg_id})", "status": "WARNING", "message": f"Port {from_port}-{to_port} open to internet", "fix": "Review if this port needs to be public"})
                    else:
                        findings.append({"service": "EC2 Security Group", "resource": f"{sg_name} ({sg_id})", "status": "OK", "message": f"Port {from_port} is restricted", "fix": "None needed"})
    except ClientError as e:
        findings.append({"service": "EC2 Security Group", "status": "ERROR", "message": str(e), "fix": "Check IAM permissions"})
    return findings

def run_all_scans():
    print("CloudGuard NG - Starting security scan...")
    print("=" * 50)
    all_findings = []
    print("Scanning S3 Buckets...")
    all_findings.extend(scan_s3_buckets())
    print("Scanning IAM Users...")
    all_findings.extend(scan_iam_users())
    print("Scanning Security Groups...")
    all_findings.extend(scan_security_groups())
    print("=" * 50)
    print(f"Scan complete! Found {len(all_findings)} findings.")
    return all_findings

if __name__ == "__main__":
    results = run_all_scans()
    for r in results:
        status = r.get('status', 'INFO')
        message = r.get('message', '')
        fix = r.get('fix', '')
        print(f"[{status}] {message}")
        if status in ['CRITICAL', 'WARNING']:
            print(f"  Fix: {fix}")
