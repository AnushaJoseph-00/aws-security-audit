#!/usr/bin/env python3
"""
AWS Security Audit - a small, read-only checker mapped to the
CIS AWS Foundations Benchmark (v3.0).

Checks:
  CIS 1.4  - No root account access keys
  CIS 1.5  - MFA enabled on the root account
  CIS 1.10 - MFA enabled for IAM users with console passwords
  CIS 2.1.4 - S3 buckets have Block Public Access fully enabled
  CIS 3.1  - CloudTrail is enabled, logging, and multi-region
  CIS 5.2/5.3 - No security group allows 0.0.0.0/0 or ::/0 to SSH (22) / RDP (3389)

Usage:
  python audit.py --region us-east-1
  python audit.py --region us-east-1 --output report.md

Needs read-only credentials (the AWS managed policy "SecurityAudit" is enough).
"""

import argparse
import datetime
import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}


def finding(cis_id, title, status, severity, detail):
    return {
        "cis": cis_id,
        "title": title,
        "status": status,  # PASS / FAIL / ERROR
        "severity": severity,  # HIGH / MEDIUM / LOW
        "detail": detail,
    }


# ---------- IAM ----------

def check_root(iam):
    results = []
    summary = iam.get_account_summary()["SummaryMap"]

    keys = summary.get("AccountAccessKeysPresent", 0)
    results.append(finding(
        "1.4", "No root account access keys",
        "PASS" if keys == 0 else "FAIL", "HIGH",
        "Root has no access keys." if keys == 0 else "Root account has access keys - delete them.",
    ))

    mfa = summary.get("AccountMFAEnabled", 0)
    results.append(finding(
        "1.5", "MFA enabled on root account",
        "PASS" if mfa == 1 else "FAIL", "HIGH",
        "Root MFA is enabled." if mfa == 1 else "Root account has no MFA.",
    ))
    return results


def check_user_mfa(iam):
    no_mfa = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            name = user["UserName"]
            try:
                iam.get_login_profile(UserName=name)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    continue  # no console password, CIS 1.10 doesn't apply
                raise
            if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                no_mfa.append(name)

    if no_mfa:
        return [finding("1.10", "MFA for IAM users with console access", "FAIL", "HIGH",
                        "Users without MFA: " + ", ".join(no_mfa))]
    return [finding("1.10", "MFA for IAM users with console access", "PASS", "HIGH",
                    "All console users have MFA.")]


# ---------- S3 ----------

def check_s3(s3):
    results = []
    buckets = s3.list_buckets().get("Buckets", [])
    if not buckets:
        return [finding("2.1.4", "S3 Block Public Access", "PASS", "MEDIUM", "No buckets found.")]

    for b in buckets:
        name = b["Name"]
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if all(cfg.values()):
                results.append(finding("2.1.4", f"S3 Block Public Access: {name}", "PASS", "MEDIUM",
                                       "All four Block Public Access settings are on."))
            else:
                off = [k for k, v in cfg.items() if not v]
                results.append(finding("2.1.4", f"S3 Block Public Access: {name}", "FAIL", "MEDIUM",
                                       "Settings off: " + ", ".join(off)))
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                results.append(finding("2.1.4", f"S3 Block Public Access: {name}", "FAIL", "MEDIUM",
                                       "No Block Public Access configuration on this bucket."))
            else:
                results.append(finding("2.1.4", f"S3 Block Public Access: {name}", "ERROR", "MEDIUM", code))
    return results


# ---------- CloudTrail ----------

def check_cloudtrail(ct):
    trails = ct.describe_trails()["trailList"]
    for t in trails:
        if t.get("IsMultiRegionTrail"):
            status = ct.get_trail_status(Name=t["TrailARN"])
            if status.get("IsLogging"):
                return [finding("3.1", "CloudTrail multi-region trail logging", "PASS", "HIGH",
                                f"Trail '{t['Name']}' is multi-region and logging.")]
    detail = "No trails found." if not trails else "No multi-region trail is currently logging."
    return [finding("3.1", "CloudTrail multi-region trail logging", "FAIL", "HIGH", detail)]


# ---------- Security groups ----------

def rule_hits_admin_port(perm):
    proto = perm.get("IpProtocol")
    if proto == "-1":  # all traffic
        return list(ADMIN_PORTS)
    if proto != "tcp":
        return []
    lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
    return [p for p in ADMIN_PORTS if lo <= p <= hi]


def check_security_groups(ec2):
    exposed = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            for perm in sg.get("IpPermissions", []):
                open_world = (
                    any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                    or any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
                )
                if not open_world:
                    continue
                for port in rule_hits_admin_port(perm):
                    exposed.append(f"{sg['GroupId']} ({sg.get('GroupName', '')}) - {ADMIN_PORTS[port]}/{port}")

    if exposed:
        return [finding("5.2/5.3", "No admin ports open to the internet", "FAIL", "HIGH",
                        "Open to the world: " + "; ".join(sorted(set(exposed))))]
    return [finding("5.2/5.3", "No admin ports open to the internet", "PASS", "HIGH",
                    "No security groups expose SSH/RDP to 0.0.0.0/0 or ::/0.")]


# ---------- Report ----------

def run_check(name, func, *args):
    try:
        return func(*args)
    except ClientError as e:
        return [finding("-", name, "ERROR", "-", e.response["Error"]["Code"])]


def to_markdown(results, account, region):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    fails = [r for r in results if r["status"] == "FAIL"]
    lines = [
        "# AWS Security Audit Report",
        "",
        f"- **Account:** {account}",
        f"- **Region (security groups):** {region}",
        f"- **Run at:** {now}",
        f"- **Result:** {len(results) - len(fails)} passed, {len(fails)} failed",
        "",
        "| CIS | Check | Status | Severity | Detail |",
        "|---|---|---|---|---|",
    ]
    order = {"FAIL": 0, "ERROR": 1, "PASS": 2}
    for r in sorted(results, key=lambda r: order.get(r["status"], 3)):
        lines.append(f"| {r['cis']} | {r['title']} | {r['status']} | {r['severity']} | {r['detail']} |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Read-only AWS security audit (CIS-mapped).")
    parser.add_argument("--region", default="us-east-1", help="Region for the security group check")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--output", help="Write the Markdown report to this file")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    try:
        account = session.client("sts").get_caller_identity()["Account"]
    except NoCredentialsError:
        sys.exit("No AWS credentials found. Run 'aws configure' first.")

    iam = session.client("iam")
    results = []
    results += run_check("Root account", check_root, iam)
    results += run_check("IAM user MFA", check_user_mfa, iam)
    results += run_check("S3 public access", check_s3, session.client("s3"))
    results += run_check("CloudTrail", check_cloudtrail, session.client("cloudtrail"))
    results += run_check("Security groups", check_security_groups, session.client("ec2"))

    report = to_markdown(results, account, args.region)
    print(report)
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"Report saved to {args.output}")

    # Non-zero exit if anything failed, so it can gate a CI pipeline later
    sys.exit(1 if any(r["status"] == "FAIL" for r in results) else 0)


if __name__ == "__main__":
    main()
