# AWS Security Audit

A small, read-only Python tool that checks an AWS account against key controls from the CIS AWS Foundations Benchmark and produces a Markdown findings report.

I built it to audit my own AWS portfolio account (ECS, ALB, EC2, Elastic Beanstalk and S3 workloads) and to practise security automation with Python and boto3.

## What it checks

| CIS control | Check | Why it matters |
|---|---|---|
| 1.4 | No root access keys | Root keys can't be scoped down and are high value to an attacker |
| 1.5 | Root account MFA | Protects the most privileged identity |
| 1.10 | MFA for IAM console users | Stops password-only account takeover |
| 2.1.4 | S3 Block Public Access | Prevents accidental data exposure |
| 3.1 | CloudTrail multi-region logging | Without an audit trail there's nothing to investigate |
| 5.2 / 5.3 | No SSH/RDP open to 0.0.0.0/0 or ::/0 | Internet-exposed admin ports are a top attack vector |

## Usage

```bash
pip install -r requirements.txt
python audit.py --region us-east-1 --output report.md
```

The easiest place to run it is **AWS CloudShell**, which already has Python and boto3 installed.

Run it as an IAM user with the AWS managed **SecurityAudit** policy (read-only). The script never changes anything in the account.

It exits with code `1` if any check fails, so it can be used in a CI pipeline as a security gate.

## How it works

- Uses boto3 paginators so no IAM users or security groups are missed on accounts with many resources.
- Checks security group **port ranges**, not just exact ports, so a rule like `0-65535` is still caught, and checks both IPv4 and IPv6.
- Each check runs independently: if one check hits a permission error it is reported as `ERROR` and the rest still run.
- Results are sorted FAIL → ERROR → PASS so the most important findings are at the top.

## Findings from my account

Audits are run under a dedicated least-privilege IAM user (`SecurityAudit` policy only, no access keys).

**First scan:** 3 of 8 checks passed, 5 failed.

| CIS | Finding | Severity |
|---|---|---|
| 5.2 | SSH (port 22) open to 0.0.0.0/0 on a leftover Elastic Beanstalk security group | HIGH |
| 3.1 | No CloudTrail trail, so no audit logging of account activity | HIGH |
| 1.10 | IAM console user without MFA | HIGH |
| 2.1.4 | Two S3 buckets without Block Public Access | MEDIUM |

Root account checks (no access keys, MFA enabled) passed.

**Remediation:**
- Terminated the unused Elastic Beanstalk environment, removing the security group with SSH open to the internet (and its ongoing cost)
- Enabled MFA on the security-auditor IAM user
- Turned on all four S3 Block Public Access settings on both buckets

## Limitations

- The security group check covers one region per run (IAM and S3 are global).
- S3 is checked via Block Public Access settings only, not bucket policies or ACLs.

## Further Development Option

- Run across all regions
- Add checks for unencrypted EBS volumes and IAM access keys older than 90 days
- Schedule it with GitHub Actions or a Lambda + EventBridge rule
- Optional AI-generated remediation summary using Amazon Bedrock
