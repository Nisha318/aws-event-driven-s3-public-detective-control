import json
import os

import boto3
from botocore.exceptions import ClientError
from dateutil import parser

s3 = boto3.client("s3")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
PUBLIC_GROUPS = [
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
]


def lambda_handler(event, context):
    detail = event["detail"]

    # ---- Extract Info ----
    bucket_name = detail["requestParameters"]["bucketName"]
    account_id = detail["userIdentity"]["accountId"]
    region = detail["awsRegion"]
    actor = detail["userIdentity"].get("arn", "Unknown")
    event_name = detail["eventName"]
    event_time = detail["eventTime"]
    readable_time = parser.isoparse(event_time).strftime("%Y-%m-%d %H:%M:%S UTC")
    findings = []
    check_errors = []

    # ---- Extract Human Name From ARN ----
    actor_name = actor.split("/")[-1] if "/" in actor else ""

    # ---- Check Public Access Block ----
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        config = pab["PublicAccessBlockConfiguration"]
        disabled = [name for name, enabled in config.items() if not enabled]
        if disabled:
            findings.append(
                f"Public Access Block is DISABLED or partially disabled ({', '.join(disabled)})"
            )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchPublicAccessBlockConfiguration":
            findings.append("No Public Access Block is configured on this bucket")
        else:
            check_errors.append(f"Public Access Block check failed ({code})")

    # ---- Check Bucket Policy Status ----
    try:
        policy_response = s3.get_bucket_policy_status(Bucket=bucket_name)
        if policy_response["PolicyStatus"]["IsPublic"]:
            findings.append("Bucket policy allows public access")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        # A bucket with no policy is a normal state, so it is not a finding
        if code != "NoSuchBucketPolicy":
            check_errors.append(f"Bucket policy check failed ({code})")

    # ---- Check Bucket ACL ----
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        if any(g.get("Grantee", {}).get("URI", "") in PUBLIC_GROUPS for g in acl["Grants"]):
            findings.append("Bucket ACL grants access to a public group")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        check_errors.append(f"Bucket ACL check failed ({code})")

    # ---- Decide Outcome ----
    all_findings = findings + [f"Evaluation incomplete: {err}" for err in check_errors]
    if findings:
        status = "NON_COMPLIANT"
    elif check_errors:
        status = "EVALUATION_ERROR"
    else:
        status = "COMPLIANT"

    # ---- Structured Audit Record ----
    print(json.dumps({
        "control": "s3-public-access-detective",
        "status": status,
        "bucket": bucket_name,
        "account_id": account_id,
        "region": region,
        "actor": actor,
        "event_name": event_name,
        "event_time": event_time,
        "findings": all_findings,
    }))

    # ---- SNS Alert ----
    if all_findings:
        findings_text = "\n".join([f"- {f}" for f in all_findings])
        message = f"""Hello {actor_name},
SECURITY ALERT: Public S3 Bucket Detected

WHAT HAPPENED?
A configuration change was made that may expose an S3 bucket to the public internet.

AFFECTED RESOURCE
Bucket Name: {bucket_name}
AWS Account ID: {account_id}
Region: {region}

WHO PERFORMED THIS ACTION?
Identity: {actor}

WHEN DID IT HAPPEN?
Time: {readable_time}

TRIGGER EVENT
Event Name: {event_name}

SECURITY FINDINGS
{findings_text}
"""
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Security Alert: Public S3 Bucket Detected",
            Message=message,
        )