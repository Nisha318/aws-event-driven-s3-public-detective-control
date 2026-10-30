# ---------- ENABLE CLOUDTRAIL ---------- 
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "trail_bucket" {
  bucket        = "s3-public-access-trail-bucket-${random_id.bucket_suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "trail_bucket_policy" {
  bucket = aws_s3_bucket.trail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.trail_bucket.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.trail_bucket.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "s3_trail" {
  name                          = "s3-public-access-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.bucket
  enable_logging                = true
  include_global_service_events = false
  is_multi_region_trail         = false
  depends_on                    = [aws_s3_bucket_policy.trail_bucket_policy]

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}

# ---------- CREATE SNS TOPIC AND SUBSCRIPTION ----------

resource "aws_sns_topic" "s3_public_alerts" {
  name = "s3-public-access-alerts"
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.s3_public_alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# ---------- CREATE IAM ROLE FOR LAMBDA ----------
resource "aws_iam_role" "lambda_role" {
  name = "s3-public-alert-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "s3-public-access-lambda-policy"
  description = "Lambda permissions to check S3 buckets and send SNS alerts"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:ListAllMyBuckets"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.s3_public_alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# ---------- CREATE THE LAMBDA FUNCTION ----------
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "lambda_function.py"
  output_path = "lambda_function.zip"
}

resource "aws_lambda_function" "s3_public_alert" {
  function_name = "s3-security-checker"
  runtime       = "python3.11"
  role          = aws_iam_role.lambda_role.arn
  handler       = "lambda_function.lambda_handler"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  timeout = 30

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.s3_public_alerts.arn
    }
  }
}

# ---------- CREATE EVENTBRIDGE RULE ----------
resource "aws_cloudwatch_event_rule" "s3_events_rule" {
  name        = "s3-public-access-rule"
  description = "Trigger Lambda for S3 bucket public access changes"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketPolicy",
        "PutBucketAcl",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.s3_events_rule.name
  target_id = "LambdaTarget"
  arn       = aws_lambda_function.s3_public_alert.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_public_alert.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_events_rule.arn
}




