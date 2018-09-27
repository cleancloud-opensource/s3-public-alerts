# Alerts about AWS S3 buckets or objects made public

This AWS Lambda function handler is part of the following AWS architecture to help users identifying S3 buckets or objects which were exposed publicly, causing customer data leaks in AWS cloud environments.

![aws architecture](https://github.com/cleancloud-opensource/s3-public-alerts/blob/master/aws_architecture.png)


## Important note

For object alerts it is required to enable an AWS CloudTrail trail to log data events for objects in an S3 bucket. *[How to here](https://docs.aws.amazon.com/AmazonS3/latest/user-guide/enable-cloudtrail-events.html)*
Additional charges apply for data events. *[Check pricing here](https://aws.amazon.com/pt/cloudtrail/pricing/)*


## Requirements

- CloudTrail enabled on AWS accounts. *[How to here](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-a-trail-using-the-console-first-time.html)*
- S3 bucket to receive CloudTrail logs. *[How to here](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html)*
- SNS topic to send notifications to subscribers. *[How to here](https://docs.aws.amazon.com/sns/latest/dg/CreateTopic.html)*
- Subscritpion to SNS topic to receive emails from. *[How to here](https://docs.aws.amazon.com/sns/latest/dg/SubscribeTopic.html)*
- IAM role with access permissions specified on following section. *[How to here](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_create.html)*


## IAM role

Create a policy with following permissions and associate this policy with an IAM role that will be used to setup Lambda function.

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "logs:CreateLogStream",
                "sns:Publish",
                "logs:CreateLogGroup",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
```


## Setup

- Create a Lambda function with following configuration: *[How to here](https://docs.aws.amazon.com/lambda/latest/dg/get-started-create-function.html)*
  - runtime: Python 2.7 
  - handler: **lambda_function.lambda_handler**
  - code: upload or copy and paste lambda_function.py
  - env variable: named as **sns_topic_arn** pointing to your SNS topic ARN
  - role: the IAM role created on previous section
  - trigger: from **S3 bucket where CloudTrail store logs** with event **s3:ObjectCreated:***

