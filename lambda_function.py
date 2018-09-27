# The MIT License (MIT)
#
# Copyright (c) 2018 CleanCloud
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# Lambda function handler to capture CloudTrail log events stored on S3 bucket
# in order to check for operations which expose publicly S3 buckets or objects.
#
# In case such operations were identified the SNS topic registered via Lambda
# variable is notified.
#

from __future__ import print_function

import json, boto3, os
from io import BytesIO
from gzip import GzipFile


sns_topic_arn = os.environ['sns_topic_arn']
sns_subject = 'Public S3 bucket/object alert'
sns_message = 'User {{user}} via {{invoke}} call has just {{bucket_or_object}} with {{operations}} public access'


def lambda_handler(event, context):
    for items in event['Records']:
        bucket = items['s3']['bucket']['name']
        key = items['s3']['object']['key']

    print('S3 bucket [' + bucket + '] object event for [' + key + ']')

    s3_client = boto3.client('s3')
    trail_json = load_json(s3_client.get_object(Bucket=bucket, Key=key))

    if 'Records' in trail_json:
        for record in trail_json['Records']:
            if record['eventSource'] == 's3.amazonaws.com' and 'requestParameters' in record:
                event_name = record['eventName']
                if event_name == 'CreateBucket' or event_name == 'PutObject':
                    handle_create(record, event_name)
                elif event_name == 'PutBucketAcl' or event_name == 'PutObjectAcl':
                    handle_change(record, event_name)


def load_json(trail_log):
    log_stream = BytesIO(trail_log['Body'].read())
    return json.loads(GzipFile(None, 'rb', fileobj=log_stream).read())


def handle_create(record, event_name):
    public_read = False
    public_write = False

    if 'x-amz-acl' in record['requestParameters']:
        acl_headers = record['requestParameters']['x-amz-acl']
        if not isinstance(acl_headers, list):
            acl_headers = [acl_headers]

        for acl_header in acl_headers:
            if acl_header == 'public-read' or acl_header == 'public-read-write':
                public_read = True
            if acl_header == 'public-read-write':
                public_write = True

    if 'accessControlList' in record['requestParameters']:
        if 'x-amz-grant-read' in record['requestParameters']['accessControlList'] \
                and '/global/AllUsers' in record['requestParameters']['accessControlList']['x-amz-grant-read']:
            public_read = True
        if 'x-amz-grant-read-acp' in record['requestParameters']['accessControlList'] \
                and '/global/AllUsers' in record['requestParameters']['accessControlList']['x-amz-grant-read-acp']:
            public_read = True
        if 'x-amz-grant-write' in record['requestParameters']['accessControlList'] \
                and '/global/AllUsers' in record['requestParameters']['accessControlList']['x-amz-grant-write']:
            public_write = True
        if 'x-amz-grant-write-acp' in record['requestParameters']['accessControlList'] \
                and '/global/AllUsers' in record['requestParameters']['accessControlList']['x-amz-grant-write-acp']:
            public_write = True

    if public_read == True or public_write == True:
        publish_alert(record, event_name, public_write, public_read)


def handle_change(record, event_name):
    public_read = False
    public_write = False

    if 'AccessControlPolicy' in record['requestParameters']:
        grant_list = record['requestParameters']['AccessControlPolicy']['AccessControlList']['Grant']
        if not isinstance(grant_list, list):
            grant_list = [grant_list]

        for grantee in grant_list:
            if 'Grantee' in grantee:
                if 'URI' in grantee['Grantee'] and '/global/AllUsers' in grantee['Grantee']['URI']:
                    if grantee['Permission'] == 'READ' or grantee['Permission'] == 'READ_ACP':
                        public_read = True
                    elif grantee['Permission'] == 'WRITE' or grantee['Permission'] == 'WRITE_ACP':
                        public_write = True

    if public_read == True or public_write == True:
        publish_alert(record, event_name, public_write, public_read)


def publish_alert(record, event_name, public_write, public_read):
    user_name = record['userIdentity']['userName']
    invoke_form = get_invoke_form(record)
    bucket_name = record['requestParameters']['bucketName']
    object_arn = get_object_arn(record)

    print('Found public S3 event [' + event_name + '] on record [' + str(record) + ']')

    pub_message = sns_message \
        .replace('{{user}}', user_name) \
        .replace('{{invoke}}', invoke_form) \
        .replace('{{operations}}', get_public_access(public_write, public_read)) \
        .replace('{{bucket_or_object}}', get_resource_access(event_name, bucket_name, object_arn))

    print('Alert [' + pub_message + '] sent to SNS topic [' + sns_topic_arn + ']')

    sns_client = boto3.client('sns')
    sns_client.publish(
        TopicArn=sns_topic_arn,
        Subject=sns_subject,
        Message=pub_message
    )


def get_object_arn(record):
    if 'resources' in record:
        for resource in record['resources']:
            if resource['type'] == 'AWS::S3::Object':
                return resource['ARN']
    return None


def get_invoke_form(record):
    if record['userAgent'] == 'signin.amazonaws.com' or record['userAgent'] == 'console.amazonaws.com':
        return 'Console'
    elif record['userAgent'] == 'lambda.amazonaws.com':
        return 'Lambda'
    else:
        return 'API'


def get_public_access(public_write, public_read):
    messages = []
    if public_read:
        messages.append('READ')
    if public_write:
        messages.append('WRITE')
    return ' and '.join(messages)


def get_resource_access(event_name, bucket_name, object_arn):
    messages = []
    if event_name == 'CreateBucket' or event_name == 'PutObject':
        messages.append('created')
    else:
        messages.append('changed')

    if object_arn is not None:
        messages.append(object_arn)
        messages.append('at bucket')
        messages.append(bucket_name)
    else:
        messages.append('bucket')
        messages.append(bucket_name)

    return ' '.join(messages)