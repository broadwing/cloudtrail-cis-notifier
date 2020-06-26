import boto3
import json
import logging
import os
import zlib
import gzip
import time
import re

from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from pprint import pprint

# The Slack hook url to send events to
HOOK_URL = os.environ['hook_url']

# The Slack channel to send a message to stored in the slackChannel environment variable
SLACK_CHANNEL = os.environ['slack_channel']

# Account name to show on messages
ACCOUNT = os.environ['account']

# Cloudwatch logs search prefix
SEARCH_PREFIX= os.environ['search_prefix']

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# logger.info(HOOK_URL);
logger.info(SLACK_CHANNEL)

# Skipped Event Names
SKIP_EVENT_NAMES = ["CreateLogStream"]


def lambda_handler(event, context):

    if "awslogs" not in event or "data" not in event["awslogs"]:
        logger.info("Skipping - no records in event")
        logger.info("event: " + str(event))
        return

    ctevents = get_events(event)

    if len(ctevents) == 0:
        logger.info("Skipping - no events in data")
        return

    attachments = []
    skipped_events = 0
    for ctevent in ctevents:
        matchedRule = match_event(ctevent)
        if matchedRule:
            attachments.append(format_slack_attachment(ctevent, matchedRule))
        else:
            skipped_events += 1

    if (skipped_events):
        logger.info("Skipped " + str(skipped_events) + " events")

    if len(attachments) > 0 :
        slack_message = {
            "channel":  SLACK_CHANNEL,
            "attachments": attachments
        }

        req = Request(HOOK_URL, json.dumps(slack_message).encode('utf-8'))

        try:
            response = urlopen(req)
            response.read()
            logger.info("Message posted to %s with %i messages", slack_message['channel'], len(attachments))
        except HTTPError as e:
            logger.error("Request failed: %d %s", e.code, e.reason)
        except URLError as e:
            logger.error("Server connection failed: %s", e.reason)


def get_events(data):
    events = []
    decompressed_data = gzip.decompress(b64decode(data["awslogs"]["data"]))
    ctdata = json.loads(decompressed_data)

    for cteventdata in ctdata["logEvents"]:
        events.append(json.loads(cteventdata["message"]))

    return events

def match_event(event):
    try:
        # 3.1 Unauthorized API
        if "errorCode" in event and ("UnauthorizedOperation" in event["errorCode"] or "AccessDenied" in event["errorCode"]):
            return "3.1 Unauthorized API Call"
        # 3.2 Login with No MFA
        if event["eventName"] == "ConsoleLogin" and event["additionalEventData"]["MFAUsed"] != "Yes" and "errorMessage" not in event:
            return "3.2 Console Login without MFA"
        # 3.3 Root Account Used
        if event["userIdentity"]["type"] == "Root" and "invokedBy" not in event["userIdentity"] and event["eventType"] != "AwsServiceEvent":
            return "3.3 Root Account Used"
        # 3.4 Iam Policy Changed
        if event["eventName"] in ["DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy", "PutGroupPolicy", "PutRolePolicy", "PutUserPolicy", "CreatePolicy", "DeletePolicy", "CreatePolicyVersion", "DeletePolicyVersion", "AttachRolePolicy", "DetachRolePolicy", "AttachUserPolicy", "DetachUserPolicy", "AttachGroupPolicy", "DetachGroupPolicy"]:
            return "3.4 Iam Policy Changed"
        # 3.5 Cloudtrail Configuration Changed
        if event["eventName"] in ["CreateTrail", "UpdateTrail", "DeleteTrail", "StartLogging", "StopLogging"]:
            return "3.5 Cloudtrail Configuration Changed"
        # 3.5 Slack-notifier code changed
        if "UpdateFunctionCode" in event["eventName"] and "functionName" in event["responseElements"] and event["responseElements"]["functionName"] == "slack-notifier":
            return "3.5 Slack Notifier Lambda Code Changed"
        if event["eventSource"] == "logs.amazonaws.com" and event["eventName"] in ["PutSubscriptionFilter", "DeleteSubscriptionFilter", "DeleteLogGroup"] and "logGroupName" in event["requestParameters"] and event["requestParameters"]["logGroupName"] in ["/slack-notifier/cloudtrail", "/aws/lambda/slack-notifier"]:
            return "3.5 Slack Notifier Log Group or Subscription Filter Changed"
        # 3.6 Console Login Failure
        if event["eventName"] == "ConsoleLogin" and "errorMessage" in event and event["errorMessage"] == "Failed authentication":
            return "3.6 Console Login Failure - Failed Authentication"
        # 3.6 Console Login Failure
        if event["eventName"] == "ConsoleLogin" and "errorMessage" in event:
            return "3.6 Console Login Failure"
        # 3.7 Scheduled Deletion of CMK
        if event["eventSource"] == "kms.amazonaws.com" and event["eventName"] in ["DisableKey", "ScheduleKeyDeletion"]:
            return "3.7 Scheduled Deletion of CMK"
        # 3.8 S3 Bucket Policy Changed
        if event["eventSource"] == "s3.amazonaws.com" and event["eventName"] in ["PutBucketAcl", "PutBucketPolicy", "PutBucketCors", "PutBucketLifecycle", "PutBucketReplication", "DeleteBucketPolicy", "DeleteBucketCors", "DeleteBucketLifecycle", "DeleteBucketReplication"]:
            return "3.8 S3 Bucket Policy Changed"
        # 3.9 Config Service Changed
        if event["eventSource"] == "config.amazonaws.com" and event["eventName"] in ["StopConfigurationRecorder", "DeleteDeliveryChannel", "PutDeliveryChannel", "PutConfigurationRecorder"]:
            return "3.9 Config Service Changed"
        # 3.10 Security Group Changed
        if event["eventName"] in ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress", "CreateSecurityGroup", "DeleteSecurityGroup"]:
            return "3.10 Security Group Changed"
        # 3.11 Network ACL Changed
        if event["eventName"] in ["CreateNetworkAcl", "CreateNetworkAclEntry", "DeleteNetworkAcl", "DeleteNetworkAclEntry", "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation"]:
            return "3.11 Network ACL Changed"
        # 3.12 Network Gateway Changed
        if event["eventName"] in ["CreateCustomerGateway", "DeleteCustomerGateway", "AttachInternetGateway", "CreateInternetGateway", "DeleteInternetGateway", "DetachInternetGateway"]:
            return "3.12 Network Gateway Changed"
        # 3.13 Network Route Table Changed
        if event["eventName"] in ["CreateRoute", "CreateRouteTable", "ReplaceRoute", "ReplaceRouteTableAssociation", "DeleteRouteTable", "DeleteRoute", "DisassociateRouteTable"]:
            return "3.13 Network Route Table Changed"
        # 3.14 VPC Changed
        if event["eventName"] in ["CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "AcceptVpcPeeringConnection", "CreateVpcPeeringConnection", "DeleteVpcPeeringConnection", "RejectVpcPeeringConnection", "AttachClassicLinkVpc", "DetachClassicLinkVpc", "DisableVpcClassicLink", "EnableVpcClassicLink"]:
            return "3.14 VPC Changed"
        # 3.15 SNS Subscribers Changed
        if event["eventSource"] == "sns.amazonaws.com" and event["eventName"] in ["CreateTopic", "Subscribe", "Unsubscribe", "DeleteTopic"]:
            return "3.15 SNS Subscribers Changed"
    except Exception as e:
        logger.error(e)
        return "Match Error: " + e.message

    return False

def format_slack_attachment(event, matchedRule = ""):
    return {
        "fallback": slack_fallback_text(event),
        "color": slack_color(event),
        "author_name": slack_user(event) + " on Account: " + slack_account(event),
        "title": slack_event_title(event) ,
        "text": slack_event_text(event, matchedRule),
        "title_link": slack_event_link(event),
        "footer": slack_event_footer(event, matchedRule),
        "footer_icon": "https://a0.awsstatic.com/main/images/logos/aws_logo_smile_1200x630.png",
        "ts": slack_time(event)
    }

def slack_event_title(event):
    return event["eventName"] + " - " + event["eventSource"]

def slack_user(event):
    if 'userIdentity' not in event:
        return "Unknown User Identity"

    identity = event['userIdentity']

    if identity['type'] == 'IAMUser':
        return "User " + identity['userName']
    if identity['type'] == 'Root':
        return "ROOT Account"
    if identity['type'] == "AssumedRole":
        p = "Assumed Role by " + identity['sessionContext']['sessionIssuer']['type']
        if identity['sessionContext']['sessionIssuer']['type'] != "Root":
            p = p + " " + identity['sessionContext']['sessionIssuer']['userName']
        return p

    return identity['type']


def slack_event_text(event, matchedRule):
    return matchedRule + " - " +  event["eventType"]

def slack_event_footer(event, matchedRule):
    if len( event["userAgent"]) > 40:
        return  "Agent: " + event["userAgent"][:40] + "..."

    return  "Agent: " + event["userAgent"]

def slack_fallback_text(event):
    return "AWS Event " + slack_event_title(event) + " by " + slack_user(event)

def slack_color(event):
    if event["userIdentity"]["type"] == "root":
        return "#cc0000"

    # default will be gray
    return ""


def slack_time(event):
    return int(time.mktime(time.strptime(event["eventTime"], "%Y-%m-%dT%H:%M:%SZ")))

def slack_account(event):
    return ACCOUNT + ": " + event["recipientAccountId"]

def slack_event_link(event):
    return SEARCH_PREFIX + ";filter=%22" + event["eventID"] + "%22"
