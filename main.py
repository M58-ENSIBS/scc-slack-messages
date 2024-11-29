import json
import os
import requests
import pprint
import base64
import re

from google.cloud import logging
from google.cloud import secretmanager


def message_post(data):
    """Function to post a message to Slack channel.

    Args:
        data (dict): The payload data to be posted to Slack.

    Raises:
        ValueError: If the request to Slack returns an error.
    """
    # pprint.pprint(payload)
    token = get_secret("slack-handler-token")
    channel_id = "G01JQJDBMUK" #cloud-platform-private
    payload = data if type(data) is dict else json.loads(data)

    url = 'https://slack.com/api/chat.postMessage'
    headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json; charset=utf-8'
    }
    try:
        with open("finding-detail.json", "rt") as block_f:
            block_template = json.load(block_f)
        # template_content
        merge_template(block_template, payload)

        params = {
            "channel": channel_id,
            "blocks": block_template,
            "text": "Alternate content from block content",
            "unfurl_links": "false"
        }
        print(params)
        r = requests.post(url, data=json.dumps(params), headers=headers)
        if r.status_code != 200:
            raise ValueError(f"Request to Slack returned error \
                {r.status_code}. Response is: {r.text}")
        print(r.text)

    except Exception as e:
        print(f"Error occurred attempting to post message. Error is: {e}")

def strip_quotes(val):
    """Function to strip quotes from a string.

    Args:
        val (str): The string to strip quotes from.

    Returns:
        str: The string without quotes.
    """
    if val.startswith('"') and val.endswith('"'):
        return val[1:-1]
    return val


def merge_template(list_data, payload):
    """Function to merge the template content with the payload data.

    Args:
        list_data (list): The list of blocks to merge with the payload.
        payload (dict): The payload data to merge with the template.
    """
    finding = payload.get("finding")
    resource = payload.get("resource")
    source = payload.get("sourceProperties")

    org_id = finding.get("name").split("/")[1]
    finding_id = finding.get("name").split("/")[-1]
    source_id = finding.get("name").split("/")[3]
    severity = finding.get("severity")
    if finding.get("category") == "Persistence: IAM Anomalous Grant" or finding.get("category") == "Persistence: Service Account Key Created" or finding.get("category") == "Persistence: New Geography":
        project_path = finding.get("logEntries")[0].get("cloudLoggingEntry").get("resourceContainer").replace("projects/", "")
    elif finding.get("category") == "Reverse Shell":
        project_path = finding.get("processes")[0].get("envVariables")[2].get("val")
    else:
        project_path = "Unknown"

    sev_emo = ":warning:" if "HIGH" in severity else ""
    sev_emo = ":exclamation:" if "CRITICAL" in severity else sev_emo

    url = "https://console.cloud.google.com/security/command-center/findings"
    url += f"?organizations/{org_id}/sources/{source_id}/"
    url += f"findings/{finding_id}=,true&orgonly=true"
    url += f"&organizationId={org_id}&supportedpurview=organizationId"
    url += "&view_type=vt_finding_type&vt_finding_type=All"
    url += f"&resourceId=organizations/{org_id}/sources/{source_id}/"
    url += f"findings/{finding_id}"
    pprint.pprint(url)

    list_data[0]["text"]["text"] = list_data[0]["text"]["text"] \
        .replace("<SUBJECT>", finding.get("category")) \
        .replace("<WEB_LINK>", url)

    list_data[1]["text"]["text"] = list_data[1]["text"]["text"] \
        .replace("<PROJECT_ID>", project_path) \
        .replace("<SEVERITY>", severity) \
        .replace("<SEV_EMO>", sev_emo) \
        .replace("<STATE>", finding.get("state")) \
        .replace("<TIMESTAMP>", finding.get("createTime"))

    list_data[1]["accessory"]["url"] = list_data[1]["accessory"]["url"] \
        .replace("<WEB_LINK>", url)

    if finding.get("category") == "Persistence: IAM Anomalous Grant":
        binding = finding.get("iamBindings")[0]
        grantee = binding.get("member")
        permission_added = binding.get("role")
        grantor = finding.get("access").get("principalEmail")

        # Initialize variables for the temporary grant check
        sensitive_role_grant = source.get("properties").get("sensitiveRoleGrant", {})
        binding_deltas = sensitive_role_grant.get("bindingDeltas", [{}])
        condition = binding_deltas[0].get("condition", {})

        # Check if it is a temporary grant
        if "Created by iam-temporary, please do not edit/remove manually." in condition.get("description", ""):
            requested_time = condition.get("expression", "").split('timestamp("')[1].split('")')[0].replace("Z", "").replace("T", " ")
            expires_text = f"Expires: {requested_time}"

            # Add requested time section
            list_data.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*:hourglass: IAM-Temporary Requested Time:*\n{expires_text}"
                }
            })

        # Add the classic structure for all grants
        list_data.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Grantor:*\n{grantor}"
            }
        })
        list_data.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Grantee:*\n{grantee}"
            }
        })
        list_data.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Permission Added:*\n{permission_added}"
            }
        })

        # Add a divider to separate entries
        list_data.append({
            "type": "divider"
        })


        list_data[-4]["text"]["text"] = list_data[-4]["text"]["text"] \
            .replace("<GIVER>", strip_quotes(grantor))
        list_data[-3]["text"]["text"] = list_data[-3]["text"]["text"] \
            .replace("<GRANTEE>", strip_quotes(grantee))
        list_data[-2]["text"]["text"] = list_data[-2]["text"]["text"] \
            .replace("<PERMISSION>", strip_quotes(permission_added))
                        
    elif finding.get("category") == "Reverse Shell":
        gitlab_runner_name = finding.get("kubernetes").get("pods")[0].get("name")
        gitlab_email = finding.get("processes")[0].get("envVariables")[12].get("val")
        destination_ip = finding.get("connections")[0].get("destinationIp")

        list_data.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*GitLab Runner Name:*\n<NAME>"
            }
        })
        list_data.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*GitLab Email:*\n<EMAIL>"
            }
        })
        list_data.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Destination IP:*\n<IP>"
            }
        })
        list_data.append({
            "type": "divider"
        })

        list_data[-4]["text"]["text"] = list_data[-4]["text"]["text"] \
            .replace("<NAME>", strip_quotes(gitlab_runner_name))
        list_data[-3]["text"]["text"] = list_data[-3]["text"]["text"] \
            .replace("<EMAIL>", strip_quotes(gitlab_email))
        list_data[-2]["text"]["text"] = list_data[-2]["text"]["text"] \
            .replace("<IP>", strip_quotes(destination_ip))
        
    elif finding.get("category") == "Persistence: Service Account Key Created":
        creator = finding.get("access").get("principalEmail")
        method = finding.get("access").get("methodName")
        service_account = resource.get("displayName")
        print(creator, method, service_account)

        list_data.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Creator:*\n<CREATOR>"
            }
        })
        list_data.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Method:*\n<METHOD>"
            }
        })
        list_data.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Service Account:*\n<SERVICE_ACCOUNT>"
            }
        })

        list_data.append({
            "type": "divider"
        })

        service_account = service_account.replace(f"projects/{project_path}/serviceAccounts/", "")

        list_data[-4]["text"]["text"] = list_data[-4]["text"]["text"] \
            .replace("<CREATOR>", strip_quotes(creator))
        list_data[-3]["text"]["text"] = list_data[-3]["text"]["text"] \
            .replace("<METHOD>", strip_quotes(method))
        list_data[-2]["text"]["text"] = list_data[-2]["text"]["text"] \
            .replace("<SERVICE_ACCOUNT>", strip_quotes(service_account))
        
    elif finding.get("category") == "Persistence: New Geography":
        region = finding.get("access").get("callerIpGeo").get("regionCode")
        region = f":flag-{region.lower()}:"
        ip = finding.get("access").get("callerIp")
        service = finding.get("access").get("methodName")
        user = finding.get("access").get("principalEmail")

        list_data.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Region:*\n<REGION>"
            }
        })

        list_data.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*IP:*\n<IP>"
            }
        })

        list_data.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*User:*\n<USER>"
            }
        })

        list_data.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Service:*\n<SERVICE>"
            }
        })

        list_data.append({
            "type": "divider"
        })

        list_data[-5]["text"]["text"] = list_data[-5]["text"]["text"] \
            .replace("<REGION>", strip_quotes(region))
        list_data[-4]["text"]["text"] = list_data[-4]["text"]["text"] \
            .replace("<IP>", strip_quotes(ip))
        list_data[-3]["text"]["text"] = list_data[-3]["text"]["text"] \
            .replace("<USER>", strip_quotes(user))
        list_data[-2]["text"]["text"] = list_data[-2]["text"]["text"] \
            .replace("<SERVICE>", strip_quotes(service))
        

def format_text(val, text2CodeBlocks: bool = False):
    """Function to format text for Slack.

    Args:
        val (str): The text to format.
        text2CodeBlocks (bool, optional): Whether to format as code block. Defaults to False.

    Returns:
        str: The formatted text.
    """
    val = val.replace("\\", "")
    val = val[1:] if val.startswith('"') else val
    val = val[:-1] if val.endswith('"') else val
    if text2CodeBlocks is True:
        val = val.replace('"', '`')
    return val


def get_secret(secret_id, version_id="latest"):
    """Function to retrieve a secret from Secret Manager.

    Args:
        secret_id (str): The ID of the secret to retrieve.
        version_id (str, optional): The version of the secret to retrieve. Defaults to "latest".

    Returns:
        str: The secret value.
    """
    gcp_project = get_project()
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{gcp_project}/secrets/{secret_id}/versions/{version_id}"
    return client.access_secret_version(name=name).payload.data.decode("utf-8")


def get_project():
    """Function to retrieve the GCP project ID.

    Returns:
        str: The GCP project ID.
    """
    return os.environ.get('project_id', 'project_id env var not set.')


def scc_slack_handler(event, context):
    """Function to handle PubSub messages.

    Args:
        event (dict): The PubSub message.
        context (dict): The PubSub context.
    """
    CUSTOM_LOG_NAME = "scc_notifications_log"
    logging_client = logging.Client()
    logger = logging_client.logger(CUSTOM_LOG_NAME)
    # logger = logging_client.logger()

    try:
        # PubSub messages come in encrypted
        payload = base64.b64decode(event['data']).decode('utf-8')
        message_post(payload)
    except Exception as e:
        logger.log(f"Oops! {e}")


if __name__ == "__main__":
    with open("test_temp.json", "rt") as testdata_f:
        testdata = json.load(testdata_f)
    message_post(testdata)
