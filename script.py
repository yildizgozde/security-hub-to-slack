import os
import datetime
import requests


webhook_url = os.environ['webHookUrl']
slack_channel = os.environ['slackChannel']
consoleUrl = "https://console.aws.amazon.com/securityhub"

accounts = {
  "111222333444": "A friendly Name"
}


def process_event(event):
    attachment = []

    for finding in event['detail']['findings']:
        if finding['Workflow']['Status'] != "NEW":
            continue
        findingDescription = finding['Description']
        findingTime = finding['UpdatedAt']
        findingTimeEpoch = round(datetime.datetime.strptime(finding['UpdatedAt'], '%Y-%m-%dT%H:%M:%S.%fZ').timestamp())
        account = f"{accounts.get(finding['AwsAccountId'], 'Unknown')} ({finding['AwsAccountId']})"
        region = ", ".join(set([res['Region'] for res in finding['Resources']]))
        _type = ", ".join(set([res['Type'] for res in finding['Resources']]))
        messageId = ", ".join(set([res['Id'] for res in finding['Resources']]))
        lastSeen = f"<!date^{findingTimeEpoch}^{{date}} at {{time}} | {findingTime}>"

        color = '#7CD197'
        severity = ''

        if 1 <= finding['Severity']['Normalized'] and finding['Severity']['Normalized'] <= 39: severity, color = 'LOW', '#879596'
        elif 40 <= finding['Severity']['Normalized'] and finding['Severity']['Normalized'] <= 69: severity, color = 'MEDIUM', '#ed7211'
        elif 70 <= finding['Severity']['Normalized'] and finding['Severity']['Normalized'] <= 89: severity, color = 'HIGH', '#ed7211'
        elif 90 <= finding['Severity']['Normalized'] and finding['Severity']['Normalized'] <= 100: severity, color = 'CRITICAL', '#ff0209'
        else: severity, color = 'INFORMATIONAL', '#007cbc'

        attachment.append({
            "fallback": f"{finding} - {consoleUrl}/home?region={region}#/findings?search=id%3D{messageId}",
            "pretext": f"*AWS SecurityHub finding in {region} for Acc: {account}*",
            "title": finding['Title'],
            "title_link": f"{consoleUrl}/home?region={region}#/findings?search=id%3D{messageId}",

            "text": findingDescription,
            "fields": [
                { "title": "Severity", "value": severity, "short": True },
                { "title": "Region", "value": region, "short": True },
                { "title": "Resource Type", "value": _type, "short": True },
                { "title": "Last Seen", "value": lastSeen, "short": True }
            ],
            "mrkdwn_in": ["pretext"],
            "color": color
        })

    if not attachment:
        return

    req = requests.post(webhook_url, json={
        'channel': slack_channel,
        'text': '',
        'attachments': attachment,
        'username': 'SecurityHub',
        'mrkdwn': True,
        'icon_url': 'data:image/pngbase64,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'
    })
    print(req.json)
    req.raise_for_status()


def handler(event, context):
    print(event)
    process_event(event)
