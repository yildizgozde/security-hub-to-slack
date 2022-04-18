# Security-hub-to-slack
Terraform Module to setup Security Hub and GuardDuty to slack nofitication chennel


## Documentation
[Enable AWS Security Hub, GuardDuty and Slack Notification Stack](https://dev.to/noyonict)

## Usages
Define your module like this:

```
provider "aws" {
  region     = "eu-west-1"
  access_key = "AWS-ACCESS-KEY"
  secret_key = "AWS-SECRET-ACCESS-KEY"
}


module "security-hub-to-slack" {
  source             = "git@github.com:noyonict/Security-hub-to-slack.git"
  IncomingWebHookURL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
  SlackChannel       = "security_alerts"
}
```
**_IncomingWebHookURL*_**: Incoming Webhook URL for slack app. To create follow this [Doc](https://api.slack.com/messaging/webhooks#getting_started). For example: `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX`

**_SlackChannel_**: Slack Chennel Name. Default: `security_alerts`

> Note: Required Terraform version >= 0.12 and also you can provide the AWS access details or it will using the default configuration.

Then open Terminal in the Module location:

`terraform init`

`terraform plan`
Plan: 12 to add, 0 to change, 0 to destroy.

`terraform apply --auto-approve`

You will see this message:
> Apply complete! Resources: 12 added, 0 changed, 0 destroyed.

It will create a `IAM role`, a CloudWatch `Log groups`, two EventBridge Rules one for `GuardDuty` and another one for `SecurityHub`
and also a lambda function which will send the notification to the Slack chennel using the webhook URL.

