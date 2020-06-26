# Cloudtrail CIS Notifier

Creates a pipeline to send cloudtrail events to a slack account.

Events are filtered according to CIS recommended rules.

https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf

Cloudtrail -> cloudwatch logs -> log stream -> lambda -> slack

## Testing

Generate test data for the lambda function with

`lambda-source/generate-test-message.sh | pbcopy`

Resulting json can be added to the `lambda` test functions.
