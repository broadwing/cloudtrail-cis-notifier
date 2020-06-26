#!/bin/sh

BASEDIR=$(dirname "$0")

DATA=$(cat $BASEDIR/decoded-test-messages.json | gzip | base64 -w 0)

echo "
{
  \"awslogs\": {
    \"data\": \"${DATA}\"
  }
}"
