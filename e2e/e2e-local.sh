#!/bin/bash

set -euxo pipefail

: "${SUBSCRIPTION_ID:=035db282-f1c8-4ce7-b78f-2a7265d5398c}" #Azure Container Service - Test Subscription
: "${RESOURCE_GROUP_NAME:=henryli-arm64-test}"
: "${LOCATION:=eastus}"
: "${CLUSTER_NAME:=test-azurelinux-arm64}"
: "${AZURE_TENANT_ID:=72f988bf-86f1-41af-91ab-2d7cd011db47}"
: "${TIMEOUT:=30m}"

export SUBSCRIPTION_ID
export RESOURCE_GROUP_NAME
export LOCATION
export CLUSTER_NAME
export AZURE_TENANT_ID

go version
go test -timeout $TIMEOUT -v -run Test_All ./