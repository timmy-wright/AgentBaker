#!/bin/bash
set -eux
LINUX_SCRIPT_PATH="linux-vhd-content-test.sh"
WIN_CONFIGURATION_SCRIPT_PATH="generate-windows-vhd-configuration.ps1"
WIN_SCRIPT_PATH="windows-vhd-content-test.ps1"
TEST_RESOURCE_PREFIX="vhd-test"
TEST_VM_ADMIN_USERNAME="azureuser"

set +x
TEST_VM_ADMIN_PASSWORD="TestVM@$(date +%s)"
set -x

if [ "$OS_TYPE" == "Linux" ]; then
  if [ "$IMG_SKU" == "20_04-lts-cvm" ] || [ "$OS_VERSION" == "V1" ] && [ "$OS_SKU" == "CBLMariner" ]; then
    echo "Skipping tests for CVM 20.04 and Mariner 1.0"
    exit 0
  fi
fi


RESOURCE_GROUP_NAME="$TEST_RESOURCE_PREFIX-$(date +%s)-$RANDOM"
az group create --name $RESOURCE_GROUP_NAME --location ${AZURE_LOCATION} --tags 'source=AgentBaker'

# defer function to cleanup resource group when VHD debug is not enabled
function cleanup() {
  if [[ "$VHD_DEBUG" == "True" ]]; then
    echo "VHD debug mode is enabled, please manually delete test vm resource group $RESOURCE_GROUP_NAME after debugging"
  else
    echo "Deleting resource group ${RESOURCE_GROUP_NAME}"
    az group delete --name $RESOURCE_GROUP_NAME --yes --no-wait
  fi
}
trap cleanup EXIT

DISK_NAME="${TEST_RESOURCE_PREFIX}-disk"
VM_NAME="${TEST_RESOURCE_PREFIX}-vm"

az account list --output json | jq '.' | sed 's/^/ACCOUNT LIST:   /g'
set | sed 's/^/ENVIRONMENT:   /g'

# Get a bunch of information about the vm we're currently on:
# curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq '.' | sed 's/^/VM METADATA:   /g'
# name=$(curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq -r .compute.name)
# subscriptionId=$(curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq -r .compute.subscriptionId)
# resourceGroupName=$(curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq -r .compute.resourceGroupName)
# az vm show --subscription "${subscriptionId}" --resource-group "${resourceGroupName}" --name "${name}" --output json | jq '.' | sed 's/^/VM INFO:   /g'
# nicId=$(az vm show --subscription "${subscriptionId}" --resource-group "${resourceGroupName}" --name "${name}" --query networkProfile.networkInterfaces[0].id --output tsv)
# subnetId=$(az network nic show --ids "${nicId}" --query ipConfigurations[0].subnet.id --output tsv)

curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq '.' | sed 's/^/VM METADATA:   /g'

# az extension add --name resource-graph
# name=$(curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq -r .compute.name)
# subnet_id=$(az graph query --graph-query "Resources | where type =~ 'Microsoft.Compute/virtualMachines' and name =~ '${name}'" | jq --raw-output '.data[0].properties.networkProfile.networkInterfaces[0].id')
# az graph query --graph-query "Resources | where type =~ 'Microsoft.Compute/virtualMachines' and name =~ '${name}'" | jq '.' | sed 's/^/GRAPH:   /g'
# az graph query --graph-query "Resources | where type =~ 'Microsoft.Compute/virtualMachines'" | jq '.' | sed 's/^/GRAPH:   /g'

ssh-keygen -f ./vm-key -N ''

SUBNET_ID=$(az network vnet subnet show -g "${VNET_RESOURCE_GROUP_NAME}" -n "${SUBNET_NAME}" --vnet-name "${VNET_NAME}" --query 'id' --output tsv)

echo "TOBIASB: MODE: '${MODE}'"
if [ "$MODE" == "default" ]; then
  echo "TOBIASB: MODE is default"
  az disk create --resource-group $RESOURCE_GROUP_NAME \
    --name $DISK_NAME \
    --source "${OS_DISK_URI}" \
    --query id
  az vm create --name $VM_NAME \
    --resource-group $RESOURCE_GROUP_NAME \
    --attach-os-disk $DISK_NAME \
    --os-type $OS_TYPE \
    --ssh-key-value ./vm-key.pub \
    --subnet "${SUBNET_ID}" \
    --public-ip-address ""
    # --ssh-key-value ./vm-key.pub \
    # --subnet "${subnet_id}" \
    # --subnet "${SUBNET_NAME}" \
    # --vnet-name "${VNET_NAME}" \
else 
  echo "TOBIASB: MODE is not default"
  if [ "$MODE" == "sigMode" ]; then
    id=$(az sig show --resource-group ${AZURE_RESOURCE_GROUP_NAME} --gallery-name ${SIG_GALLERY_NAME}) || id=""
    if [ -z "$id" ]; then
      echo "Shared Image gallery ${SIG_GALLERY_NAME} does not exist in the resource group ${AZURE_RESOURCE_GROUP_NAME} location ${AZURE_LOCATION}"
      exit 1
    fi

    id=$(az sig image-definition show \
      --resource-group ${AZURE_RESOURCE_GROUP_NAME} \
      --gallery-name ${SIG_GALLERY_NAME} \
      --gallery-image-definition ${SIG_IMAGE_NAME}) || id=""
    if [ -z "$id" ]; then
      echo "Image definition ${SIG_IMAGE_NAME} does not exist in gallery ${SIG_GALLERY_NAME} resource group ${AZURE_RESOURCE_GROUP_NAME}"
      exit 1
    fi
  fi

  if [ -z "${MANAGED_SIG_ID}" ]; then
    echo "Managed Sig Id from packer-output is empty, unable to proceed..."
    exit 1
  else
    echo "Managed Sig Id from packer-output is ${MANAGED_SIG_ID}"
    IMG_DEF=${MANAGED_SIG_ID}
  fi

  # In SIG mode, Windows VM requires admin-username and admin-password to be set,
  # otherwise 'root' is used by default but not allowed by the Windows Image. See the error image below:
  # ERROR: This user name 'root' meets the general requirements, but is specifically disallowed for this image. Please try a different value.
  TARGET_COMMAND_STRING=""
  if [[ "${ARCHITECTURE,,}" == "arm64" ]]; then
    TARGET_COMMAND_STRING+="--size Standard_D2pds_v5"
  elif [[ "${FEATURE_FLAGS,,}" == "kata" ]]; then
    TARGET_COMMAND_STRING="--size Standard_D4ds_v5"
  fi

  if [[ "${OS_TYPE}" == "Linux" && "${ENABLE_TRUSTED_LAUNCH}" == "True" ]]; then
    if [[ -n "$TARGET_COMMAND_STRING" ]]; then
      # To take care of Mariner Kata TL images
      TARGET_COMMAND_STRING+=" "
    fi
    TARGET_COMMAND_STRING+="--security-type TrustedLaunch --enable-secure-boot true --enable-vtpm true"
  fi


  az network vnet subnet show -g "${VNET_RESOURCE_GROUP_NAME}" -n "${SUBNET_NAME}" --vnet-name "${VNET_NAME}" --output json | jq '.' | sed 's/^/SUBNET INFO:   /g'

  az vm create \
      --resource-group $RESOURCE_GROUP_NAME \
      --name $VM_NAME \
      --image $IMG_DEF \
      --admin-username $TEST_VM_ADMIN_USERNAME \
      --admin-password $TEST_VM_ADMIN_PASSWORD \
      --ssh-key-value ./vm-key.pub \
      --subnet "${SUBNET_ID}" \
      --public-ip-address "" \
      ${TARGET_COMMAND_STRING}

      # --subnet "${subnetId}" \
      # --ssh-key-value ./vm-key.pub \
      # --subnet "${SUBNET_NAME}" \
      # --vnet-name "${VNET_NAME}" \
  echo "VHD test VM username: $TEST_VM_ADMIN_USERNAME, password: $TEST_VM_ADMIN_PASSWORD"
fi

time az vm wait -g $RESOURCE_GROUP_NAME -n $VM_NAME --created

az vm show -g $RESOURCE_GROUP_NAME -n $VM_NAME --show-details --output json | jq '.' | sed 's/^/VM INFO:   /g'

az network vnet subnet show -g "${VNET_RESOURCE_GROUP_NAME}" -n "${SUBNET_NAME}" --vnet-name "${VNET_NAME}" --output json | jq '.' | sed 's/^/SUBNET INFO:   /g'

# get private ip address of the vm
VM_IP_ADDRESS_FROM_SHOW=$(az vm show -g ${RESOURCE_GROUP_NAME} -n ${VM_NAME} --show-details --query privateIps -o tsv)

VM_IP_ADDRESS=$(az vm list-ip-addresses --resource-group "${RESOURCE_GROUP_NAME}" --name "${VM_NAME}" --output tsv --query '[0].virtualMachine.network.privateIpAddresses[0]')

ssh -i ./vm-key "${TEST_VM_ADMIN_USERNAME}@${VM_IP_ADDRESS}" "echo 'Hello World'" | sed 's/^/SSH:   /g'

FULL_PATH=$(realpath $0)
CDIR=$(dirname $FULL_PATH)

if [ "$OS_TYPE" == "Linux" ]; then
  if [[ -z "${ENABLE_FIPS// }" ]]; then
    ENABLE_FIPS="false"
  fi


  # Replace dots with dashes and make sure we only have the file name of the test script.
  # This will be used to name azure resources related to the test.
  LINUX_SCRIPT_FILE_NAME_NO_DOTS=$(basename "${LINUX_SCRIPT_PATH//./-}")

  # Create blob storage for the test stdout and stderr. This allows us to get all output, not just
  # the first 4KB each of stdout/stderr.
  STDOUT_BLOB_NAME="${RESOURCE_GROUP_NAME}-${VM_NAME}-${LINUX_SCRIPT_FILE_NAME_NO_DOTS}-stdout.txt"
  STDERR_BLOB_NAME="${RESOURCE_GROUP_NAME}-${VM_NAME}-${LINUX_SCRIPT_FILE_NAME_NO_DOTS}-stderr.txt"
  SAS_EXPIRY=$(date -u -d "60 minutes" '+%Y-%m-%dT%H:%MZ')
  STDOUT_BLOB_URI=$(az storage blob generate-sas \
    --account-name "${OUTPUT_STORAGE_ACCOUNT_NAME}" \
    --container-name "${OUTPUT_STORAGE_CONTAINER_NAME}" \
    --connection-string "${CLASSIC_SA_CONNECTION_STRING}" \
    --name "${STDOUT_BLOB_NAME}" \
    --permissions acrw \
    --expiry "${SAS_EXPIRY}"\
    --full-uri --output tsv)
  STDERR_BLOB_URI=$(az storage blob generate-sas \
    --account-name "${OUTPUT_STORAGE_ACCOUNT_NAME}" \
    --container-name "${OUTPUT_STORAGE_CONTAINER_NAME}" \
    --connection-string "${CLASSIC_SA_CONNECTION_STRING}" \
    --name "${STDERR_BLOB_NAME}" \
    --permissions acrw \
    --expiry "${SAS_EXPIRY}" \
    --full-uri --output tsv)

  # Start the test script on the VM and wait for it to complete.
  # In testing, I've found that creating the script with --no-wait and then waiting for it
  # is nore reliable than waiting on the initial create command.
  COMMAND_NAME="${LINUX_SCRIPT_FILE_NAME_NO_DOTS}-command"
  SCRIPT_PATH="$CDIR/$LINUX_SCRIPT_PATH"
  az vm run-command create \
    --resource-group "${RESOURCE_GROUP_NAME}" \
    --vm-name "${VM_NAME}" \
    --name "${COMMAND_NAME}" \
    --script @$SCRIPT_PATH \
    --output json \
    --output-blob-uri "${STDOUT_BLOB_URI}" \
    --error-blob-uri "${STDERR_BLOB_URI}" \
    --no-wait
  az vm run-command wait \
    --resource-group "${RESOURCE_GROUP_NAME}" \
    --vm-name "${VM_NAME}" \
    --name "${COMMAND_NAME}" \
    --instance-view \
    --custom 'instanceView.endTime != null' \
    --output json

  # Get the data associated with the command, collecting the exit code
  # and execution state. Dump the whole thing.
  command_data=$(az vm run-command show \
    --resource-group "${RESOURCE_GROUP_NAME}" \
    --vm-name "${VM_NAME}" \
    --name "${COMMAND_NAME}" \
    --output json)
  command_exit_code=$(echo "${command_data}" | jq '.instanceView.exitCode')
  command_execution_state=$(echo "${command_data}" | jq '.instanceView.executionState')
  echo "${command_data}" | sed 's/^/TEST COMMAND DATA:  /g'

  # Get our stdout from the blob storage.
  az storage blob download \
    --account-name "${OUTPUT_STORAGE_ACCOUNT_NAME}" \
    --container-name "${OUTPUT_STORAGE_CONTAINER_NAME}" \
    --connection-string "${CLASSIC_SA_CONNECTION_STRING}" \
    --name "${STDOUT_BLOB_NAME}" \
    --file "./${STDOUT_BLOB_NAME}"
  cat "./${STDOUT_BLOB_NAME}" | sed 's/^/TEST STDOUT:  /g'

  # Get our stderr from the blob storage, collecting it in a variable
  # for later inspection.
  az storage blob download \
    --account-name "${OUTPUT_STORAGE_ACCOUNT_NAME}" \
    --container-name "${OUTPUT_STORAGE_CONTAINER_NAME}" \
    --connection-string "${CLASSIC_SA_CONNECTION_STRING}" \
    --name "${STDERR_BLOB_NAME}" \
    --file "./${STDERR_BLOB_NAME}"
  errMsg=$(cat "./${STDERR_BLOB_NAME}")
  echo "${errMsg}" | sed 's/^/TEST STDERR:  /g'

  # Clean up the command and blob storage.
  az vm run-command delete \
    --resource-group "${RESOURCE_GROUP_NAME}" \
    --vm-name "${VM_NAME}" \
    --name "${COMMAND_NAME}" \
    --yes
  az storage blob delete \
    --account-name "${OUTPUT_STORAGE_ACCOUNT_NAME}" \
    --container-name "${OUTPUT_STORAGE_CONTAINER_NAME}" \
    --connection-string "${CLASSIC_SA_CONNECTION_STRING}" \
    --name "${STDOUT_BLOB_NAME}" \
    --output json
  az storage blob delete \
    --account-name "${OUTPUT_STORAGE_ACCOUNT_NAME}" \
    --container-name "${OUTPUT_STORAGE_CONTAINER_NAME}" \
    --connection-string "${CLASSIC_SA_CONNECTION_STRING}" \
    --name "${STDERR_BLOB_NAME}" \
    --output json

  # A failure occurs if any of the following three happens:
  #   1. The command execution state is not "Succeeded".
  #   2. The command exit code is not 0.
  #   3. The stderr is not empty.
  if [ "${command_execution_state}" != '"Succeeded"' ] || [ "${command_exit_code}" != "0" ] || [ -n "${errMsg}" ]; then
    echo "TEST FAILED: See about output for details."
    exit 1
  fi
else
  SCRIPT_PATH="$CDIR/../$WIN_CONFIGURATION_SCRIPT_PATH"
  echo "Run $SCRIPT_PATH"
  az vm run-command invoke --command-id RunPowerShellScript \
    --name $VM_NAME \
    --resource-group $RESOURCE_GROUP_NAME \
    --scripts @$SCRIPT_PATH \
    --output json

  SCRIPT_PATH="$CDIR/$WIN_SCRIPT_PATH"
  echo "Run $SCRIPT_PATH"
  ret=$(az vm run-command invoke --command-id RunPowerShellScript \
    --name $VM_NAME \
    --resource-group $RESOURCE_GROUP_NAME \
    --scripts @$SCRIPT_PATH \
    --output json \
    --parameters "containerRuntime=${CONTAINER_RUNTIME}" "windowsSKU=${WINDOWS_SKU}")
  # An example of failed run-command output:
  # {
  #   "value": [
  #     {
  #       "code": "ComponentStatus/StdOut/succeeded",
  #       "displayStatus": "Provisioning succeeded",
  #       "level": "Info",
  #       "message": "c:\akse-cache\containerd\containerd-0.0.87-public.zip is cached as expected
  # c:\akse-cache\win-vnet-cni\azure-vnet-cni-singletenancy-windows-amd64-v1.1.2.zip is cached as expected
  # ... ...
  # "
  #       "time": null
  #     },
  #     {
  #       "code": "ComponentStatus/StdErr/succeeded",
  #       "displayStatus": "Provisioning succeeded",
  #       "level": "Info",
  #       "message": "Test-FilesToCacheOnVHD : File c:\akse-cache\win-k8s\v1.15.10-azs-1int.zip does not exist
  # At C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\1.1.5\Downloads\script0.ps1:146 char:1
  # + Test-FilesToCacheOnVHD
  # + ~~~~~~~~~~~~~~~~~~~~~~
  #     + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
  #     + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,Test-FilesToCacheOnVHD
  #  ",
  #       "time": null
  #     }
  #   ]
  # }
  # we have to use `-E` to disable interpretation of backslash escape sequences, for jq cannot process string
  # with a range of control characters not escaped as shown in the error below:
  #   Invalid string: control characters from U+0000 through U+001F must be escaped
  errMsg=$(echo -E $ret | jq '.value[]  | select(.code == "ComponentStatus/StdErr/succeeded") | .message')
  # a successful errMsg should be '""' after parsed by `jq`
  if [[ $errMsg != \"\" ]]; then
    exit 1
  fi
fi

echo "Tests Run Successfully"