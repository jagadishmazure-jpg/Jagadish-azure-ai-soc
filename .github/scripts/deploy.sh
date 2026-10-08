#!/usr/bin/env bash
# Deployment steps used by .github/workflows/deploy.yml and teardown.yml. Each subcommand is
# idempotent and reads its inputs from the environment:
#   DEPLOY_TOOL   terraform | bicep
#   TARGET_ENV    dev | prod
#   LOCATION      Azure region (default eastus2)
#   ARM_* / AZURE_*  set by azure/login (OIDC) and the workflow env
#
#   deploy.sh provision   create/update the workspace stack, write rg/workspace to $GITHUB_OUTPUT
#   deploy.sh smoke       check Sentinel onboarding, the playbook and the two role assignments
#   deploy.sh destroy     tear the environment down (teardown workflow only)
#
# Never run from this repository so far: DEPLOY_ENABLED is not set.
set -euo pipefail

TOOL="${DEPLOY_TOOL:-terraform}"
ENV_NAME="${TARGET_ENV:?TARGET_ENV is required}"
LOCATION="${LOCATION:-eastus2}"
STACK="infra/terraform"
OUT="${GITHUB_OUTPUT:-/dev/stdout}"

log() { echo "::group::$*"; }
end() { echo "::endgroup::"; }

tf_init() {
  : "${TFSTATE_RESOURCE_GROUP:?set repo/environment variable TFSTATE_RESOURCE_GROUP}"
  : "${TFSTATE_STORAGE_ACCOUNT:?set repo/environment variable TFSTATE_STORAGE_ACCOUNT}"
  terraform -chdir="$STACK" init -input=false \
    -backend-config="envs/${ENV_NAME}.backend.hcl" \
    -backend-config="resource_group_name=${TFSTATE_RESOURCE_GROUP}" \
    -backend-config="storage_account_name=${TFSTATE_STORAGE_ACCOUNT}" \
    -backend-config="container_name=${TFSTATE_CONTAINER:-tfstate}"
}

provision() {
  if [[ "$TOOL" == "terraform" ]]; then
    log "terraform apply ($ENV_NAME)"
    tf_init
    terraform -chdir="$STACK" apply -auto-approve -input=false -var-file="envs/${ENV_NAME}.tfvars" -var "location=${LOCATION}"
    rg=$(terraform -chdir="$STACK" output -raw AZURE_RESOURCE_GROUP)
    ws=$(terraform -chdir="$STACK" output -raw LOG_ANALYTICS_WORKSPACE_NAME)
    end
  else
    log "bicep: az deployment sub create ($ENV_NAME)"
    private=false; rules=false
    [[ "$ENV_NAME" == "prod" ]] && { private=true; rules=true; }
    outputs=$(az deployment sub create --name "aisoc-${ENV_NAME}-${GITHUB_RUN_ID:-local}" \
      --location "$LOCATION" --template-file infra/bicep/main.bicep \
      --parameters environment="$ENV_NAME" location="$LOCATION" privateNetworking="$private" deployAnalyticsRules="$rules" \
      --query properties.outputs -o json)
    rg=$(jq -r .AZURE_RESOURCE_GROUP.value <<<"$outputs")
    ws=$(jq -r .LOG_ANALYTICS_WORKSPACE_NAME.value <<<"$outputs")
    end
  fi
  { echo "resource_group=$rg"; echo "workspace=$ws"; } >>"$OUT"
}

smoke() {
  : "${RESOURCE_GROUP:?}" "${WORKSPACE:?}"
  sub=$(az account show --query id -o tsv)
  ws_id="/subscriptions/${sub}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE}"
  az rest --method get --url "https://management.azure.com${ws_id}/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01" >/dev/null \
    || { echo "::error::Sentinel is not onboarded on ${WORKSPACE}"; exit 1; }
  n=$(az resource list -g "$RESOURCE_GROUP" --resource-type Microsoft.Logic/workflows --query "length(@)" -o tsv)
  [[ "$n" -ge 1 ]] || { echo "::error::playbook missing"; exit 1; }
  roles=$(az role assignment list --scope "$ws_id" --query "[].roleDefinitionName" -o tsv | sort -u | tr '\n' ',')
  [[ "$roles" == *"Microsoft Sentinel Reader"* && "$roles" == *"Microsoft Sentinel Responder"* ]] || { echo "::error::expected Sentinel Reader and Responder assignments, found: $roles"; exit 1; }
  echo "smoke checks passed: Sentinel onboarded, playbook present, roles: $roles"
}

destroy() {
  if [[ "$TOOL" == "terraform" ]]; then
    tf_init
    terraform -chdir="$STACK" destroy -auto-approve -input=false -var-file="envs/${ENV_NAME}.tfvars" -var "location=${LOCATION}"
  else
    case "$LOCATION" in eastus2) short=eus2 ;; westus2) short=wus2 ;; westeurope) short=weu ;; *) exit 1 ;; esac
    az group delete --name "rg-aisoc-${TENANT_SLUG:-brightwater}-${ENV_NAME}-${short}-001" --yes
  fi
}

"$@"
