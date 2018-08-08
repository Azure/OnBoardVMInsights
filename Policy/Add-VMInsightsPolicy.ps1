<#
.SYNOPSIS
  Adds the Policies and Initiatives to configure VM's for VM Insights Preview

.Description
  This script adds the Policies and Initiatives for VM Insights preview to your current subscription.

  Note:
  This script can be re-run if changes are made to the Policies.
  However if changes are made to the parameters, you will need to delete the Policies/Initiative first.

.PARAMETER UseLocalPolicies
    <Optional> Load the policies from local folder instead of https://raw.githubusercontent.com/dougbrad/OnBoardVMInsights/Policy/Policy/

.EXAMPLE 
  .\Add-VMInsightsPolicy.ps1

.LINK
    This script is posted to and further documented at the following location:
    http://aka.ms/OnBoardVMInsights
#>

[CmdletBinding()]
param(
    [Parameter(mandatory = $false)][switch]$UseLocalPolicies
)

# First check that latest version of Azure PowerShell is installed
$LatestAzureCmdletsVersion = "6.3.0"
try {
    Import-Module -MinimumVersion $LatestAzureCmdletsVersion AzureRM.Resources -ErrorAction Stop
}
catch {
    Write-Error $_.Exception
    Write-Error "Please install version $LatestAzureCmdletsVersion or greater of Azure PowerShell"
    Exit
}

$policiesToAddJson = @"
[
    {
        "name": "deploy-dependencyagent-windows-vm-preview",
        "displayName": "Deploy Dependency Agent VM extension for Windows VMs - Preview",
        "description": "-",
        "policy": "deploy-dependencyagent-windows-vm.rules.json"
    },
    {
        "name": "deploy-dependencyagent-linux-vm-preview",
        "displayName": "Deploy Dependency Agent VM extension for Linux VMs - Preview",
        "description": "-",
        "policy": "deploy-dependencyagent-linux-vm.rules.json"
    },
    {
        "name": "deploy-loganalytics-windows-vm-preview",
        "displayName": "Deploy Log Analytics VM extension for Windows VMs - Preview",
        "description": "-",
        "policy": "deploy-loganalytics-windows-vm.rules.json",
        "parameter": "deploy-loganalytics-vm.parameters.json"
    },
    {
        "name": "deploy-loganalytics-linux-vm-preview",
        "displayName": "Deploy Log Analytics VM extension for Linux VMs - Preview",
        "description": "-",
        "policy": "deploy-loganalytics-linux-vm.rules.json",
        "parameter": "deploy-loganalytics-vm.parameters.json"
    }
]
"@

$vmInsightsInitiativeJson = @"
{
    "name": "vminsights-initiative-preview",
    "displayName": "Enable VM Insights for VMs - Preview",
    "description": "-",
    "policy": "vminsights.definitions.json",
    "parameters": "vminsights.parameters.json"
}
"@

$logAnalyticsParameterJson = @"
"parameters": {
    "logAnalytics": {
        "value": "[parameters('logAnalytics_1')]"
    }
}
"@

$vmInsightsParametersJson = @"
{
    "logAnalytics_1": {
        "type": "String",
        "metadata": {
            "displayName": "Log Analytics workspace",
            "description": "Select Log Analytics workspace from dropdown list",
            "strongType": "omsWorkspace"
        }
    }
}
"@

$policiesToAdd = $policiesToAddJson | ConvertFrom-Json
$vmInsightsInitiative = $vmInsightsInitiativeJson  | ConvertFrom-Json

#
# First make sure authenticed
#
$account = Get-AzureRmContext
if ($null -eq $account.Account) {
    Write-Output("Account Context not found, please login")
    Login-AzureRmAccount
}

foreach ($policy in $policiesToAdd ) {
    $parameter = @{}
    if ($policy.parameter) {
        $parameter."Parameter" = $policy.parameter
    }

    if ($UseLocalPolicies) {
        $policyFile = $policy.policy
    }
    else {
        # TODO: Remove the branch
        $policyFile = "https://raw.githubusercontent.com/dougbrad/OnBoardVMInsights/Policy/Policy/" + $policy.policy
    }

    Write-Verbose("Adding Policy: $policyFile")

    New-AzureRmPolicyDefinition `
        -Name $policy.name `
        -DisplayName $policy.displayName `
        -Description $policy.description `
        -Policy $policyFile `
        @parameter
}

# Craft the Json for the initiative definition
# Would like any feedback on how to implement this better
$vmInsightsDefinition = "["
foreach ($policy in $policiesToAdd) {
    $policyDefinitionId = (Get-AzureRmPolicyDefinition -Name $policy.name | select -ExpandProperty PolicyDefinitionId)
    $vmInsightsDefinition += '{ "policyDefinitionId": "' + $policyDefinitionId + '"'
    if ($policy.parameter) {
        $vmInsightsDefinition += ',' + $logAnalyticsParameterJson
    }
    $vmInsightsDefinition += '},'
}
$vmInsightsDefinition = $vmInsightsDefinition.TrimEnd(",")
$vmInsightsDefinition += "]"

Write-Verbose($vmInsightsDefinition)

New-AzureRmPolicySetDefinition `
    -Name $vmInsightsInitiative.name `
    -DisplayName $vmInsightsInitiative.displayName `
    -Description $vmInsightsInitiative.description `
    -PolicyDefinition $vmInsightsDefinition `
    -Parameter $vmInsightsParametersJson
