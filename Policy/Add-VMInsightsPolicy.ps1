﻿<#PSScriptInfo

.VERSION 1.02

.GUID 7f0faed7-7563-483a-856e-55554761f4b2

.AUTHOR dougbrad@microsoft.com

.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#>

<#
.SYNOPSIS
  Adds the Policies and Initiatives to configure VM's for VM Insights Preview

.Description
  This script adds the Policies and Initiatives for VM Insights preview to your current subscription or the subscription specified for -SubscriptionId

  Note:
  This script can be re-run if changes are made to the Policies.
  However if changes are made to the parameters, you will need to delete the Policies/Initiative first.

.PARAMETER UseLocalPolicies
    <Optional> Load the policies from a local folder instead of https://github.com/dougbrad/OnBoardVMInsights/tree/master/Policy

.PARAMETER SubscriptionId
    <Optional> SubscriptionId to add the Policies/Initiatives to

.PARAMETER ManagementGroupId
    <Optional> Management Group Id to add the Policies/Initiatives to

.PARAMETER Approve
    <Optional> Gives the approval to add the Policies/Initiatives without any prompt

.EXAMPLE
  .\Add-VMInsightsPolicy.ps1

.LINK
    This script is posted to and further documented at the following location:
    http://aka.ms/OnBoardVMInsights
#>

[CmdletBinding()]
param(
    [Parameter(mandatory = $false)][switch]$UseLocalPolicies,
    [Parameter(mandatory = $false)][string]$SubscriptionId,
    [Parameter(mandatory = $false)][string]$ManagementGroupId,
    [Parameter(mandatory = $false)][switch]$Approve
)

# TODO: Remove the branch once this is in master
#
# Take policies from here unless run with -UseLocalPolicies
$gitHubSource = "https://raw.githubusercontent.com/dougbrad/OnBoardVMInsights/master/Policy/"
if ($UseLocalPolicies) {
    $gitHubSource = ""
}

$vmInsightsInitiativePoliciesJson = @"
[
    {
        "name": "deploy-loganalytics-windows-vm",
        "displayName": "Deploy Log Analytics Agent for Windows VMs - Preview",
        "description": "Deploy Log Analytics Agent for Windows VMs if the VM Image (OS) is in the list defined and the agent is not installed.",
        "policy": "deploy-loganalytics-windows-vm.rules.json",
        "parameter": "deploy-loganalytics-vm.parameters.json"
    },
    {
        "name": "deploy-loganalytics-linux-vm",
        "displayName": "Deploy Log Analytics Agent for Linux VMs - Preview",
        "description": "Deploy Log Analytics Agent for Linux VMs if the VM Image (OS) is in the list defined and the agent is not installed.",
        "policy": "deploy-loganalytics-linux-vm.rules.json",
        "parameter": "deploy-loganalytics-vm.parameters.json"
    },
    {
        "name": "deploy-dependencyagent-windows-vm",
        "displayName": "Deploy Dependency Agent for Windows VMs - Preview",
        "description": "Deploy Dependency Agent for Windows VMs if the VM Image (OS) is in the list defined and the agent is not installed.",
        "policy": "deploy-dependencyagent-windows-vm.rules.json"
    },
    {
        "name": "deploy-dependencyagent-linux-vm",
        "displayName": "Deploy Dependency Agent for Linux VMs - Preview",
        "description": "Deploy Dependency Agent for Linux VMs if the VM Image (OS) is in the list defined and the agent is not installed.",
        "policy": "deploy-dependencyagent-linux-vm.rules.json"
    },
    {
        "name": "audit-loganalytics-vm-os-notinscope",
        "displayName": "Audit Log Analytics Agent Deployment - VM Image (OS) unlisted - Preview",
        "description": "Reports VMs as non-compliant if the VM Image (OS) is not in the list defined and the agent is not installed.",
        "policy": "audit-loganalytics-vm-os-notinscope.json"
    },
    {
        "name": "audit-dependencyagent-vm-os-notinscope",
        "displayName": "Audit Dependency Agent Deployment - VM Image (OS) unlisted - Preview",
        "description": "Reports VMs as non-compliant if the VM Image (OS) is not in the list defined and the agent is not installed.",
        "policy": "audit-dependencyagent-vm-os-notinscope.json"
    }
]
"@

$vmInsightsStandalonePoliciesJson = @"
[
    {
        "name": "audit-loganalytics-mismatch-vm",
        "displayName": "Audit Log Analytics Workspace for VM - Report Mismatch - Preview",
        "description": "Reports VMs as non-compliant if they not logging to the LA workspace specified in the policy/initiative assignment.",
        "policy": "audit-loganalytics-mismatch-vm.rules.json",
        "parameter": "audit-loganalytics-mismatch-vm.parameters.json"
    }
]
"@

$vmInsightsInitiativeJson = @"
{
    "name": "vminsights-initiative",
    "displayName": "Enable Azure Monitor for VMs - Preview",
    "description": "Enable Azure Monitor for the Virtual Machines (VMs) in the specified scope (Management group, Subscription or resource group). Takes Log Analytics workspace as parameter."
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
            "description": "Select Log Analytics workspace from dropdown list. If this workspace is outside of the scope of the assignment you must manually grant 'Log Analytics Contributor' permissions (or similar) to the policy assignment's principal ID.",
            "strongType": "omsWorkspace"
        }
    }
}
"@

$category = @"
{
    "category": "Monitoring"
}
"@

$vmInsightsInitiativePolicies = $vmInsightsInitiativePoliciesJson | ConvertFrom-Json
$vmInsightsStandalonePolicies = $vmInsightsStandalonePoliciesJson | ConvertFrom-Json
$vmInsightsInitiative = $vmInsightsInitiativeJson  | ConvertFrom-Json

function Add-PolicyDefinition {
    <#
	.SYNOPSIS
    Adds the policies. By default adds to the current subscription.
    If ManagementGroupName is specified adds to that.
	#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)][psobject]$Policies,
        [Parameter(mandatory = $false)][string]$ManagementGroupId
    )

    $managementGroupIdParameter = @{}
    if ($ManagementGroupId) {
        $managementGroupIdParameter."ManagementGroupName" = $ManagementGroupId
    }

    foreach ($policy in $Policies) {
        $parameter = @{}
        if ($policy.parameter) {
            $parameter."Parameter" = $gitHubSource + $policy.parameter
            Write-Verbose("Policy Parameter: " + $parameter."Parameter")
        }

        Write-Verbose("Adding Policy: " + $gitHubSource + $policy.policy)

        New-AzureRmPolicyDefinition `
            -Name $policy.name `
            -DisplayName $policy.displayName `
            -Description $policy.description `
            -Policy ($gitHubSource + $policy.policy) `
            -Metadata $category `
            @parameter `
            @managementGroupIdParameter `
            -ApiVersion 2018-05-01
    }
}

#
# First make sure authenticed, select to the WorkspaceSubscriptionId if supplied
#
$account = Get-AzureRmContext
if ($null -eq $account.Account) {
    Write-Output("Account Context not found, please login")
    if ($SubscriptionId) {
        Connect-AzureRmAccount -SubscriptionId $SubscriptionId
    }
    else {
        Connect-AzureRmAccount
    }
}
elseif ($SubscriptionId) {
    if ($account.Subscription.SubscriptionId -eq $SubscriptionId) {
        Write-Output("Subscription: $SubscriptionId is already selected.")
    }
    else {
        Write-Output("Changing to subscription: $SubscriptionId")
        $account = Set-AzureRmContext -SubscriptionId $SubscriptionId
    }
}

if ($ManagementGroupId) {
    Write-Output("Policies and Initiatives for VM Insights will be added to Management Group Id: `n" `
    + $ManagementGroupId)
} else {
    Write-Output("Policies and Initiatives for VM Insights will be added to subscription: `n" `
    + $account.Subscription.Name + " ( " + $account.Subscription.SubscriptionId + " )")
}

if ($Approve -eq $true -or !$PSCmdlet.ShouldProcess("All") -or $PSCmdlet.ShouldContinue("Continue?", "")) {
    Write-Output ""
}
else {
    Write-Output "You selected No - exiting"
    return
}

#
# Add the Policies
#
Add-PolicyDefinition -Policies $vmInsightsInitiativePolicies -ManagementGroupId $ManagementGroupId
Add-PolicyDefinition -Policies $vmInsightsStandalonePolicies -ManagementGroupId $ManagementGroupId

#
# Add the Initiative
#
$managementGroupIdParameter = @{}
if ($ManagementGroupId) {
    $managementGroupIdParameter."ManagementGroupName" = $ManagementGroupId
}

$vmInsightsDefinition = "["
foreach ($policy in $vmInsightsInitiativePolicies) {
    $policyDefinitionId = (Get-AzureRmPolicyDefinition -Name $policy.name @managementGroupIdParameter | Select-Object -ExpandProperty PolicyDefinitionId)
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
    -Parameter $vmInsightsParametersJson `
    -Metadata $category `
    @managementGroupIdParameter `
    -ApiVersion 2018-05-01