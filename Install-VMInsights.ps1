<#PSScriptInfo

.VERSION 1.10

.GUID 76a487ef-47bf-4537-8942-600a66a547b1

.AUTHOR vpidatala@microsoft.com

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
This script installs VM extensions for Log Analytics/Azure Monitoring Agent (AMA) and Dependency Agent as needed for VM Insights.
If AMA is onboarded a Data Collection Rule(DCR) and an User Assigned Managed Identity (UAMI) is also associated with the VM's and VM Scale Sets.

.DESCRIPTION
This script installs or re-configures following on VM's and VM Scale Sets:
- Log Analytics VM Extension configured to supplied Log Analytics Workspace
- Azure Monitor Agent
- Data Collection Rule
- User Assigned Identity
- Dependency Agent VM Extension

Can be applied to:
- Subscription
- Resource Group in a Subscription
- Specific VM/VM Scale Set
- Compliance results of a policy for a VM or VM Extension

If the extensions are already installed won't be reinstalled and rather updated unless extensionType = OmsAgentForLinux where uninstall + install operation is performed when switching workspaces.

Script will show you list of VM's/VM Scale Sets that will apply to and let you confirm to continue.
Use -Approve switch to run without prompting, if all required parameters are provided.

If the Log Analyitcs Agent extension is already configured with a workspace, use -ReInstall switch to update the workspace.

Use -WhatIf if you would like to see what would happen in terms of installs, what workspace configured to, and status of the extension.

.PARAMETER WorkspaceId
Log Analytics WorkspaceID (GUID) for the data to be sent to

.PARAMETER WorkspaceKey
Log Analytics Workspace primary or secondary key

.PARAMETER SubscriptionId
SubscriptionId for the VMs/VM Scale Sets
If using PolicyAssignmentName parameter, subscription that VM's are in

.PARAMETER WorkspaceRegion
Region the Log Analytics Workspace is in
Suported values: "East US","eastus","Southeast Asia","southeastasia","West Central US","westcentralus","West Europe","westeurope", "Canada Central", "canadacentral", "UK South", "uksouth", "West US 2", "westus2", "East Australia", "eastaustralia", "Southeast Australia", "southeastaustralia", "Japan East", "japaneast", "North Europe", "northeurope", "East US 2", "eastus2", "South Central US", "southcentralus", "North Central US", "northcentralus", "Central US", "centralus", "West US", "westus", "Central India", "centralindia", "East Asia", "eastasia","East US 2 EUAP", "eastus2euap", "USGov Virginia","usgovvirginia", "USGov Arizona","usgovarizona"
For Health supported is: "East US","eastus","West Central US","westcentralus", "West Europe", "westeurope"

.PARAMETER ProcessAndDependencies
Determines whether to onboard Dependency Agent with Azure Monitoring Agent (AMA)

.PARAMETER DcrResourceId
ResourceId of Data Collection Rule (DCR)

.PARAMETER UserAssignedManagedIdentityResourceGroup
Resource Group of User Assigned Managed Identity (UAMI)

.PARAMETER UserAssignedManagedIdentityName
Name of User Assigned Managed Identity (UAMI) 

.PARAMETER ResourceGroup
<Optional> Resource Group to which the VMs or VM Scale Sets belong to

.PARAMETER Name
<Optional> To install to a single VM/VM Scale Set

.PARAMETER PolicyAssignmentName
<Optional> Take the input VM's to operate on as the Compliance results from this Assignment
If specified will only take from this source.

.PARAMETER ReInstall
If for a VM/VM Scale Set, the Log Analytics Agent is already configured for a different workspace, provide this parameter to switch to the new workspace

.PARAMETER TriggerVmssManualVMUpdate
<Optional> Set this flag to trigger update of VM instances in a scale set whose upgrade policy is set to Manual

.PARAMETER Approve
<Optional> Gives the approval for the installation to start with no confirmation prompt for the listed VM's/VM Scale Sets

.PARAMETER Whatif
<Optional> See what would happen in terms of installs.
If extension is already installed will show what workspace is currently configured, and status of the VM extension

.PARAMETER Confirm
<Optional> Confirm every action

.EXAMPLE
.\Install-VMInsights.ps1 -WorkspaceRegion eastus -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup>
Install for all VM's in a Resource Group in a subscription

.EXAMPLE
.\Install-VMInsights.ps1 -WorkspaceRegion eastus -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup> -ReInstall
Specify to ReInstall extensions even if already installed, for example to update to a different workspace

.EXAMPLE
.\Install-VMInsights.ps1 -WorkspaceRegion eastus -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -PolicyAssignmentName a4f79f8ce891455198c08736 -ReInstall
Specify to use a PolicyAssignmentName for source, and to ReInstall (move to a new workspace)

.EXAMPLE
.\Install-VMInsights.ps1 -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup>  -DcrResourceId <DataCollectionRuleResourceId> -ProcessAndDependencies -UserAssignedManagedIdentityName <UserAssignedIdentityName> -UserAssignedManagedIdentityResourceGroup <UserAssignedIdentityResourceGroup>
(the above command will onboard Assign a UAMI to a VM/VMss for AMA, Onboard AMA, DA and associate a DCR with the VM/Vmss)

.EXAMPLE
.\Install-VMInsights.ps1 -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup>  -DcrResourceId <DataCollectionRuleResourceId> -UserAssignedManagedIdentityName <UserAssignedIdentityName> -UserAssignedManagedIdentityResourceGroup <UserAssignedIdentityResourceGroup>
(the above command will onboard Assign a UAMI to a VM/VMss for AMA, Onboard AMA and associate a DCR with the VM/Vmss)

.EXAMPLE
.\Install-VMInsights.ps1 -SubscriptionId <SubscriptionId> -PolicyAssignmentName a4f79f8ce891455198c08736  -DcrResourceId <DataCollectionRuleResourceId> -UserAssignedManagedIdentityName <UserAssignedIdentityName> -UserAssignedManagedIdentityResourceGroup <UserAssignedIdentityResourceGroup>
(the above command will onboard Assign a UAMI to a VMs for AMA, Onboard AMA and associate a DCR with the VM/Vmss)

.EXAMPLE
.\Install-VMInsights.ps1 -SubscriptionId <SubscriptionId> -PolicyAssignmentName a4f79f8ce891455198c08736  -DcrResourceId <DataCollectionRuleResourceId> -ProcessAndDependencies -UserAssignedManagedIdentityName <UserAssignedIdentityName> -UserAssignedManagedIdentityResourceGroup <UserAssignedIdentityResourceGroup>
(the above command will onboard Assign a UAMI to a VMs for AMA, Onboard AMA, DA and associate a DCR with the VM/Vmss)

.LINK
This script is posted to and further documented at the following location:
http://aka.ms/OnBoardVMInsights
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(mandatory = $true)][string]$SubscriptionId,
    [Parameter(mandatory = $false)][string]$ResourceGroup,
    [Parameter(mandatory = $false)][string]$Name,
    [Parameter(mandatory = $false)][string]$PolicyAssignmentName,
    [Parameter(mandatory = $false)][switch]$TriggerVmssManualVMUpdate,
    [Parameter(mandatory = $false)][switch]$Approve,
    [Parameter(mandatory = $true, ParameterSetName = 'LogAnalyticsAgent')][string]$WorkspaceId,
    [Parameter(mandatory = $true, ParameterSetName = 'LogAnalyticsAgent')][string]$WorkspaceKey,
    [Parameter(mandatory = $false, ParameterSetName = 'LogAnalyticsAgent')][switch]$ReInstall,
    [Parameter(mandatory = $true, ParameterSetName = 'LogAnalyticsAgent')] `
        [ValidateSet(
            "Australia East", "australiaeast",
            "Australia Central", "australiacentral",
            "Australia Central 2", "australiacentral2",
            "Australia Southeast", "australiasoutheast",
            "Brazil South", "brazilsouth",
            "Brazil Southeast", "brazilsoutheast",
            "Canada Central", "canadacentral",
            "Central India", "centralindia",
            "Central US", "centralus",
            "East Asia", "eastasia",
            "East US", "eastus",
            "East US 2", "eastus2",
            "East US 2 EUAP", "eastus2euap",
            "France Central", "francecentral",
            "France South", "francesouth",
            "Germany West Central", "germanywestcentral",
            "India South", "indiasouth",
            "Japan East", "japaneast",
            "Japan West", "japanwest",
            "Korea Central", "koreacentral",
            "North Central US", "northcentralus",
            "North Europe", "northeurope",
            "Norway East", "norwayeast",
            "Norway West", "norwaywest",
            "South Africa North", "southafricanorth",
            "Southeast Asia", "southeastasia",
            "South Central US", "southcentralus",
            "Switzerland North", "switzerlandnorth",
            "Switzerland West", "switzerlandwest",
            "UAE Central", "uaecentral",
            "UAE North", "uaenorth",
            "UK South", "uksouth",
            "West Central US", "westcentralus",
            "West Europe", "westeurope",
            "West US", "westus",
            "West US 2", "westus2",
            "USGov Arizona", "usgovarizona",
            "USGov Virginia", "usgovvirginia"
        )]
        [string]$WorkspaceRegion,
    [Parameter(mandatory = $false, ParameterSetName = 'AzureMonitoringAgent')][switch]$ProcessAndDependencies,
    [Parameter(mandatory = $true, ParameterSetName = 'AzureMonitoringAgent')][string]$DcrResourceId,
    [Parameter(mandatory = $true, ParameterSetName = 'AzureMonitoringAgent')][string]$UserAssignedManagedIdentityResourceGroup,
    [Parameter(mandatory = $true, ParameterSetName = 'AzureMonitoringAgent')][string]$UserAssignedManagedIdentityName
    )

# Log Analytics Extension constants
Set-Variable -Name mmaExtensionMap -Option Constant -Value @{ "Windows" = "MicrosoftMonitoringAgent"; "Linux" = "OmsAgentForLinux" }
Set-Variable -Name mmaExtensionVersionMap -Option Constant -Value @{ "Windows" = "1.0"; "Linux" = "1.6" }
Set-Variable -Name mmaExtensionPublisher -Option Constant -Value "Microsoft.EnterpriseCloud.Monitoring"
Set-Variable -Name mmaExtensionName -Option Constant -Value "MMAExtension"

# Azure Monitoring Agent ExtFension constants
Set-Variable -Name amaExtensionMap -Option Constant -Value @{ "Windows" = "AzureMonitorWindowsAgent"; "Linux" = "AzureMonitorLinuxAgent" }
Set-Variable -Name amaExtensionVersionMap -Option Constant -Value @{ "Windows" = "1.16"; "Linux" = "1.16" }
Set-Variable -Name amaExtensionPublisher -Option Constant -Value "Microsoft.Azure.Monitor"
Set-Variable -Name amaExtensionName -Option Constant -Value "AzureMonitoringAgent"

# Dependency Agent Extension constants
Set-Variable -Name daExtensionMap -Option Constant -Value @{"Windows" = "DependencyAgentWindows"; "Linux" = "DependencyAgentLinux" }
Set-Variable -Name daExtensionVersionMap -Option Constant -Value @{ "Windows" = "9.10"; "Linux" = "9.10" }
Set-Variable -Name daExtensionPublisher -Option Constant -Value "Microsoft.Azure.Monitoring.DependencyAgent"
Set-Variable -Name daExtensionName -Option Constant -Value "DA-Extension"
Set-Variable -Name processAndDependenciesPublicSettings -Option Constant -Value @{"enableAMA" = "true"}
Set-Variable -Name processAndDependenciesPublicSettingsRegexPattern -Option Constant -Value '"enableAMA"\s*:\s*"(\w+)"'

# Script Exception counters
Set-Variable -Name networkIssueToleranceLimit -Option Constant -Value 3
Set-Variable -Name serverIssueToleranceLimit -Option Constant -Value 3

# Script Util Constants
Set-Variable -Name UNAVAILABLE -Option Constant -Value 0
Set-Variable -Name invalidOperationParserPattern -Option Constant -Value "^Operation returned an invalid status code (.*)"
class InputParameterObsolete : System.Exception {
    [String]$errorMessage
    [Object]$innerExcepObj
    [String]$obsParamType
    InputParameterObsolete($message, $excepObj, $obsParamType) {
        $this.errorMessage = $message
        $this.innerExcepObj = $excepObj
        $this.obsParamType = $obsParamType
    }
}
class OperationFailed : System.Exception {
    [String]$errorMessage
    [Int32]$statusCode
    [String]$reasonPhrase
    OperationFailed($statusCode, $reasonPhrase, $errorMessage) {
        $this.statusCode = $statusCode
        $this.reasonPhrase = $reasonPhrase
        $this.errorMessage = $errorMessage
    }
}
class FatalException : System.Exception {
    [Object]$innerExcepObj
    [string]$errorMessage
    FatalException($message, $excepObj) {
        $this.errorMessage = $message
        $this.innerExcepObj = $excepObj
    }
}

#
# FUNCTIONS
#

function Parse-CloudExceptionMessage {
    param
    (
        [Parameter(mandatory = $true)][string]$excepMessage
    )
    $pattern = '^.*ErrorCode:\s+(.*)ErrorMessage:\s+(.*)ErrorTarget:\s+(.*)StatusCode:\s+(.*)ReasonPhrase:\s+(.*)OperationID\s+:(.*)$'
    $exceptionInfo = @{}
    $excepMessage = $excepMessage | ConvertTo-Json
    if ($excepMessage -match $pattern) {
        $exceptionInfo["errorCode"] = $matches[1]
        $exceptionInfo["errorMessage"] = $matches[2]
        $exceptionInfo["statusCode"] = $matches[4]
        $exceptionInfo["reasonPhrase"] = $matches[5]
    }   
    return $exceptionInfo
}

function Get-VMExtension {
    <#
	.SYNOPSIS
	Return the VM extension of specified ExtensionType
	#>
    param
    (
        [Parameter(mandatory = $true)][Object]$VMObject,
        [Parameter(mandatory = $true)][string]$ExtensionType,	
	    [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmResourceGroupName = $VMObject.ResourceGroupName
    $vmName = $VMObject.Name

    try {
        $extensions = Get-AzVMExtension -ResourceGroupName $vmResourceGroupName -VMName $vmName -ErrorAction "Stop"
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $exceptionInfo = Parse-CloudExceptionMessage($_.Exception.Message)
        if (!$exceptionInfo) {
            throw [FatalException]::new("$vmName ($vmResourceGroupName) : Failed to lookup extensions", $_)
        } else {
            if ($exceptionInfo["errorCode"].contains("ParentResourceNotFound")) {
                throw [InputParameterObsolete]::new("$vmName ($vmResourceGroupName) : Failed to lookup VM",$_,"VirtualMachine")
            } elseif($exceptionInfo["errorCode"].contains("ResourceGroupNotFound")) {
                throw [InputParameterObsolete]::new("Failed to lookup resource group in $vmResourceGroupName",$_,"ResourceGroup")       
            } else {
                throw [FatalException]::new("$vmName ($vmResourceGroupName) : Failed to lookup extensions", $_)
            }
        }
    }

    foreach ($extension in $extensions) {
        if ($ExtensionType -eq $extension.ExtensionType) {
            Write-Verbose("$vmName : Extension : $ExtensionType found")
            $extension
            return
        }
    }
    Write-Verbose("$vmName ($vmResourceGroupName) : Extension $ExtensionType not found")
}

function Get-VMssExtension {
    <#
	.SYNOPSIS
	Return the VMss extension of specified ExtensionType
	#>
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject,
        [Parameter(mandatory = $true)][string]$ExtensionType
    )

    $vmssName = $VMssObject.Name
    foreach ($extension in $VMssObject.VirtualMachineProfile.ExtensionProfile.Extensions) {
        if ($ExtensionType -eq $extension.Type) {
            Write-Verbose("$vmssName ($vmssResourceGroupName) : Extension: $ExtensionType found")
            $extension
            return
        }
    }
    Write-Verbose("$vmssName ($vmssResourceGroupName) : $ExtensionType not found")
}

function Remove-VMExtension {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(mandatory = $true)][Object]$VMObject,
        [Parameter(mandatory = $true)][string]$ExtensionType,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmResourceGroupName = $VMObject.ResourceGroupName
    $vmName = $VMObject.VMName
    $extension = Get-VMExtension -VMObject $VMObject -ExtensionType $ExtensionType -OnboardingStatus $OnboardingStatus
    if (!$extension) {
        Write-Verbose "$vmName ($vmResourceGroupName) : Failed to lookup $ExtensionType"
        return
    }
    $extensionName = $extension.Name

    if (!$PSCmdlet.ShouldProcess($vmName, "Remove OmsAgentForLinux")) {
        return
    }

    try {
        $removeResult = Remove-AzVMExtension -ResourceGroupName $vmResourceGroupName -VMName $vmName -Name $extensionName -Force -ErrorAction "Stop"
    } catch [System.Management.Automation.ParameterBindingException] {
        if ($_.ErrorId -eq "NamedParameterNotFound") {
            throw [InputParameterObsolete]::new("$vmResourceGroupName : Failed to lookup resource-group",$_,"ResourceGroup")
        } else {
            throw [FatalException]::new("$vmName ($vmResourceGroupName) : Failed to remove extension $extensionName", $_)
        }
    }
    
    if ($removeResult.IsSuccessStatusCode) {
        Write-Verbose "$vmName ($vmResourceGroupName) : Successfully removed $ExtensionType"
        return
    }

    $statusCode = $removeResult.StatusCode
    $reasonPhrase = $removeResult.ReasonPhrase
    throw [OperationFailed]::new($statusCode, $reasonPhrase, "$vmName ($vmResourceGroupName) : Failed to remove extension $extension")
}

function New-DCRAssociation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(mandatory = $true)][Object]$VMObject,
        [Parameter(mandatory = $true)][Object]$DcrResourceId,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmName = $VMObject.Name
    $vmResourceGroupName = $VMObject.ResourceGroupName
    $vmId = $VMObject.Id
    
    try {
        # A VM may have zero or more Data Collection Rule Associations
        $dcrAssociationList = Get-AzDataCollectionRuleAssociation -TargetResourceId $vmId -ErrorAction "Stop"
    } catch [System.Management.Automation.ParameterBindingException] {
        throw [InputParameterObsolete]::new("$vmName ($vmResourceGroupName) : Failed to lookup VM",$_,"VirtualMachine")
    }

    # A VM may have zero or more Data Collection Rule Associations
    foreach ($dcrAssociation in $dcrAssociationList) {
        if ($dcrAssociation.DataCollectionRuleId -eq $DcrResourceId) {
            Write-Output "$vmName ($vmResourceGroupName) : Data Collection Rule already associated under $($dcrAssociation.Name)"
            return
        }
    }

    #The Customer is responsible to uninstall the DCR Association themselves
    if (!($PSCmdlet.ShouldProcess($vmName, "Install Data Collection Rule Association. (NOTE : Customer is responsible for uninstalling a data collection rule association)"))) {
        return
    }

    $dcrassociationName = "VM-Insights-$vmName-Association"
    Write-Verbose "$vmName ($vmResourceGroupName) : Deploying Data Collection Rule Association with name $dcrassociationName"
    try {
        $dcrassociation = New-AzDataCollectionRuleAssociation -TargetResourceId $vmId -AssociationName $dcrassociationName -RuleId $DcrResourceId -ErrorAction "Stop"
    } catch [System.Management.Automation.PSInvalidOperationException] {
        $exceptionMessage = $_.Exception.InnerException.Message
        
        if ($exceptionMessage.Contains('Invalid format of the resource identifier')) {
            throw "$DcrResourceId : DataCollectionRule is in wrong format"
        }
        elseif (!($exceptionMessage -match $invalidOperationParserPattern)){
            throw [FatalException]::new("$vmName ($vmResourceGroupName) : Failed to create data collection rule association for $DcrResourceId", $_)
        } else {
            $statusCode = $matches[1]
            if ($statusCode.Contains('BadRequest')) {
                throw [InputParameterObsolete]::new("$DcrResourceId : Failed to lookup dataCollectionRule",$_,"DataCollectionRule")
            } elseif ($statusCode.Contains('NotFound')) {
                throw [InputParameterObsolete]::new("$vmName ($vmResourceGroupName) : Failed to lookup VM",$_,"VirtualMachine")
            } elseif ($statusCode.Contains('Forbidden')) {
                throw [InputParameterObsolete]::new("$DcrResourceId : Failed to access dataCollectionRule",$_,"DataCollectionRule")     
            } else {
                throw [FatalException]::new("$DcrResourceId : Failed to lookup dataCollectionRule. UnknownStatusCode = $statusCode", $_)
            }
        }
    }
    #Tmp fix task:- 21191002
    if (!$dcrassociation -or $dcrassociation -is [Microsoft.Azure.Management.Monitor.Models.ErrorResponseCommonV2Exception]) {
        throw [FatalException]::new("$vmName ($vmResourceGroupName) : Failed to create data collection rule association for $DcrResourceId", $_)
    }
}

function Onboard-VmiWithMmaVm {
    <#
	.SYNOPSIS
	Onboard VMI with MMA on Vms
	#>
    param
    (
        [Parameter(mandatory = $true)][Object]$VMObject,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus,
        [Parameter(mandatory = $true)][hashtable]$OnboardParameters    
    )

    $vmName = $VMObject.Name
    $vmResourceGroupName = $VMObject.ResourceGroupName
    $workspaceId = $OnboardParameters.WorkspaceID
    $workspacekey = $OnboardParameters.WorkspaceKey
    $reInstall = $OnboardParameters.ReInstall

    Install-MmaVm -VMObject $VMObject `
                  -WorkspaceId $workspaceId `
                  -WorkspaceKey $workspacekey `
                  -ReInstall $reInstall `
                  -OnboardingStatus $OnboardingStatus

    Install-DaVm -VMObject $VMObject `
                 -OnboardingStatus $OnboardingStatus

    #reached this point - indicates all previous deployments succeeded
    $message = "$vmName ($vmResourceGroupName) : Successfully onboarded VMInsights"
    Write-Output $message
    $OnboardingStatus.Succeeded += $message
}

function Onboard-VmiWithMmaVmss {
    <#
	.SYNOPSIS
	Onboard VMI with MMA on Vmss
	#>
    param
    (
        [Parameter(mandatory = $true)][Object]$VMssObject,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus,
        [Parameter(mandatory = $true)][hashtable]$OnboardParameters    
    )

    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    $workspaceId = $OnboardParameters.WorkspaceID
    $workspacekey = $OnboardParameters.WorkspaceKey
    $reInstall = $OnboardParameters.ReInstall

    Install-MmaVmss -VMssObject $VMssObject `
                    -WorkspaceId $workspaceId `
                    -WorkspaceKey $workspacekey `
                    -ReInstall $reInstall `
                    -OnboardingStatus $OnboardingStatus

    Install-DaVmss -VMssObject $VMssObject `
                   -OnboardingStatus $OnboardingStatus

    #reached this point - indicates all previous deployments succeeded
    $message = "$vmssName ($vmssResourceGroupName) : Successfully onboarded VMInsights"
    Write-Output $message
    $OnboardingStatus.Succeeded += $message
}

function Onboard-VmiWithAmaVm {
    <#
	.SYNOPSIS
	Onboard VMI with AMA on Vms
	#>
    param
    (
        [Parameter(mandatory = $true)][Object]$VMObject,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus,
        [Parameter(mandatory = $true)][hashtable]$OnboardParameters
    )
    
    $amaPublicSettings = @{'authentication' = @{
        'managedIdentity' = @{
        'identifier-name' = 'mi_res_id'
        }
      }
    }
    $dcrResourceId = $OnboardParameters.DcrResourceId
    $userAssignedManagedIdentityObject = $OnboardParameters.UserAssignedIdentityObject
    $processAndDependencies = $OnboardParameters.ProcessAndDependencies
    $vmName = $VMObject.Name
    $vmResourceGroupName = $VMObject.ResourceGroupName

    Assign-VmUserManagedIdentity -VMObject $VMObject `
                             -UserAssignedManagedIdentityObject $userAssignedManagedIdentityObject `
                             -AmaPublicSettings $amaPublicSettings `
                             -OnboardingStatus $OnboardingStatus
    
    Install-AmaVm -VMObject $VMObject `
                  -AmaPublicSettings $amaPublicSettings `
                  -OnboardingStatus $OnboardingStatus

    if ($processAndDependencies) {
        Install-DaVm -VMObject $VMObject `
                    -IsAmaOnboarded `
                    -OnboardingStatus $OnboardingStatus                
    }

    New-DCRAssociation `
                  -VMObject $VMObject `
                  -DcrResourceId $dcrResourceId `
                  -OnboardingStatus $OnboardingStatus

    #reached this point - indicates all previous deployments succeeded
    $message = "$vmName ($vmResourceGroupName) : Successfully onboarded VMInsights"
    Write-Output $message
    $OnboardingStatus.Succeeded += $message
}

function Onboard-VmiWithAmaVmss {
    <#
	.SYNOPSIS
	Onboard VMI with AMA on VMSS
	#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $true)][Object]$VMssObject,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus,
        [Parameter(mandatory = $true)][hashtable]$OnboardParameters
    )

    $amaPublicSettings = @{'authentication' = @{
        'managedIdentity' = @{
        'identifier-name' = 'mi_res_id'
        }
      }
    }
    $dcrResourceId = $OnboardParameters.DcrResourceId
    $userAssignedManagedIdentityObject = $OnboardParameters.UserAssignedIdentityObject
    $processAndDependencies = $OnboardParameters.ProcessAndDependencies
    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
            
    Assign-VmssManagedIdentity -VMssObject $VMssObject `
                               -UserAssignedManagedIdentityObject $userAssignedManagedIdentityObject `
                               -AmaPublicSettings $amaPublicSettings `
                               -OnboardingStatus $OnboardingStatus
        
    Install-AmaVmss -VMssObject $VMssObject `
                    -AmaPublicSettings $amaPublicSettings `
                    -OnboardingStatus $OnboardingStatus

    if ($ProcessAndDependencies) {
        Install-DaVmss -VMssObject $VMssObject `
                       -IsAmaOnboarded `
                       -OnboardingStatus $OnboardingStatus                
    }

    New-DCRAssociation `
                  -VMObject $VMssObject `
                  -DcrResourceId $dcrResourceId `
                  -OnboardingStatus $OnboardingStatus

    #reached this point - indicates all previous deployments succeeded
    $message = "$vmssName ($vmssResourceGroupName) : Successfully onboarded VMInsights"
    Write-Output $message
    $OnboardingStatus.Succeeded += $message
}

function Install-DaVm {
    <#
	.SYNOPSIS
	Install DA (VM), handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $true)][Object]$VMObject,
        [Parameter(mandatory = $true)][Switch]$IsAmaOnboarded,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmName = $VMObject.Name
    $vmLocation = $VMObject.Location
    $vmResourceGroupName = $VMObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $daExtensionName
    $osType = $VMObject.StorageProfile.OsDisk.OsType
    $extensionType = $daExtensionMap.($osType.ToString())
    $extension = Get-VMExtension -VMObject $VMObject -ExtensionType $extensionType -OnboardingStatus $OnboardingStatus
    
    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "$vmName ($vmResourceGroupName) : Extension $extensionType with name $extensionName already installed. Provisioning State: $($extension.ProvisioningState)"
        if (!$IsAmaOnboarded) {
            return
        } else {
            if ($extension.PublicSettings) {
                if ($extension.PublicSettings -match $processAndDependenciesPublicSettingsRegexPattern -and $matches[1] -eq "true") {
                    Write-Output "$vmName ($vmResourceGroupName) : Extension $extensionType already configured with AMA enabled. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
                    return
                }
            }   
        }
    }
    
    if (!($PSCmdlet.ShouldProcess($vmName, "install extension $extensionType"))) {
        return
    }

    $parameters = @{
        ResourceGroupName  = $vmResourceGroupName
        VMName             = $vmName
        Location           = $vmLocation
        Publisher          = $daExtensionPublisher
        ExtensionType      = $extensionType
        ExtensionName      = $extensionName
        TypeHandlerVersion = $daExtensionVersionMap.($osType.ToString())
        ForceRerun         = $True
    }

    if ($IsAmaOnboarded) {
        $parameters.Add("Settings", $processAndDependenciesPublicSettings)
    }

    Install-VMExtension -InstallParameters $parameters -OnboardingStatus $OnboardingStatus
}

function Install-DaVmss {
    <#
	.SYNOPSIS
	Install DA (VM), handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $true)][Object]$VMssObject,
        [Parameter(mandatory = $true)][Switch]$IsAmaOnboarded,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )
    
    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $daExtensionName
    $osType = $VMssObject.VirtualMachineProfile.StorageProfile.OsDisk.OsType
    $extensionType = $daExtensionMap.($osType.ToString())
    $extension = Get-VMssExtension -VMssObject $VMssObject -ExtensionType $extensionType -OnboardingStatus $OnboardingStatus
    
    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "$vmssName ($vmssResourceGroupName) : Extension $extensionType with name $extensionName already installed. Provisioning State: $($extension.ProvisioningState)"
        if (!$IsAmaOnboarded) {
            return
        } else {
            if ($extension.PublicSettings) {
                if ($extension.PublicSettings -match $processAndDependenciesPublicSettingsRegexPattern -and $matches[1] -eq "true") {
                    Write-Output "$vmssName ($vmssResourceGroupName) : Extension $extensionType already configured with AMA enabled. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
                    return
                }
            }
        }
    }
    
    if (!($PSCmdlet.ShouldProcess($vmssName, "install extension $extensionType"))) {
        return
    }

    $parameters = @{
        VirtualMachineScaleSet = $VMssObject
        Name                   = $vmssName
        Publisher              = $daExtensionPublisher
        Type                   = $extensionType
        ExtensionName          = $extensionName
        TypeHandlerVersion     = $daExtensionVersionMap.($osType.ToString())
        AutoUpgradeMinorVersion = $True
    }

    if ($IsAmaOnboarded) {
        $parameters.Add("Setting", $processAndDependenciesPublicSettings)
    }

    Install-VMssExtension -InstallParameters $parameters -OnboardingStatus $OnboardingStatus
}

function Install-AmaVm {
    <#
	.SYNOPSIS
	Install AMA (VMSS), handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $true)][Object]$VMObject,
        [Parameter(mandatory = $true)][hashtable]$AmaPublicSettings,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmName = $VMObject.Name
    $vmLocation = $VMObject.Location
    $vmResourceGroupName = $VMObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $amaExtensionName
    $osType = $VMObject.StorageProfile.OsDisk.OsType
    $extensionType = $amaExtensionMap.($osType.ToString())
    $extension = Get-VMExtension -VMObject $VMObject -ExtensionType $extensionType -OnboardingStatus $OnboardingStatus
    
    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "$vmName ($vmResourceGroupName) : Extension $extensionType with name $extensionName already installed. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
        if ($extension.PublicSettings) {
            if ($extension.PublicSettings.Contains($AmaPublicSettings.authentication.managedIdentity.'identifier-value')) {
                Write-Output "$vmName ($vmResourceGroupName) : Extension $extensionType already configured with this user assigned managed identity. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
                return
            }
        }
    }
    
    if (!($PSCmdlet.ShouldProcess($VMName, "install extension $ExtensionType"))) {
        return
    }

    $parameters = @{
        ResourceGroupName  = $vmResourceGroupName
        VMName             = $vmName
        Location           = $vmLocation
        Publisher          = $amaExtensionPublisher
        ExtensionType      = $extensionType
        ExtensionName      = $extensionName
        TypeHandlerVersion = $amaExtensionVersionMap.($osType.ToString())
        ForceRerun         = $True
        Settings           = $AmaPublicSettings
    }

    Install-VMExtension -InstallParameters $parameters -OnboardingStatus $OnboardingStatus 
}

function Install-MmaVm {
    <#
	.SYNOPSIS
	Install LA Extension on Virtual Machines, handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $true)][Object]$VMObject,
        [Parameter(mandatory = $true)][String]$WorkspaceId,
        [Parameter(mandatory = $true)][String]$WorkspaceKey,
        [Parameter(mandatory = $false)][Switch]$ReInstall,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmName = $VMObject.Name
    $vmLocation = $VMObject.Location
    $vmResourceGroupName = $VMObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $mmaExtensionName
    $extensionType = $mmaExtensionMap.($osType.ToString())
    $extension = Get-VMExtension -VMObject $VMObject -ExtensionType $extensionType -OnboardingStatus $OnboardingStatus
    $mmaPublicSettings = @{"workspaceId" = $WorkspaceId; "stopOnMultipleConnections" = "true"}
    $mmaProtectedSettings = @{"workspaceKey" = $WorkspaceKey}
    $osType = $VMObject.StorageProfile.OsDisk.OsType

    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "$vmName ($vmResourceGroupName) : Extension $extensionType with name $extensionName already installed. Provisioning State: $($extension.ProvisioningState)"
        if ($extension.PublicSettings) {
            if ($extension.PublicSettings.Contains($MmaPublicSettings.workspaceId)) {
                Write-Output "$vmName ($vmResourceGroupName) : Extension $extensionType already configured for this workspace. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
                return
            } else {
                if (!$ReInstall) {
                    Write-Output "$vmName ($vmResourceGroupName) : Extension $extensionType present, run with -ReInstall again to move to new workspace. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
                    return
                }
            }
        }
    }

    if ($extensionType -eq "OmsAgentForLinux") {
        Write-Output "$vmName ($vmssResourceGroupName) : ExtensionType $extensionType does not support updating workspace. An uninstall followed by re-install is required"
    }

    if (!($PSCmdlet.ShouldProcess($VMName, "install extension $extensionType"))) {
        return
    }

    $parameters = @{
        ResourceGroupName  = $vmResourceGroupName
        VMName             = $vmName
        Location           = $vmLocation
        Publisher          = $mmaExtensionPublisher
        ExtensionType      = $extensionType
        ExtensionName      = $extensionName
        TypeHandlerVersion = $mmaExtensionVersionMap.($osType.ToString())
        ForceRerun         = $True
        Settings           = $mmaPublicSettings
        ProtectedSettings  = $mmaProtectedSettings
    }

    if ($ExtensionType -eq "OmsAgentForLinux") {
        Remove-VMExtension -VMObject $VMObject `
                            -ExtensionType $extensionType `
                            -OnboardingStatus $OnboardingStatus
    }

    Install-VMExtension -InstallParameters $parameters -OnboardingStatus $OnboardingStatus 
}

function Install-AmaVMss {
    <#
	.SYNOPSIS
	Install AMA (VMSS), handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)][Object]$VMssObject,
        [Parameter(mandatory = $true)][hashtable]$AmaPublicSettings,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $amaExtensionName
    $osType = $VMssObject.VirtualMachineProfile.StorageProfile.OsDisk.OsType
    $extensionType = $amaExtensionMap.($osType.ToString())
    # Use supplied name unless already deployed, use same name
    $extension = Get-VMssExtension -VMss $VMssObject -ExtensionType $extensionType
    
    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "$vmssName ($vmssResourceGroupName) : Extension $extensionType with name $extensionName already installed. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
        if ($extension.PublicSettings) {
            if ($extension.PublicSettings.Contains($AmaPublicSettings.authentication.managedIdentity.'identifier-value')) {
                Write-Output "$vmName ($vmssResourceGroupName) : Extension $extensionType already configured with this user assigned managed identity. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
                return
            }
        }
    }
    

    if (!($PSCmdlet.ShouldProcess($vmssName, "install extension $extensionType"))) {
        return
    }

    $parameters = @{
        VirtualMachineScaleSet  = $VMssObject
        Name                    = $vmssName
        Publisher               = $amaExtensionPublisher
        Type                    = $extensionType
        ExtensionName           = $extensionName
        TypeHandlerVersion      = $amaExtensionVersionMap.($osType.ToString())
        Setting                 = $AmaPublicSettings
        AutoUpgradeMinorVersion = $True
    }

    Install-VMssExtension -InstallParameters $parameters -OnboardingStatus $OnboardingStatus   
}

function Install-MmaVMss {
    <#
	.SYNOPSIS
	Install AMA (VMSS), handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)][Object]$VMssObject,
        [Parameter(Mandatory = $true)][String]$WorkspaceId,
        [Parameter(Mandatory = $true)][String]$WorkspaceKey,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $mmaExtensionName
    $osType = $VMssObject.VirtualMachineProfile.StorageProfile.OsDisk.OsType
    $extensionType = $amaExtensionMap.($osType.ToString())
    # Use supplied name unless already deployed, use same name
    $extension = Get-VMssExtension -VMss $VMssObject -ExtensionType $extensionType
    $mmaPublicSettings = @{"workspaceId" = $WorkspaceId; "stopOnMultipleConnections" = "true"}
    $mmaProtectedSettings = @{"workspaceKey" = $WorkspaceKey}
    
    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "$vmssName ($vmssResourceGroupName) : Extension $extensionType with name $extensionName already installed. Provisioning State: $($extension.ProvisioningState)"
        if ($extension.PublicSettings) {
            if ($extension.PublicSettings.Contains($MmaPublicSettings.workspaceId)) {
                Write-Output "$vmssName ($vmssResourceGroupName) : Extension $extensionType already configured for this workspace. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
                return
            } else {
                if (!$ReInstall) {
                    Write-Output "$vmssName ($vmssResourceGroupName) : Extension $extensionType present, run with -ReInstall again to move to new workspace. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
                    return
                }
            }
        }
    }

    if (!($PSCmdlet.ShouldProcess($vmssName, "install extension $extensionType"))) {
        return
    }

    $parameters = @{
        VirtualMachineScaleSet  = $VMssObject
        Name                    = $vmssName
        Publisher               = $mmaExtensionPublisher
        Type                    = $extensionType
        ExtensionName           = $extensionName
        TypeHandlerVersion      = $mmaExtensionVersionMap.($osType.ToString())
        Setting                 = $mmaPublicSettings
        ProtectedSetting       = $mmaProtectedSettings
    }

    Install-VMssExtension -InstallParameters $parameters -OnboardingStatus $OnboardingStatus
}

function Set-ManagedIdentityRoles {
    
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)][String]$TargetScope,
        [Parameter(Mandatory = $true)][Object]$UserAssignedManagedIdentityObject
    )

    $userAssignedManagedIdentityName = $UserAssignedManagedIdentityObject.Name
    $userAssignedManagedIdentityId = $UserAssignedManagedIdentityObject.principalId

    $roleDefinitionList = @("Virtual Machine Contributor", "Azure Connected Machine Resource Administrator", "Log Analytics Contributor") 
    
    if (!($PSCmdlet.ShouldProcess($vmResourceGroupName, "assign roles : $roleDefinitionList to user assigned managed identity : $userAssignedManagedIdentityName"))) {
        return
    }

    foreach ($role in $roleDefinitionList) {
        $roleAssignmentFound = Get-AzRoleAssignment -ObjectId $userAssignedManagedIdentityId -RoleDefinitionName $role -Scope $TargetScope
        if ($roleAssignmentFound) {
            Write-Verbose "Scope $targetScope : role $role already set"
        } else {
            Write-Verbose("Scope $targetScope : assigning role $role")
            try {
                New-AzRoleAssignment  -ObjectId $userAssignedManagedIdentityId -RoleDefinitionName $role -Scope $targetScope
                Write-Verbose "Scope $targetScope : role assignment for $userAssignedManagedIdentityName with $role succeeded"
            }
            catch [ErrorResponseException] {
                $excepMessage = $_.Message
                if ($excepMessage -contains 'Conflict') {
                    Write-Verbose ("$userAssignedManagedIdentityName : $role has been assigned already")
                } elseif ($excepMessage -contains 'BadRequest') {
                    throw [InputParameterObsolete]::new("$userAssignedManagedIdentityName : Failed to lookup managed identity",$_,"UserAssignedManagedIdentity") 
                } elseif ($excepMessage -contains 'NotFound') {
                    throw [InputParameterObsolete]::new("$userAssignedManagedIdentityName : Failed to lookup $TargetScope",$_,"ResourceGroup") 
                } else {
                    throw [FatalException]::new("$TargetScope : Failed to assign managed identity to targetScope", $_)
                }
            }
        }
    }
}

function Install-VMExtension {
    <#
	.SYNOPSIS
	Install VM Extension, handling if already installed
	#>
    param
    (
        [Parameter(mandatory = $true)][hashtable]$InstallParameters,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmName = $InstallParameters.VMName
    $vmResourceGroupName = $InstallParameters.ResourceGroupName
    $extensionType = $InstallParameters.ExtensionType
    
    Write-Verbose("$vmName ($vmResourceGroupName) : Deploying/Updating $extensionType")
    try {
        $result = Set-AzVMExtension @InstallParameters -ErrorAction "Stop"
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $exceptionInfo = Parse-CloudExceptionMessage($_.Message)
        if (!$exceptionInfo) {
            throw [FatalException]::new("$vmName ($vmResourceGroupName) : Failed to update/install extension : $extensionType", $_)
        } else {
            if ($exceptionInfo["errorCode"].contains("ParentResourceNotFound")) {
                throw [InputParameterObsolete]::new("$vmName ($vmResourceGroupName) : Failed to lookup VM",$_,"VirtualMachine")
            } elseif($exceptionInfo["errorCode"].contains("ResourceGroupNotFound")) {
                throw [InputParameterObsolete]::new("$vmResourceGroupName : Failed to lookup resource group",$_,"ResourceGroup")       
            } else {
                $extensionType = $InstallParameters.ExtensionType
                throw [FatalException]::new("$vmName ($vmResourceGroupName) : Failed to update/install extension : $extensionType", $_)
            }
        }
    }
    
    if ($result.IsSuccessStatusCode) {
        Write-Output "$vmName ($vmResourceGroupName) : Successfully deployed/updated $extensionType"
        return
    }

    $statusCode = $removeResult.StatusCode
    $reasonPhrase = $removeResult.ReasonPhrase
    throw [OperationFailed]::new($statusCode, $reasonPhrase, "$vmName ($vmResourceGroupName) : Failed to update extension $extensionType")
}

function Install-VMssExtension {
    <#
	.SYNOPSIS
	Install VMss Extension, handling if already installed
	#>
    param
    (
        [Parameter(mandatory = $true)][hashtable]$InstallParameters,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $extensionType = $InstallParameters.Type
    $vmssName = $InstallParameters.VirtualMachineScaleSet.Name
    $vmssResourceGroupName = $InstallParameters.VirtualMachineScaleSet.ResourceGroupName
    Write-Verbose("$vmssName : Adding $extensionType with name $extensionName")
    $VMssObject = Add-AzVmssExtension @InstallParameters
    Write-Verbose("$vmssName : Updating scale set with $extensionType extension")
    try {
        $VMssObject = Update-AzVmss -VMScaleSetName $vmssName `
                                    -ResourceGroupName $vmssResourceGroupName `
                                    -VirtualMachineScaleSet $VMssObject `
                                    -ErrorAction "Stop"
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $exceptionInfo = Parse-CloudExceptionMessage($_.Message)
        if (!$exceptionInfo) {
            throw [FatalException]::new("$vmssName ($vmssResourceGroupName) : Failed to update/install extension $extensionType", $_)
        } else {
            if ($exceptionInfo["errorCode"].contains("ParentResourceNotFound")) {
                throw [InputParameterObsolete]::new("$vmssName ($vmssResourceGroupName) : Failed to lookup VMSS",$_,"VirtualMachineScaleSet")
            } elseif($exceptionInfo["errorCode"].contains("ResourceGroupNotFound")) {
                throw [InputParameterObsolete]::new("$vmssResourceGroupName : Failed to lookup resource group",$_,"ResourceGroup")       
            } else {
                throw [FatalException]::new("$vmssName ($vmssResourceGroupName) : Failed to update/install extension", $_)
            }
        }
    }
    
    if ($VMssObject.ProvisioningState -eq "Succeeded") {
        Write-Output "$vmssName ($vmssResourceGroupName) : Successfully updated scale set with extension $extensionType"
        return
    }

    throw [OperationFailed]::new($UNAVAILABLE,$UNAVAILABLE,"$vmssName ($vmssResourceGroupName) : Failed to update extension extension $extensionType")
}

function Check-UserManagedIdentityAlreadyAssigned {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)][Object]$VMObject,
        [Parameter(Mandatory = $true)][string]$UserAssignedManagedIdentyId
    )

    if ($VMObject.Identity.Type -eq "UserAssigned") {
        $userAssignedIdentitiesList = $VMObject.Identity.UserAssignedIdentities
        foreach ($userAssignDict in $userAssignedIdentitiesList) {
            if ($userAssignDict.Keys -eq $UserAssignedManagedIdentyId) {
                return $True
            }
        }
    }

    return $False
}

function Assign-VmssManagedIdentity {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)][Object]$VMssObject,
        [Parameter(Mandatory = $true)][Object]$UserAssignedManagedIdentityObject,
        [Parameter(mandatory = $true)][hashtable]$AmaPublicSettings,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmssName = $VMssObject.Name
    $vmssResourceGroup = $VMssObject.ResourceGroupName
    $userAssignedManagedIdentityName = $UserAssignedManagedIdentityObject.Name
    $userAssignedManagedIdentityId = $UserAssignedManagedIdentityObject.Id

    if (Check-UserManagedIdentityAlreadyAssigned -VMObject $VMssObject `
                                                 -UserAssignedManagedIdentyId $userAssignedManagedIdentityId) {
        Write-Verbose "$vmssName ($vmssResourceGroup) : Already assigned with user managed identity : $userAssignedManagedIdentityName"
    } else {
        if (!($PSCmdlet.ShouldProcess($vmssName, "assign managed identity $userAssignedManagedIdentityName"))) {
            return
        }

        try {
            $result = Update-AzVmss -VirtualMachineScaleSet $VMssObject `
                                    -ResourceGroupName $vmssResourceGroup `
                                    -IdentityType "UserAssigned" `
                                    -IdentityID $userAssignedManagedIdentityId `
                                    -ErrorAction "Stop"
        } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
            $exceptionInfo = Parse-CloudExceptionMessage($_.Message)
            if (!$exceptionInfo) {
                throw [FatalException]::new("$vmssName ($vmssResourceGroup) : Failed to assign user managed identity : $userAssignedManagedIdentityName", $_)
            } else {
                if ($exceptionInfo["errorCode"].contains("FailedIdentityOperation")) {
                    throw [InputParameterObsolete]::new("$userAssignedManagedIdentityName : Failed to lookup managed identity",$_,"UserAssignedManagedIdentity")
                } elseif($exceptionInfo["errorCode"].contains("ResourceGroupNotFound")) {
                    throw [InputParameterObsolete]::new("$vmssResourceGroup : Failed to lookup resource group",$_,"ResourceGroup")       
                } elseif ($exceptionInfo["errorCode"].contains("InvalidParameter") -and $exceptionInfo["errorMessage"].contains("Parameter 'osDisk.managedDisk.id' is not allowed")) {
                    throw [InputParameterObsolete]::new("$vmssName ($vmssResourceGroup)  : Failed to lookup VMSS",$_,"VirtualMachine") 
                }
                else {
                    throw [FatalException]::new("vmssName ($vmssResourceGroup) : Failed to assign managed identity : $userAssignedManagedIdentityName. ExceptionInfo = $exceptionInfo", $_)
                }
            }
        }

        if ($result -and $result.IsSuccessStatusCode) {
            Write-Output "$vmScaleSetName : Successfully assigned user managed identity : $userAssignedManagedIdentityName"
            return
        }

        $statusCode = $result.StatusCode
        $reasonPhrase = $result.ReasonPhrase
        throw [OperationFailed]::new($statusCode,$reasonPhrase,"$vmssName : Failed to assign user assigned managed identity $userAssignedManagedIdentityName")
    }

    ##Assign Managed identity to Azure Monitoring Agent
    $AmaPublicSettings.authentication.managedIdentity.'identifier-value' = $UserAssignedManagedIdentityObject.Id
}

function Assign-VmUserManagedIdentity {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)][Object]$VMObject,
        [Parameter(Mandatory = $true)][Object]$UserAssignedManagedIdentityObject,
        [Parameter(mandatory = $true)][hashtable]$AmaPublicSettings,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmName = $VMObject.Name
    $vmResourceGroup = $VMObject.ResourceGroupName
    $userAssignedManagedIdentityName = $UserAssignedManagedIdentityObject.Name
    $userAssignedManagedIdentityId = $UserAssignedManagedIdentityObject.Id

    if (Check-UserManagedIdentityAlreadyAssigned -VMObject $VMObject `
                                                 -UserAssignedManagedIdentyId $userAssignedManagedIdentityId) {
        Write-Verbose "$vmName ($vmResourceGroup) : Already assigned with managed identity : $userAssignedManagedIdentityName"
    } else {
        if (!($PSCmdlet.ShouldProcess($vmName, "assign managed identity $userAssignedManagedIdentityName"))) {
            return
        }

        try {
            $result = Update-AzVM -VM $VMObject `
                                  -ResourceGroupName $vmResourceGroup `
                                  -IdentityType "UserAssigned" `
                                  -IdentityID $userAssignedManagedIdentityId `
                                  -ErrorAction "Stop"                              
        } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
            $exceptionInfo = Parse-CloudExceptionMessage($_.Message)
            if (!$exceptionInfo) {
                throw [FatalException]::new("$vmName : Failed to assign user managed identity : $userAssignedManagedIdentityName.", $_)
            } else {
                if ($exceptionInfo["errorCode"].contains("FailedIdentityOperation")) {
                    throw [InputParameterObsolete]::new("$userAssignedManagedIdentityName : Failed to lookup managed identity",$_,"UserAssignedManagedIdentity")
                } elseif($exceptionInfo["errorCode"].contains("ResourceGroupNotFound")) {
                    throw [InputParameterObsolete]::new("$vmResourceGroupName : Failed to lookup resource group",$_,"ResourceGroup")       
                } elseif ($exceptionInfo["errorCode"].contains("InvalidParameter") -and $exceptionInfo["errorMessage"].contains("Parameter 'osDisk.managedDisk.id' is not allowed")) {
                    throw [InputParameterObsolete]::new("$vmName ($vmResourceGroup) : Failed to lookup VM",$_,"VirtualMachine") 
                }
                else {
                    throw [FatalException]::new("$vmName : Failed to assign managed identity : $userAssignedManagedIdentityName. Exception Info = $exceptionInfo", $_)
                }
            }
        }
    
        if ($result.IsSuccessStatusCode) {
            Write-Output "$vmName : Successfully assigned managed identity : $userAssignedManagedIdentityName"
            return
        }
       
        $statusCode = $result.StatusCode
        $reasonPhrase = $result.ReasonPhrase
        throw [OperationFailed]::new($statusCode,$reasonPhrase,"$vmName : Failed to assign user assigned managed identity $userAssignedManagedIdentityName")
    }

    ##Assign Managed identity to Azure Monitoring Agent
    $AmaPublicSettings.authentication.managedIdentity.'identifier-value' = $UserAssignedManagedIdentityObject.Id
}

function Display-Exception {
    param(
    [Parameter(Mandatory = $true)][Object]$ExcepObj
    )
    try {
        try { "ExceptionClass = $($ExcepObj.Exception.GetType().Name)" | Write-Output } catch { }
        try { "ExceptionMessage:`r`n$($ExcepObj.Exception.Message)`r`n" | Write-Output } catch { }
        try { "StackTrace:`r`n$($ExcepObj.Exception.StackTrace)`r`n" | Write-Output } catch { }
        try { "ScriptStackTrace:`r`n$($ExcepObj.ScriptStackTrace)`r`n" | Write-Output } catch { }
        try { "Exception.HResult = 0x{0,0:x8}" -f $ExcepObj.Exception.HResult | Write-Output } catch { }
    }
    catch {
        #silently ignore
    }
}

#
# Main Script
#
#
# First make sure we are authenticed and Select the subscription supplied and input parameters are valid.
#
try {
    $account =  Get-AzContext
    if ($null -eq $account.Account) {
        Write-Output "Account Context not found, please login"
        Connect-AzAccount -subscriptionid $SubscriptionId
    }
    else {
        if ($account.Subscription.Id -eq $SubscriptionId) {
            Write-Verbose "Subscription: $SubscriptionId is already selected."
            $account
        }
        else {
            Write-Output "Current Subscription:"
            $account
            Write-Output "Changing to subscription: $SubscriptionId"
            Select-AzSubscription -SubscriptionId $SubscriptionId
        }
    }

    #Script Parameter Validation
    if ($DcrResourceId) {
        #VMI supports Customers onboarding DCR from different subscription
        #Cannot validate DCRResourceId as parameter set ByResourceId will be deprecated for - Get-AzDataCollectionRule
        try {
            Write-Output "Validating ($UserAssignedManagedIdentityName,$UserAssignedManagedIdentityResourceGroup)"
            $userAssignedIdentityObject = Get-AzUserAssignedIdentity -Name $UserAssignedManagedIdentityName `
                                    -ResourceGroupName $UserAssignedManagedIdentityResourceGroup `
                                    -ErrorAction "Stop"
        } catch [Exception]{
            Write-Output $_.Exception.Message
            exit
        }
        $OnboardParameters = @{ "DcrResourceId" = $DcrResourceId ; "UserAssignedIdentityObject" =  $userAssignedIdentityObject; "ProcessAndDependencies" = $ProcessAndDependencies}
    } else {
        #Cannot validate WorkspaceId, WorkspaceKey with the below parameters
        #Verification requires name of workspacename and resourcegroup
        #MMA proceeding to Deprecate, not adding extra parameters for just verification.
        $OnboardParameters = @{ "WorkspaceId" = $WorkspaceId ; "WorkspaceKey" =  $WorkspaceKey ; "ReInstall" = $ReInstall}
    }

    $Vms = @()
    $Vmss = @()
    $networkIssueCounter = 0
    $serverIssueCounter = 0

    # To report on overall status
    $OnboardingSucceeded = @()
    $OnboardingFailed = @()
    $OnboardingBlockedNotRunning = @()
    $VMScaleSetNeedsUpdate = @()
    $OnboardingStatus = @{
        Succeeded             = $OnboardingSucceeded;
        Failed                = $OnboardingFailed;
        NotRunning            = $OnboardingBlockedNotRunning;
        VMScaleSetNeedsUpdate = $VMScaleSetNeedsUpdate;
    }


    if ($PolicyAssignmentName) {
        Write-Output "Getting list of VM's from PolicyAssignmentName: $($PolicyAssignmentName)"
        $complianceResults = Get-AzPolicyState -PolicyAssignmentName $PolicyAssignmentName -ErrorAction "Stop"

        foreach ($result in $complianceResults) {
            Write-Verbose($result.ResourceId)
            Write-Verbose($result.ResourceType)
            if ($result.SubscriptionId -ne $SubscriptionId) {
                Write-Output "VM is not in same subscription, this scenario is not currently supported. Skipping this VM."
            }

            $vmName = $result.ResourceId.split('/')[8]
            $vmResourceGroup = $result.ResourceId.split('/')[4]

            # Skip if ResourceGroup or Name provided, but does not match
            if ($ResourceGroup -and $ResourceGroup -ne $vmResourceGroup) { continue }
            if ($Name -and $Name -ne $vmName) { continue }

            $vm = Get-AzVM -Name $vmName -ResourceGroupName $vmResourceGroup -ErrorAction "Stop"
            $vmStatus = Get-AzVM -Status -Name $vmName -ResourceGroupName $vmResourceGroup -ErrorAction "Stop"

            # fix to have same property as VM that is retrieved without Name
            $vm | Add-Member -NotePropertyName PowerState -NotePropertyValue $vmStatus.Statuses[1].DisplayStatus
            $VMs = @($VMs) + $vm
        }
    } else {
        Write-Output "Getting list of VM's or VM ScaleSets matching criteria specified"
        if (!$ResourceGroup -and !$Name) {
            # If ResourceGroup and Name value is not passed - get all VMs under given SubscriptionId
            $Vms = Get-AzVM -Status -ErrorAction "Stop"
            #skipping VMSS Instances and Virtual Machines not running.
            $Vms = $Vms | Where-Object {$_.PowerState -eq 'VM running' -and !($_.VirtualMachineScaleSet)}
            $Vmss = Get-AzVmss -ErrorAction "Stop"
        } else {
            if (!$ResourceGroup -and $Name) {
                Write-Output ("Script input parameters contain resource : $Name but no Resource Group information.")
                $ResourceGroup = Read-Host "Please provide ResourceGroup name"
            }
            # If ResourceGroup value is passed - select all VMs under given ResourceGroupName
            #Virtual Machines not running and those part of a virtual machine scale set will be skipped.
            try {
                $Vms = Get-AzVM -ResourceGroupName $ResourceGroup -Status -ErrorAction "Stop"
            } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
                Write-Output ("Cannot lookup resourceGroup : $ResourceGroup. Exiting...")
                exit    
            }
            $Vms = $Vms | Where-Object {$_.PowerState -eq 'VM running' -and !($_.VirtualMachineScaleSet)}
            if ($Name) {
                $Vms = $Vms | Where-Object {$_.Name -like $Name}
            }
            try {
                $Vmss = Get-AzVmss -ResourceGroupName $ResourceGroup -ErrorAction "Stop"
            } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
                Write-Output ("Cannot lookup resourceGroup : $ResourceGroup. Check access permissions or if ResourceGroup was deleted. Exiting...")
                exit
            }
            if ($Name) {
                $Vmss = $Vmss | Where-Object {$_.Name -like $Name}
            }
        }
    }

    Write-Output("`nVM's or VM ScaleSets matching criteria:`n")
    $Vms | ForEach-Object { Write-Output "$($_.Name) $($_.PowerState)" }
    $Vmss | ForEach-Object { Write-Output "$($_.Name) $($_.PowerState)" }

    #script blocks
    $sb_ama_vm = { param($vmObj); Onboard-VmiWithAmaVm -VMObject $vmObj -OnboardingStatus $OnboardingStatus -OnboardParameters $OnboardParameters}
    $sb_mma_vm = { param($vmObj); Onboard-VmiWithMmaVm -VMObject $vmObj -OnboardingStatus $OnboardingStatus -OnboardParameters $OnboardParameters}
    $sb_ama_vmss = { param($vmssObj); Onboard-VmiWithAmaVmss -VMssObject $vmssObj -OnboardingStatus $OnboardingStatus -OnboardParameters $OnboardParameters}
    $sb_mma_vmss =   { param($vmssObj);  Onboard-VmiWithMmaVmss -VMssObject $vmssObj -OnboardingStatus $OnboardingStatus -OnboardParameters $OnboardParameters}

    if (!$DcrResourceId) {
        $sb_vmss = $sb_mma_vmss
        $sb_vm = $sb_mma_vm
    } else {
        #Assign roles to the user managed identity.     
        if ($ResourceGroup) {
            $rg = Get-AzResourceGroup -Name $ResourceGroup
            Set-ManagedIdentityRoles -TargetScope $rg.ResourceId `
                                     -UserAssignedManagedIdentityObject $userAssignedIdentityObject
        } else {
            $Rgs = Get-AzResourceGroup
            ForEach ($rg in $Rgs) {
                Set-ManagedIdentityRoles -TargetScope $rg.ResourceId `
                                         -UserAssignedManagedIdentityObject $userAssignedIdentityObject
            }
        }

        $sb_vm = $sb_ama_vm
        $sb_vmss = $sb_ama_vmss
    }

    # Validate customer wants to continue
    Write-Output "VM's in a non-running state will be skipped."
    if ($Approve -or $PSCmdlet.ShouldContinue("Continue?", "")) {
        Write-Output ""
    }
    else {
        Write-Output "You selected No - exiting"
        return
    }

    #
    # Loop through each VM/VM Scale set, as appropriate handle installing VM Extensions
    #
    $Vms = @($VMs) + $Vmss

    Foreach ($vm in $Vms) {
        try {
            if ($vm.type -eq 'Microsoft.Compute/virtualMachineScaleSets') {
                &$sb_vmss -vmssObj $vm
            } else {
                &$sb_vm -vmObj $vm
            }
        } catch [InputParameterObsolete] {
            $errorMessage = $_.Exception.errorMessage
            $innerExcepObj = $_.Exception.innerExcepObj
            $obsParamType = $_.Exception.Exception.obsParamType
            $cannotContinue = @("DataCollectionRule", "ResourceGroup","UserAssignedManagedIdentity")
            Write-Output "InputParameterObsolete =>`n`rCustomer Action : Please check if $obsParamType exists or check access permissions"
            Write-Output $errorMessage
            Display-Exception -ExcepObj $innerExcepObj
            if ($cannotContinue.contains($obsParamType)) {
                Write-Output "Exiting..."
                exit
            } else {
                Write-Output "Continuing..."
            }
        } catch [OperationFailed] {
            $errorMessage = $_.Exception.errorMessage
            $statusCode = $_Exception.statusCode
            $reasonPhrase = $_Exception.reasonPhrase
            $possibleNetworkIssue = @(502,408,409,504,505,508,511,426,406)
            $possibleIssueWithApi = @(400,417,424,403,411,510,501,412,414,415,428,413,431,422)
            $serverUnavailable = @(507,503,500,421,451,429)
            $possibleResourceUnavailable = $(401,410,423,405,404,407,416)
            Write-Output "OperationFailed => `n`rStatusCode=$statusCode ReasonPhrase=$reasonPhrase"    
            if ($possibleNetworkIssue.contains($statusCode)) {
                $networkIssueCounter+=1
                if ($networkIssueCounter -lt $networkIssueToleranceLimit) {
                    Write-Output "Possible Network Issue : continuing for the time being"
                } else {
                    Write-Output "Possible Network Issue : not resolving.`n`rExiting..."
                    exit
                }
            } elseif ($possibleIssueWithApi.contains($statusCode)) {
                Write-Output "Customer Action : Please consider raising support ticket."
                Write-Output $errorMessage
            } elseif ($possibleResourceUnavailable.contains($statusCode)) {
                Write-Output "Customer Action : Please check if the resource is unavailable or access is denied"
                Write-Output $errorMessage
                Write-Output "Continuing to next VM/VNss..."
            }  elseif ($serverUnavailable.contains($statusCode)) {
                $serverIssueCounter+=1
                if ($serverIssueCounter -lt $serverIssueToleranceLimit) {
                    Write-Output "Possible API Server/Infrastructure Issue : continuing for the time being"
                } else {
                    Write-Output "Possible API Server/Infrastructure Issue : not resolving.`n`rExiting..."
                    Write-Output "Customer Action : Please consider raising support ticket with below details against -> Owning Server : Service Map and VM Insights"
                    exit
                }
            }
            else {
                Write-Output "Continuing to next VM/VMss..."
            }
        } catch [FatalException] {
            $errorMessage = $_.Exception.errorMessage
            $innerExcepObj = $_.Exception.innerExcepObj
            Write-Output "FatalException =>`n`rCustomer Action : Please consider raising support ticket with below details"
            Write-Output $errorMessage
            Display-Exception -ExcepObj $innerExcepObj
            Write-Output "Exiting..."
            exit
        }
    }
}
catch {
    Write-Output "UnknownException :`n`rCustomer Action : Check Error Message, if issue persists. Please consider raising support ticket with below details against -> Owning Server : Service Map and VM Insights"
    Display-Exception -ExcepObj $_
    Write-Output "Exiting..."
    exit
}

Write-Output "`nSummary:"
Write-Output "`nSucceeded: ($($OnboardingStatus.Succeeded.Count))"
$OnboardingStatus.Succeeded | ForEach-Object { Write-Output $_ }
Write-Output "`nNot running - start VM to configure: ($($OnboardingStatus.NotRunning.Count))"
$OnboardingStatus.NotRunning  | ForEach-Object { Write-Output $_ }
Write-Output "`nVM Scale Set needs update: ($($OnboardingStatus.VMScaleSetNeedsUpdate.Count))"
$OnboardingStatus.VMScaleSetNeedsUpdate  | ForEach-Object { Write-Output $_ }
Write-Output "`nFailed: ($($OnboardingStatus.Failed.Count))"
$OnboardingStatus.Failed | ForEach-Object { Write-Output $_ }
