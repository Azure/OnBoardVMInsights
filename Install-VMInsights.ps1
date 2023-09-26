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
If AMA is onboarded, a Data Collection Rule(DCR) and a User Assigned Managed Identity (UAMI) is also associated with the VM's and VM Scale Sets.

.DESCRIPTION
This script installs or re-configures following on VM's and VM Scale Sets:
1. Log Analytics VM Extension configured to supplied Log Analytics Workspace and Dependency Agent VM Extension.
2. Azure Monitor Agent along with Data Collection Rule, User Assigned Managed Identity and Dependency Agent VM Extension if 'ProcessAndDependencies' is provided.

Can be applied to:
- Subscription
- Resource Group in a Subscription
- Specific VM/VM Scale Set
- Compliance results of a policy for a VM or VM Extension

Script will show you list of VM's/VM Scale Sets that will apply to and let you confirm to continue.
Use -Approve Switch to run without prompting, if all required parameters are provided.

If the Log Analyitcs Agent extension is already configured with a workspace, use -ReInstall Switch to update the workspace.

Use -WhatIf if you would like to see what would happen in terms of installs, what workspace configured to, and status of the extension.

.PARAMETER WorkspaceId
Log Analytics WorkspaceID (GUID) for the data to be sent to

.PARAMETER WorkspaceKey
Log Analytics Workspace primary or secondary key

.PARAMETER SubscriptionId
SubscriptionId for the VMs/VM Scale Sets
If using PolicyAssignmentName parameter, subscription that VM's are in

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
Install-VMInsights.ps1 -WorkspaceRegion eastus -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup>
Install for all VM's in a Resource Group in a subscription

.EXAMPLE
Install-VMInsights.ps1 -WorkspaceRegion eastus -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup> -ReInstall
Specify to ReInstall extensions even if already installed, for example to update to a different workspace

.EXAMPLE
Install-VMInsights.ps1 -WorkspaceRegion eastus -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -PolicyAssignmentName a4f79f8ce891455198c08736 -ReInstall
Specify to use a PolicyAssignmentName for source, and to ReInstall (move to a new workspace)

.EXAMPLE
Install-VMInsights.ps1 -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup>  -DcrResourceId <DataCollectionRuleResourceId> -ProcessAndDependencies -UserAssignedManagedIdentityName <UserAssignedIdentityName> -UserAssignedManagedIdentityResourceGroup <UserAssignedIdentityResourceGroup>
(The above command will onboard Assign a UAMI to a VM/VMss for AMA, Onboard AMA, DA and associate a DCR with the VM/Vmss)

.EXAMPLE
Install-VMInsights.ps1 -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup>  -DcrResourceId <DataCollectionRuleResourceId> -UserAssignedManagedIdentityName <UserAssignedIdentityName> -UserAssignedManagedIdentityResourceGroup <UserAssignedIdentityResourceGroup>
(The above command will onboard Assign a UAMI to a VM/VMss for AMA, Onboard AMA and associate a DCR with the VM/Vmss)

.EXAMPLE
Install-VMInsights.ps1 -SubscriptionId <SubscriptionId> -PolicyAssignmentName a4f79f8ce891455198c08736  -DcrResourceId <DataCollectionRuleResourceId> -UserAssignedManagedIdentityName <UserAssignedIdentityName> -UserAssignedManagedIdentityResourceGroup <UserAssignedIdentityResourceGroup>
(The above command will onboard Assign a UAMI to a VMs for AMA, Onboard AMA and associate a DCR with the VM/Vmss)

.EXAMPLE
Install-VMInsights.ps1 -SubscriptionId <SubscriptionId> -PolicyAssignmentName a4f79f8ce891455198c08736  -DcrResourceId <DataCollectionRuleResourceId> -ProcessAndDependencies -UserAssignedManagedIdentityName <UserAssignedIdentityName> -UserAssignedManagedIdentityResourceGroup <UserAssignedIdentityResourceGroup>
(The above command will onboard Assign a UAMI to a VMs for AMA, Onboard AMA, DA and associate a DCR with the VM/Vmss)

.LINK
This script is posted to and further documented at the following location:
http://aka.ms/OnBoardVMInsights
#>

[CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
param(
    [Parameter(mandatory = $True)][String]$SubscriptionId,
    [Parameter(mandatory = $False)][Switch]$TriggerVmssManualVMUpdate,
    [Parameter(mandatory = $False)][Switch]$Approve,
    
    [Parameter(mandatory = $False, ParameterSetName = 'NonPolicyAssignment')][String]$ResourceGroup,
    [Parameter(mandatory = $False, ParameterSetName = 'NonPolicyAssignment')][String]$Name = "*",
    
    [Parameter(mandatory = $False, ParameterSetName = 'PolicyAssignment')][String]$PolicyAssignmentName,
    
    [Parameter(mandatory = $False, ParameterSetName = 'AzureMonitoringAgent')][Switch]$ProcessAndDependencies,
    [Parameter(mandatory = $True,  ParameterSetName = 'AzureMonitoringAgent')][String]$DcrResourceId,
    [Parameter(mandatory = $True,  ParameterSetName = 'AzureMonitoringAgent')][String]$UserAssignedManagedIdentityResourceGroup,
    [Parameter(mandatory = $True,  ParameterSetName = 'AzureMonitoringAgent')][String]$UserAssignedManagedIdentityName,

    [Parameter(mandatory = $True,  ParameterSetName = 'LogAnalyticsAgent')][String]$WorkspaceId,
    [Parameter(mandatory = $True,  ParameterSetName = 'LogAnalyticsAgent')][String]$WorkspaceKey,
    [Parameter(mandatory = $False, ParameterSetName = 'LogAnalyticsAgent')][Switch]$ReInstall
    )

# Log Analytics Extension constants
Set-Variable -Name laExtensionMap -Option Constant -Value @{ "Windows" = @{LaExtensionType = "MicrosoftMonitoringAgent";LaExtensionVersion = "1.0"}; "Linux" = @{LaExtensionType = "OmsAgentForLinux"; LaExtensionVersion = "1.6"} }
Set-Variable -Name laExtensionPublisher -Option Constant -Value "Microsoft.EnterpriseCloud.Monitoring"
Set-Variable -Name laExtensionName -Option Constant -Value "MMAExtension"

# Azure Monitoring Agent Extension constants
Set-Variable -Name amaExtensionMap -Option Constant -Value @{ "Windows" = @{AmaExtensionType = "AzureMonitorWindowsAgent"; AmaExtensionVersion = "1.16"}; "Linux" = @{AmaExtensionType = "AzureMonitorLinuxAgent"; AmaExtensionVersion = "1.16"} }
Set-Variable -Name amaExtensionPublisher -Option Constant -Value "Microsoft.Azure.Monitor"
Set-Variable -Name amaExtensionName -Option Constant -Value "AzureMonitoringAgent"

# Dependency Agent Extension constants
Set-Variable -Name daExtensionMap -Option Constant -Value @{"Windows" = @{DaExtensionType = "DependencyAgentWindows"; DaExtensionVersion = "9.10"}; "Linux" = @{DaExtensionType = "DependencyAgentLinux"; DaExtensionVersion = "9.10"} }
Set-Variable -Name daExtensionName -Option Constant -Value "DA-Extension"
Set-Variable -Name processAndDependenciesPublicSettings -Option Constant -Value @{"enableAMA" = "true"}
Set-Variable -Name processAndDependenciesPublicSettingsRegexPattern -Option Constant -Value '"enableAMA"\s*:\s*"(\w+)"'

$ErrorActionPreference = "Stop"
#Presence of DCR Resource Id indicates AMA onboarding.
$isAma = if ($DcrResourceId) {"True"} else {"False"}

class FatalException : System.Exception {
    FatalException($errorMessage, $innerException) : base($errorMessage, $innerException) { 
    }
}

class UnknownException : System.Exception {
    UnknownException($errorMessage, $innerException) : base($errorMessage, $innerException) {
    }
}

class VirtualMachineDoesNotExist : System.Exception {
    VirtualMachineDoesNotExist ($errorMessage, $innerException) : base($errorMessage, $innerException) {
    }
}

class VirtualMachineScaleSetDoesNotExist : System.Exception {
    VirtualMachineScaleSetDoesNotExist ($errorMessage, $innerException) : base($errorMessage, $innerException) {
    }
}

class OperationFailed : System.Exception {
    OperationFailed($errorMessage) : base($errorMessage) {}
}

class DataCollectionRuleForbidden : FatalException {
    DataCollectionRuleForbidden($errorMessage, $innerException) : base($errorMessage, $innerException) {
    }
}

class DataCollectionRuleDoesNotExist : FatalException {
    DataCollectionRuleDoesNotExist($errorMessage, $innerException) : base($errorMessage, $innerException) {
    }
}

class PolicyAssignmentDoesNoExist : FatalException {
    PolicyAssignmentDoesNoExist($errorMessage, $innerException) : base($errorMessage, $innerException) {
    }
}

class DataCollectionRuleIncorrect : FatalException {
    DataCollectionRuleIncorrect($errorMessage, $innerException) : base($errorMessage, $innerException) {
    }
}

class UserAssignedManagedIdentityDoesNotExist : FatalException {
    UserAssignedManagedIdentityDoesNotExist($errorMessage, $innerException) : base($errorMessage, $innerException) {
    }
}

#
# FUNCTIONS
#
function PrintSummaryMessage {
    param (
        [Parameter(mandatory = $True)][hashtable]$OnboardingStatus
    )
    Write-Output "" "Summary:"
    Write-Output "" "TotalEligibleResources : $($($OnboardingStatus.Total))"
    Write-Output "`nSucceeded : $($OnboardingStatus.Succeeded)"
    Write-Output "`nFailed : $($($OnboardingStatus.Total) - $OnboardingStatus.Succeeded)"
}

function ParseCloudExceptionMessage {
    param
    (
        [Parameter(mandatory = $True)][String]$exceptionMessage
    )
    
   if ($errorMessage -match 'ErrorCode:(.*)') {
        return $matches[1]
   }
}

function GetVMExtension {
    <#
	.SYNOPSIS
	Return the VM extension of specified ExtensionType
	#>
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject,
        [Parameter(mandatory = $True)][String]$ExtensionType
    )

    $vmResourceGroupName = $VMObject.ResourceGroupName
    $vmName = $VMObject.Name

    try {
        $extensions = Get-AzVMExtension -ResourceGroupName $vmResourceGroupName -VMName $vmName
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ParseCloudExceptionMessage($_.Exception.Message)
        if ($errorCode -eq "ParentResourceNotFound") {
            throw [VirtualMachineDoesNotExist]::new("($($VMObject.ResourceGroupName) $($VMObject.Name) : Virtual Machine does not exist or unaccessible.",$_.Exception)
        } elseif ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($vmResourceGroupName,$_.Exception)   
        } else {
            throw [UnknownException]::new("($vmResourceGroupName) $vmName : Failed to lookup extension", $_.Exception)
        }
    }
    
    foreach ($extension in $extensions) {
        if ($ExtensionType -eq $extension.ExtensionType) {
            Write-Verbose("($vmResourceGroupName) $vmName, $ExtensionType : Extension found")
            $extension
            return
        }
    }
}

function GetVMssExtension {
    <#
	.SYNOPSIS
	Return the VMss extension of specified ExtensionType
	#>
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject,
        [Parameter(mandatory = $True)][String]$ExtensionType
    )

    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = = $VMssObject.ResourceGroupName
    foreach ($extension in $VMssObject.VirtualMachineProfile.ExtensionProfile.Extensions) {
        if ($ExtensionType -eq $extension.Type) {
            Write-Verbose("($vmssResourceGroupName) $vmssName, $ExtensionType : Extension found")
            $extension
            return
        }
    }
}

function RemoveVMExtension {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject,
        [Parameter(mandatory = $True)][String]$ExtensionType
    )

    $vmResourceGroupName = $VMObject.ResourceGroupName
    $vmName = $VMObject.VMName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionType $ExtensionType 
    if (!$extension) {
        Write-Verbose "($vmResourceGroupName) $vmName, $ExtensionType : Unable to lookup extension"
        return
    }
    $extensionName = $extension.Name

    if (!$PSCmdlet.ShouldProcess("($vmResourceGroupName) $vmName, $extensionName", "Remove $extensionName")) {
        return
    }

    try {
        #Remove operation on non existent VM, extension still return a success
        $removeResult = Remove-AzVMExtension -ResourceGroupName $vmResourceGroupName -VMName $vmName -Name $extensionName -Force
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ParseCloudExceptionMessage($_.Exception.Message)
        if($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($vmResourceGroupName,$_.Exception)       
        } else {
            throw [UnknownException]::new("($vmResourceGroupName) $vmName, $extensionName : Failed to remove extension", $_.Exception)
        }
    }
    
    if ($removeResult.IsSuccessStatusCode) {
        Write-Verbose "($vmResourceGroupName) $vmName, $extensionName : Successfully removed extension"
        return
    }

    throw [OperationFailed]::new("($vmResourceGroupName) $vmName, $extensionName : Failed to remove extension. StatusCode = $($removeResult.StatusCode). ReasonPhrase = $($removeResult.ReasonPhrase)")
}

function NewDCRAssociation {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject
    )

    $vmName = $VMObject.Name
    $vmResourceGroupName = $VMObject.ResourceGroupName
    $vmId = $VMObject.Id
    $invalidOperationParserPattern = "^Operation returned an invalid status code (.*)"

    try {
        # A VM may have zero or more Data Collection Rule Associations
        $dcrAssociationList = Get-AzDataCollectionRuleAssociation -TargetResourceId $vmId
    } catch [System.Management.Automation.ParameterBindingException] {
        throw [VirtualMachineDoesNotExist]::new("($($VMObject.ResourceGroupName) $($VMObject.Name) : Virtual Machine does not exist or unaccessible.",$_.Exception)
    }

    # A VM may have zero or more Data Collection Rule Associations
    foreach ($dcrAssociation in $dcrAssociationList) {
        if ($dcrAssociation.DataCollectionRuleId -eq $DcrResourceId) {
            Write-Output "($vmResourceGroupName) $vmName, $($dcrAssociation.Name) : Data Collection Rule already associated to the VM"
            return $VMObject
        }
    }

    #The Customer is responsible to uninstall the DCR Association themselves
    if (!($PSCmdlet.ShouldProcess("($vmResourceGroupName) $vmName", "Install Data Collection Rule Association"))) {
        return $VMObject
    }

    $dcrassociationName = "VM-Insights-DCR-Association"
    Write-Output "($vmResourceGroupName) $vmName, $dcrassociationName : Deploying Data Collection Rule Association"
    try {
        $dcrassociation = New-AzDataCollectionRuleAssociation -TargetResourceId $vmId -AssociationName $dcrassociationName -RuleId $DcrResourceId
    } catch [System.Management.Automation.PSInvalidOperationException] {
        $exceptionMessage = $_.Exception.InnerException.Message
        
        if ($exceptionMessage.Contains('Invalid format of the resource identifier')) {
            throw [DataCollectionRuleIncorrect]::new("$DcrResourceId : Data Collection Rule does not exist.")
        } elseif (!($exceptionMessage -match $invalidOperationParserPattern)){
            throw [UnknownException]::new("($vmResourceGroupName) $vmName, $DcrResourceId : Failed to create data collection rule association", $_.Exception)
        } else {
            $statusCode = $matches[1]
            if ($statusCode.Contains('BadRequest')) {
                throw [DataCollectionRuleDoesNotExist]::new("$DcrResourceId : Data Collection Rule does not exist.", $_.Exception)
            } elseif ($statusCode.Contains('NotFound')) {
                throw [VirtualMachineDoesNotExist]::new("($($VMObject.ResourceGroupName) $($VMObject.Name) : Virtual Machine does not exist or unaccessible.", $_.Exception)
            } elseif ($statusCode.Contains('Forbidden')) {
                throw [DataCollectionRuleForbidden]::new("$DcrResourceId : Access to data collection rule is forbidden", $_.Exception)     
            } else {
                throw [UnknownException]::new("($vmResourceGroupName) $vmName, $DcrResourceId : Failed to create data collection rule association with unknown StatusCode = $statusCode", $_.Exception)
            }
        }
    }
    #Tmp fix task:- 21191002
    if (!$dcrassociation -or $dcrassociation -is [Microsoft.Azure.Management.Monitor.Models.ErrorResponseCommonV2Exception]) {
        throw [UnknownException]::new("$vmName ($vmResourceGroupName), $DcrResourceId : Failed to create data collection rule association",$dcrassociation)
    }

    return $VMObject
}

function OnboardDaWithoutAmaSettingsVm {
    <#
	.SYNOPSIS
	Install DA (VM) on AMA with ProcessingAndDependencies Disabled.
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject,
        [Parameter(mandatory = $True)][String]$DaExtensionType,
        [Parameter(mandatory = $True)][String]$DaExtensionVersion
    )

    return $VMObject
}

function OnboardDaWithAmaSettingsVm {
    <#
	.SYNOPSIS
	Install DA (VM) on AMA with ProcessingAndDependencies Enabled, handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject,
        [Parameter(mandatory = $True)][String]$DaExtensionType,
        [Parameter(mandatory = $True)][String]$DaExtensionVersion
    )

    $vmName = $VMObject.Name
    $vmResourceGroupName = $VMObject.ResourceGroupName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionType $DaExtensionType

    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "($vmResourceGroupName) $vmName, $extensionName : Extension $DaExtensionType already installed."   
    }
    
    if (!($PSCmdlet.ShouldProcess("($vmResourceGroupName) $vmName, $extensionName", "install extension $DaExtensionType"))) {
        return $VMObject
    }

    $parameters = @{
        ResourceGroupName  = $vmResourceGroupName
        VMName             = $vmName
        Publisher          = $daExtensionPublisher
        ExtensionType      = $DaExtensionType
        ExtensionName      = $daExtensionName
        TypeHandlerVersion = $DaExtensionVersion
        ForceRerun         = $True
        Settings           = $processAndDependenciesPublicSettings
    }

    InstallVMExtension -InstallParameters $parameters
    return $VMObject
}

function OnboardDaLaVm {
    <#
	.SYNOPSIS
	Install DA (VM) with LA settings, handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject,
        [Parameter(mandatory = $True)][String]$DaExtensionType,
        [Parameter(mandatory = $True)][String]$DaExtensionVersion
    )

    $vmName = $VMObject.Name
    $vmResourceGroupName = $VMObject.ResourceGroupName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionType $DaExtensionType

    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "($vmResourceGroupName) $vmName, $extensionName : Extension $DaExtensionType already installed."   
    }
    
    if (!($PSCmdlet.ShouldProcess("($vmResourceGroupName) $vmName, $extensionName", "install extension $DaExtensionType"))) {
        return $VMObject
    }

    $parameters = @{
        ResourceGroupName  = $vmResourceGroupName
        VMName             = $vmName
        Publisher          = $daExtensionPublisher
        ExtensionType      = $DaExtensionType
        ExtensionName      = $extensionName
        TypeHandlerVersion = $DaExtensionVersion
        ForceRerun         = $True
    }

    InstallVMExtension -InstallParameters $parameters
    return $VMObject
}

function OnboardDaWithoutAmaSettingsVmss {
    <#
	.SYNOPSIS
	Install DA (VMSS) with ProcessAndDependencies disabled.
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject,
        [Parameter(mandatory = $True)][String]$DaExtensionType,
        [Parameter(mandatory = $True)][String]$DaExtensionVersion
    )

    return $VMssObject
}

function OnboardDaWithAmaSettingsVmss {
    <#
	.SYNOPSIS
	Install DA (VMSS), handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject,
        [Parameter(mandatory = $True)][String]$DaExtensionType,
        [Parameter(mandatory = $True)][String]$DaExtensionVersion
    )
    
    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $daExtensionName
    $extension = GetVMssExtension -VMssObject $VMssObject -ExtensionType $DaExtensionType
     
    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "($vmssResourceGroupName) $vmssName, $extensionName : Extension $DaExtensionType already installed."
        $extension.Settings = $processAndDependenciesPublicSettings
    } else {
        if (!($PSCmdlet.ShouldProcess("$vmssName ($vmssResourceGroupName)", "install extension $extensionType"))) {
            return $VMssObject
        }

        $parameters = @{
            VirtualMachineScaleSet = $VMssObject
            Publisher              = $daExtensionPublisher
            Type                   = $extensionType
            Name                   = $extensionName
            TypeHandlerVersion     = $daExtensionVersionMap.($osType.ToString())
            AutoUpgradeMinorVersion = $True
            Setting                 = $processAndDependenciesPublicSettings
        }

        $VMssObject = Add-AzVmssExtension @parameters
        Write-Output "$vmssName ($vmssResourceGroupName) : $extensionType added"
    }

    return UpdateVMssExtension -VMssObject $VMssObject

}

function OnboardDaVmss {
    <#
	.SYNOPSIS
	Install DA (VMSS), handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject,
        [Parameter(mandatory = $True)][String]$DaExtensionType,
        [Parameter(mandatory = $True)][String]$DaExtensionVersion
    )
    
    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $daExtensionName
    $extension = GetVMssExtension -VMssObject $VMssObject -ExtensionType $DaExtensionType
     
    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "($vmssResourceGroupName) $vmssName, $extensionName : Extension $DaExtensionType already installed."
        $extension.Settings = $processAndDependenciesPublicSettings
    } else {
        if (!($PSCmdlet.ShouldProcess("$vmssName ($vmssResourceGroupName)", "install extension $extensionType"))) {
            return $VMssObject
        }

        $parameters = @{
            VirtualMachineScaleSet = $VMssObject
            Publisher              = $daExtensionPublisher
            Type                   = $extensionType
            Name                   = $extensionName
            TypeHandlerVersion     = $daExtensionVersionMap.($osType.ToString())
            AutoUpgradeMinorVersion = $True
            Setting                 = $processAndDependenciesPublicSettings
        }

        $VMssObject = Add-AzVmssExtension @parameters
        Write-Output "$vmssName ($vmssResourceGroupName) : $extensionType added"
    }

    return UpdateVMssExtension -VMssObject $VMssObject
}


function InstallDaLaVmss {
     <#
	.SYNOPSIS
	Install DA (VMss) with LA settings, handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject,
        [Parameter(mandatory = $True)][String]$DaExtensionType,
        [Parameter(mandatory = $True)][String]$DaExtensionVersion,
        [Parameter(mandatory = $True)][bool]$TriggerVmssManualVMUpdate
    )
    
    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $daExtensionName
    $extension = GetVMssExtension -VMssObject $VMssObject -ExtensionType $DaExtensionType
     
    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "$vmssName ($vmssResourceGroupName) : Extension $DaExtensionType with name $extensionName already installed."
    } else {
        if (!($PSCmdlet.ShouldProcess("$vmssName ($vmssResourceGroupName)", "install extension $extensionType"))) {
            return $VMssObject
        }

        $parameters = @{
            VirtualMachineScaleSet = $VMssObject
            Publisher              = $daExtensionPublisher
            Type                   = $extensionType
            Name                   = $extensionName
            TypeHandlerVersion     = $daExtensionVersionMap.($osType.ToString())
            AutoUpgradeMinorVersion = $True
        }

        $VMssObject = Add-AzVmssExtension @parameters
        Write-Output "$vmssName ($vmssResourceGroupName) : $DaExtensionType added"
        $VMssObject = UpdateVMssExtension -VMssObject $VMssObject
    }

    return $VMssObject
}

function InstallAmaVm {
    <#
	.SYNOPSIS
	Install AMA (VMSS), handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject,
        [Parameter(mandatory = $True)][String]$AmaExtensionType,
        [Parameter(mandatory = $True)][String]$AmaExtensionVersion
    )

    $vmName = $VMObject.Name
    $vmResourceGroupName = $VMObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extension = $amaExtensionName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionType $AmaExtensionType
    
    if ($extension) {
        $extensionName = $extension.Name 
        Write-Verbose "($vmResourceGroupName) $vmName, $extensionName : Extension $AmaExtensionType already installed. Provisioning State: $($extension.ProvisioningState)" ""
    }
    
    if (!($PSCmdlet.ShouldProcess("($vmResourceGroupName) $vmName", "install extension $ExtensionType"))) {
        return $VMObject
    }

    $parameters = @{
        ResourceGroupName  = $vmResourceGroupName
        VMName             = $vmName
        Publisher          = $amaExtensionPublisher
        ExtensionType      = $AmaExtensionType
        Name               = $extensionName
        TypeHandlerVersion = $AmaExtensionVersion
        ForceRerun         = $True
        Settings           = $amaPublicSettings
    }

    InstallVMExtension -InstallParameters $parameters 
    return $VMObject
}

function OnboardVmiWithLaVmWithReInstall {
    <#
	.SYNOPSIS
	Install OMS Extension on Virtual Machines, handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject,
        [Parameter(mandatory = $True)][String]$LaExtensionType,
        [Parameter(mandatory = $True)][String]$LaExtensionVersion
    )

    $vmName = $VMObject.Name
    $vmResourceGroupName = $VMObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $laExtensionName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionType $LaExtensionType

    if ($extension) {
        $extensionName = $extension.Name
        if ($LaExtensionType -eq "OmsAgentForLinux") {
            #it is important to preserve the previous behavior.
            Write-Output "($vmResourceGroupName) $vmName : ExtensionType $LaExtensionType does not support updating workspace. An uninstall followed by re-install is required"
            RemoveVMExtension -VMObject $VMObject `
                                -ExtensionType $LaExtensionType
        }
    }
    
    if (!($PSCmdlet.ShouldProcess("($vmResourceGroupName) $vmName ", "install extension $LaExtensionType"))) {
        return $VMObject
    }
    
    $parameters = @{
        ResourceGroupName  = $vmResourceGroupName
        VMName             = $vmName
        Publisher          = $laExtensionPublisher
        ExtensionType      = $LaExtensionType
        ExtensionName      = $extensionName
        TypeHandlerVersion = $LaExtensionVersion
        ForceRerun         = $True
        Settings           = $laPublicSettings
        ProtectedSettings  = $laProtectedSettings
    }

    InstallVMExtension -InstallParameters $parameters
    return $VMObject
}

function OnboardVmiWithLaVmWithoutReInstall {
    <#
	.SYNOPSIS
	Install OMS Extension on Virtual Machines, handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject,
        [Parameter(mandatory = $True)][String]$LaExtensionType,
        [Parameter(mandatory = $True)][String]$LaExtensionVersion
    )

    $vmName = $VMObject.Name
    $vmResourceGroupName = $VMObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $laExtensionName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionType $LaExtensionType

    if ($extension) {
        $extensionName = $extension.Name
        if ($LaExtensionType -eq "OmsAgentForLinux") {
            Write-Output "($vmResourceGroupName) $vmName $extensionName : Extension $LaExtensionType present, run with -ReInstall again to move to new workspace."
            return $VMObject
        }
    }
    
    if (!($PSCmdlet.ShouldProcess("($vmResourceGroupName) $vmName ", "install extension $LaExtensionType"))) {
        return $VMObject
    }

    $parameters = @{
        ResourceGroupName  = $vmResourceGroupName
        VMName             = $vmName
        Publisher          = $laExtensionPublisher
        ExtensionType      = $LaExtensionType
        ExtensionName      = $extensionName
        TypeHandlerVersion = $LaExtensionVersion
        ForceRerun         = $True
        Settings           = $laPublicSettings
        ProtectedSettings  = $laProtectedSettings
    }
                
    InstallVMExtension -InstallParameters $parameters
    return $VMObject
}

function InstallAmaVMss {
    <#
	.SYNOPSIS
	Install AMA (VMSS), handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject,
        [Parameter(mandatory = $True)][String]$AmaExtensionType,
        [Parameter(mandatory = $True)][String]$AmaExtensionVersion,
        [Parameter(mandatory = $True)][bool]$TriggerVmssManualVMUpdate
    )

    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $amaExtensionName
    $extension = GetVMssExtension -VMss $VMssObject -ExtensionType $AmaExtensionType
    
    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "($vmssResourceGroupName) $vmssName, $extensionName  : Extension $AmaExtensionType with name already installed."
        $extension.Settings = $amaPublicSettings
        
    } else {
        if (!($PSCmdlet.ShouldProcess("($vmssResourceGroupName) $vmssName", "install extension $AmaExtensionType"))) {
            return $VMssObject
        }
        
        $parameters = @{
            VirtualMachineScaleSet  = $VMssObject
            Name                    = $extensionName
            Publisher               = $amaExtensionPublisher
            Type                    = $extensionType 
            TypeHandlerVersion      = $AmaExtensionVersion
            Setting                 = $amaPublicSettings
            AutoUpgradeMinorVersion = $True
        }
        $VMssObject = Add-AzVmssExtension @parameters
        Write-Output " ($vmssResourceGroupName) $vmssName : $AmaExtensionType added"
    }

    return UpdateVMssExtension -VMssObject $VMssObject
}

function OnboardVmiWithLaVmss {
    <#
	.SYNOPSIS
	Install LA (VMSS), handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject,
        [Parameter(mandatory = $True)][String]$LaExtensionType,
        [Parameter(mandatory = $True)][String]$LaExtensionVersion
    )

    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $laExtensionName
    # Use supplied name unless already deployed, use same name
    $extension = GetVMssExtension -VMss $VMssObject -ExtensionType $LaExtensionType

    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "($vmssResourceGroupName) $vmssName, $extensionName : Extension already installed."
        $extension.Settings = $laPublicSettings
        $extension.ProtectedSetting = $laProtectedSettings
    } else {
        if (!($PSCmdlet.ShouldProcess("($vmssResourceGroupName) $vmssName", "Install extension"))) {
            return $VMssObject
        }

        $parameters = @{
            VirtualMachineScaleSet  = $VMssObject
            Name                    = $extensionName
            Publisher               = $laExtensionPublisher
            Type                    = $LaExtensionType
            TypeHandlerVersion      = $LaExtensionVersion
            Setting                 = $laPublicSettings
            ProtectedSetting        = $laProtectedSettings
        }
        $VMssObject = Add-AzVmssExtension @parameters
        Write-Output "($vmssResourceGroupName) $vmssName : $LaExtensionType added"
    }

    return UpdateVMssExtension -VMssObject $VMssObject
}

function OnboardVmiWithAmaVm {
    <#
	.SYNOPSIS
	Onboard VMI with AMA on Vms
	#>
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject,
        [Parameter(mandatory = $True)][String]$AmaExtensionType,
        [Parameter(mandatory = $True)][String]$AmaExtensionVersion
    )

    AssignVmUserManagedIdentity -VMObject $VMObject
    NewDCRAssociation -VMObject $VMObject
    return InstallAmaVm -VMObject $VMObject `
                  -AmaExtensionType $AmaExtensionType `
                  -AmaExtensionVersion $AmaExtensionVersion
}

function OnboardVmiWithAmaVmss {
    <#
	.SYNOPSIS
	Onboard VMI with AMA on VMSS
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)][Object]$VMssObject,
        [Parameter(mandatory = $True)][String]$UserAssignedIdentityObject,
        [Parameter(mandatory = $True)][String]$DcrResourceId,
        [Parameter(mandatory = $True)][Hashtable]$AmaPublicSettings,
        [Parameter(mandatory = $True)][String]$AmaExtensionType,
        [Parameter(mandatory = $True)][String]$AmaExtensionVersion
    )
            
    $VMssObject = AssignVmssManagedIdentity -VMssObject $VMssObject `
                               -UserAssignedManagedIdentityObject $UserAssignedIdentityObject
    NewDCRAssociation -VMObject $VMssObject
    return InstallAmaVMss -VMssObject $VMssObject `
                    -AmaExtensionType $AmaExtensionType `
                    -AmaExtensionVersion $AmaExtensionVersion
}

function SetManagedIdentityRoles {
    
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)][String]$TargetScope,
        [Parameter(Mandatory = $True)][Object]$UserAssignedManagedIdentityObject
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
            Write-Verbose "Scope $targetScope, $role : role already set"
        } else {
            Write-Verbose("Scope $targetScope, $role : assigning role" )
            New-AzRoleAssignment  -ObjectId $userAssignedManagedIdentityId -RoleDefinitionName $role -Scope $targetScope
            Write-Verbose "Scope $targetScope : role assignment for $userAssignedManagedIdentityName with $role succeeded"
        }
    }
}

function InstallVMExtension {
    <#
	.SYNOPSIS
	Install VM Extension, handling if already installed
	#>
    param
    (
        [Parameter(mandatory = $True)][Object]$InstallParameters
    )

    $vmName = $InstallParameters.VMName
    $vmResourceGroupName = $InstallParameters.ResourceGroupName
    $extensionName = $InstallParameters.ExtensionName
    
    Write-Verbose("($vmResourceGroupName) $vmName, $extensionName : Deploying/Updating extension")
    try {
        $result = Set-AzVMExtension @InstallParameters
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $exceptionInfo = $_.Exception.Message
        $errorCode = ParseCloudExceptionMessage($exceptionInfo)
        if ($errorCode -eq "ParentResourceNotFound") {
            throw [VirtualMachineDoesNotExist]::new("($($VMObject.ResourceGroupName) $($VMObject.Name) : Virtual Machine does not exist or unaccessible.",$_.Exception)
        } elseif($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($vmResourceGroupName,$_.Exception)       
        } else {
            $extensionType = $InstallParameters.ExtensionType
            throw [UnknownException]::new("($vmResourceGroupName) $vmName, $extensionName : Failed to update/install extension", $_.Exception)
        }
    }

    if ($result.IsSuccessStatusCode) {
        Write-Output "$vmName ($vmResourceGroupName) : Successfully deployed/updated extension"
        return
    }

    throw [OperationFailed]::new("($vmResourceGroupName) $vmName, $extensionType : Failed to update extension. StatusCode = $($removeResult.StatusCode). ReasonPhrase = $($removeResult.ReasonPhrase)")
}

function UpgradeVmssExtensionWithoutManualUpdate {
    <#
	.SYNOPSIS
	Upgrade VMss Extension
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)][Object]$VMssObject
    )

    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    
    if ($VMssObject.UpgradePolicy.Mode -ne 'Manual') {
        Write-Output "($vmssResourceGroupName) $vmssName, $VMssObject.UpgradePolicy.Mode : Upgrade mode not Manual"
        return
    }

    Write-Output "($vmssResourceGroupName) $vmssName : has UpgradePolicy of Manual. Please trigger upgrade of VM Scale Set or call with -TriggerVmssManualVMUpdate"
}

function UpgradeVmssExtensionManualUpdateEnabled {
    <#
	.SYNOPSIS
	Upgrade VMss Extension
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)][Object]$VMssObject
    )

    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    
    if ($VMssObject.UpgradePolicy.Mode -ne 'Manual') {
        Write-Output "($vmssResourceGroupName) $vmssName, $($VMssObject.UpgradePolicy.Mode) : Upgrade mode not Manual"
        return
    }

    try {
        $scaleSetInstances = Get-AzVmssVm -ResourceGroupName $vmssResourceGroupName -VMScaleSetName $vmssName -InstanceView
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $exceptionInfo = $_.Exception.Message
        $errorCode = ParseCloudExceptionMessage($exceptionInfo)
        if ($errorCode -eq "ParentResourceNotFound") {
            throw [VirtualMachineScaleSetDoesNotExist]::new("($($VMssObject.ResourceGroupName) $($VMssObject.Name) : Virtual Machine Scale Set does not exist or unaccessible.",$_.Exception)
        } elseif ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($vmssResourceGroupName,$_.Exception)       
        } else {
            throw [UnknownException]::new("($vmssResourceGroupName) $vmssName : Failed to upgrade virtual machine scale set", $_.Exception)
        }
    }

    $i = 0
    $instanceCount = $scaleSetInstances.Length
    Foreach ($scaleSetInstance in $scaleSetInstances) {
        if ($scaleSetInstance.LatestModelApplied) {
            continue
        }
        $i++
        Write-Verbose "($vmssResourceGroupName) $vmssName $($scaleSetInstance.Name) : Updating instance $i of $instanceCount"
        try {
            if (!($PSCmdlet.ShouldProcess("($vmssResourceGroupName) $vmssName $($scaleSetInstance.Name)", "Upgrading virtual machine scale set instance"))) {
                return
            }
            $result = Update-AzVmssInstance -ResourceGroupName $vmssResourceGroupName -VMScaleSetName $vmssName -InstanceId $scaleSetInstance.InstanceId
            if ($result.Status -ne "Succeeded") {
                Write-Output "($vmssResourceGroupName) $vmssName $($scaleSetInstance.Name) : Failed to upgrade virtual machine scale set instance. $($result.Status)"
            }
        } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
            $errorCode = ParseCloudExceptionMessage($_.Exception.Message)
            if ($errorCode -eq "ResourceNotFound") {
                throw [VirtualMachineScaleSetDoesNotExist]::new("($($VMssObject.ResourceGroupName) $($VMssObject.Name) : Virtual Machine Scale Set does not exist or unaccessible.",$_.Exception)
            } elseif($errorCode -eq "ResourceGroupNotFound") {
                throw [ResourceGroupDoesNotExist]::new($vmssResourceGroupName,$_)       
            } elseif($errorCode -eq "OperationNotAllowed") {
                Write-Output "($vmssResourceGroupName) $vmssName, $($scaleSetInstance.Name) : Unable to lookup VMSS instance"
                DisplayException $_
                Write-Output "Continuing.."
            } else {
                throw [UnknownException]::new("($vmssResourceGroupName) $vmssName $($scaleSetInstance.Name) : Failed to upgrade virtual machine scale set instance", $_.Exception)
            }
        }
    }
    Write-Output("($vmssResourceGroupName) $vmssName) : All virtual machine scale set instances upgraded")
}

function UpdateVMssExtension {
    <#
	.SYNOPSIS
	Update VMss Extension
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)][Object]$VMssObject
    )

    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    
    if (!($PSCmdlet.ShouldProcess("($vmssResourceGroupName) $vmssName", "Updating virtual machine scale set"))) {
        return
    }

    Write-Verbose("($vmssResourceGroupName) $vmssName : Updating virtual machine scale set")
    try {
        $VMssObject = Update-AzVmss -VMScaleSetName $vmssName `
                                    -ResourceGroupName $vmssResourceGroupName `
                                    -VirtualMachineScaleSet $VMssObject `
                                   
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ParseCloudExceptionMessage($_.Exception.Message)
        if ($errorCode -eq "ParentResourceNotFound") {
            throw [VirtualMachineScaleSetDoesNotExist]::new("($($VMssObject.ResourceGroupName) $($VMssObject.Name) : Virtual Machine Scale Set does not exist or unaccessible.",$_.Exception)
        } elseif($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($vmssResourceGroupName,$_.Exception)       
        } else {
            throw [UnknownException]::new("($vmssResourceGroupName) $vmssName : Failed to update virtual machine scale set", $_.Exception)
        }
    }
    
    if ($VMssObject.ProvisioningState -eq "Succeeded") {
        Write-Output "($vmssResourceGroupName) $vmssName : Successfully updated scale set with extension"
        return $VMssObject
    }

    throw [OperationFailed]::new("($vmssResourceGroupName) $vmssName : Failed to update virtual machine scale set")
}

function CheckUserManagedIdentityAlreadyAssigned {
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMObject,
        [Parameter(Mandatory = $True)][String]$UserAssignedManagedIdentyId
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

function AssignVmssManagedIdentity {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject,
        [Parameter(Mandatory = $True)][Object]$UserAssignedManagedIdentityObject
    )

    $vmssName = $VMssObject.Name
    $vmssResourceGroup = $VMssObject.ResourceGroupName
    $userAssignedManagedIdentityName = $UserAssignedManagedIdentityObject.Name
    $userAssignedManagedIdentityId = $UserAssignedManagedIdentityObject.Id

    if (CheckUserManagedIdentityAlreadyAssigned -VMObject $VMssObject `
                                                 -UserAssignedManagedIdentyId $userAssignedManagedIdentityId) {
        Write-Output "($vmssResourceGroup) $vmssName, $userAssignedManagedIdentityName : Already assigned with user managed identity"
    } else {
        if (!($PSCmdlet.ShouldProcess("($vmssResourceGroup) $vmssName, $userAssignedManagedIdentityName", "assign managed identity"))) {
            return $VMssObject
        }

        try {
            $VMssObject = Update-AzVmss -VMScaleSetName $vmssName `
                                    -ResourceGroupName $vmssResourceGroup `
                                    -VirtualMachineScaleSet $VMssObject `
                                    -IdentityType "UserAssigned" `
                                    -IdentityID $userAssignedManagedIdentityId `
                                   
        } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
            $exceptionInfo = $_.Exception.Message
            $errorCode = ParseCloudExceptionMessage($exceptionInfo)
            if ($errorCode -eq "FailedIdentityOperation") {
                throw [UserAssignedManagedIdentityDoesNotExist]::new("$userAssignedManagedIdentityName : User Assigned Managed Identity doesn't Exist or unaccessible.",$_.Exception)
            } elseif($errorCode -eq "ResourceGroupNotFound") {
                throw [ResourceGroupDoesNotExist]::new($vmssResourceGroupName,$_)       
            } elseif ($errorCode -eq "InvalidParameter") {
                throw [VirtualMachineScaleSetDoesNotExist]::new("($($VMssObject.ResourceGroupName) $($VMssObject.Name) : Virtual Machine Scale Set does not exist or unaccessible.",$_.Exception) 
            } else {
                throw [UnknownException]::new("($vmssResourceGroup) $vmssName, $userAssignedManagedIdentityName : Failed to user assign managed identity. ExceptionInfo = $exceptionInfo", $_.Exception)
            }
        }

        if ($VMssObject.ProvisioningState -ne "Succeeded") {
            throw [OperationFailed]::new("($vmssResourceGroup) $vmssName, $userAssignedManagedIdentityName : Failed to assign user assigned managed identity")
        }
        Write-Output "($vmssResourceGroup) $vmssName, $userAssignedManagedIdentityName : Successfully assigned user assign managed identity"
    }

    return $VMssObject
}

function AssignVmUserManagedIdentity {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMObject
    )

    $vmName = $VMObject.Name
    $vmResourceGroup = $VMObject.ResourceGroupName
    $userAssignedManagedIdentityName = $UserAssignedManagedIdentityObject.Name
    $userAssignedManagedIdentityId = $UserAssignedManagedIdentityObject.Id

    if (CheckUserManagedIdentityAlreadyAssigned -VMObject $VMObject `
                                                 -UserAssignedManagedIdentyId $userAssignedManagedIdentityId) {
        Write-Output "($vmResourceGroup) $vmName, $userAssignedManagedIdentityName : Already assigned with managed identity"
        return
    }
    
    if (!($PSCmdlet.ShouldProcess("($vmResourceGroup) $vmName", "assign managed identity $userAssignedManagedIdentityName"))) {
        return
    }

    try {
        $result = Update-AzVM -VM $VMObject `
                                -ResourceGroupName $vmResourceGroup `
                                -IdentityType "UserAssigned" `
                                -IdentityID $userAssignedManagedIdentityId `
                                                            
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $exceptionInfo = $_.Exception.Message
        $errorCode = ParseCloudExceptionMessage()
        if ($errorCode -eq "FailedIdentityOperation") {
            throw [UserAssignedManagedIdentityDoesNotExist]::new("$userAssignedManagedIdentityName : User Assigned Managed Identity doesn't Exist or unaccessible.",$_.Exception)
        } elseif($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($vmssResourceGroupName,$_)       
        } elseif ($errorCode -eq "InvalidParameter") {
            throw [VirtualMachineDoesNotExist]::new("($($VMObject.ResourceGroupName) $($VMObject.Name) : Virtual Machine does not exist or unaccessible.",$_.Exception) 
        } else {
            throw [UnknownException]::new("($vmResourceGroup) $vmName,$userAssignedManagedIdentityName : Failed to assign managed identity. Exception Info = $exceptionInfo", $_.Exception)
        }
    }

    if (!($result.IsSuccessStatusCode)) {
        throw [OperationFailed]::new("($vmResourceGroup) $vmName, $userAssignedManagedIdentityName : Failed to assign user assigned managed identity. StatusCode : $($result.StatusCode). ReasonPhrase : $($result.ReasonPhrase)")
    }
    
    Write-Output "($vmResourceGroup) $vmName, $userAssignedManagedIdentityName : Successfully assigned managed identity"
}

#recrusive prnting of inner exception messages.
function DisplayException {
    <#
    .SYNOPSIS
    Renders the given exception on the output.
    Does not throw any exceptions.
    .DESCRIPTION
    Renders the given exception.
    .EXAMPLE
    DisplayException $_
    .PARAMETER ex
    The exception.
    #>

    param (
        [Parameter(Mandatory=$True,Position=0)]
        [alias("Exception")]
        [System.Management.Automation.ErrorRecord]
        $ex,

        [Parameter(Mandatory=$False)]
        [alias("Message")]
        [string]
        $msg = "Exception"
    )

    try {
        "$($msg):" | Write-Output
        try { "StackTrace:`r`n$($_.Exception.StackTrace)`r`n" | Write-Verbose } catch { }
        try { "ScriptStackTrace:`r`n$($_.ScriptStackTrace)`r`n" | Write-Verbose } catch { }
        try { "Exception.HResult = 0x{0,0:x8}" -f $_.Exception.HResult | Write-Verbose } catch { }
        $ex | Write-Output
    }
    catch {
        # silently ignore
    }
}

function SetManagedIdentityRolesAma {
    param(
        [Parameter(Mandatory = $True)][Object]$UserAssignedManagedIdentityObject,
        [Parameter(Mandatory = $True)][String]$ResourceGroupName
    )

    #script block for assinging roles for mma, ama
    if ($ResourceGroupName) {
        try { 
            $rgObj = Get-AzResourceGroup -Name $ResourceGroupName
        } catch { 
            throw [FatalException]::new("$ResourceGroupName : Unable to lookup ResourceGroup")
        }
        try {
            SetManagedIdentityRoles -TargetScope $rgObj.ResourceId `
                                    -UserAssignedManagedIdentityObject $UserAssignedManagedIdentityObject
        } catch [ErrorResponseException] {
            $excepMessage = $_.Exception.Message
            if ($excepMessage.Contains('Conflict')) {
                Write-Verbose ("$userAssignedManagedIdentityName : $role has been assigned already")
            } elseif ($excepMessage.Contains('BadRequest')) {
                throw [FatalException]::new("$($UserAssignedManagedIdentity.Name) : User Assigned Managed Identity doesn't Exist or unaccessible.",$_.Exception) 
            } elseif ($excepMessage.Contains('NotFound')) {
                throw [FatalException]::new("$TargetScope : Target Scope does not exist",$_.Exception) 
            } else {
                throw [UnknownException]::new("$TargetScope : Failed to assign managed identity to targetScope. ExceptionInfo = $excepMessage", $_.Exception)
            }
        }    
    } else {
        $rgObjList = Get-AzResourceGroup
        ForEach ($rg in $rgObjList) {
            try {
                SetManagedIdentityRoles -TargetScope $rg.ResourceId `
                                     -UserAssignedManagedIdentityObject $UserAssignedManagedIdentityObject
            } catch [ErrorResponseException] {
                $excepMessage = $_.Exception.Message
                if ($excepMessage.Contains('Conflict')) {
                    Write-Verbose "$userAssignedManagedIdentityName : $role has been assigned already"
                } elseif ($excepMessage.Contains('BadRequest')) {
                    Write-Output "$($UserAssignedManagedIdentity.Name) : User Assigned Managed Identity doesn't Exist or unaccessible."
                } elseif ($excepMessage.Contains('NotFound')) {
                    Write-Output "$TargetScope : Target Scope does not exist"
                } else {
                    Write-Output "$TargetScope : Failed to assign managed identity to targetScope. ExceptionInfo = $excepMessage"
                }
            }
            finally {
                Write-Output ("$($rg.ResourceGroupName) : Continuing with next resource-group.")
            }
        }
    }
}

#
# Main Script
#
#
#
try {
    # First make sure we are authenticed and Select the subscription supplied and input parameters are valid.
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

    #script block
    Set-Variable -Name sb_nop_block_roles -Option Constant -Value { param($obj, $rg)} 
    Set-Variable -Name sb_nop_block -Option Constant -Value { param($obj, $osType) $obj}

    #Script Input Parameter Validation. 
    if ($PolicyAssignmentName) {
        try {
            Get-AzPoPolicyAssignmentNamelicyAssignment -Name $PolicyAssignmentName
        } catch [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.ErrorResponses.ErrorResponseMessageException] {
            throw [FatalException]::new("$PolicyAssignmentName : Invalid policyassignment name.")
        }
    } 
    
    if ($ResourceGroup) {
        try { 
            Get-AzResourceGroup -Name $ResourceGroup
        } catch { 
            throw [FatalException]::new("$ResourceGroup : Invalid ResourceGroup")
        }
    }

    if ($UserAssignedManagedIdentityName) {
        try {
            Write-Verbose "Validating ($UserAssignedManagedIdentityResourceGroup, $UserAssignedManagedIdentityName)"
            Set-Variable -Name UserAssignedIdentityObject -Option Constant -Value Get-AzUserAssignedIdentity -Name $UserAssignedManagedIdentityName `
                                                                    -ResourceGroupName $UserAssignedManagedIdentityResourceGroup
        } catch {
            throw [FatalException]::new($_.Exception.Message)
        }
    }
 
    if (!$isAma) {
        #Cannot validate Workspace existence with WorkspaceId, WorkspaceKey parameters.
        Set-Variable -Name laPublicSettings -Option Constant -Value @{"workspaceId" = $WorkspaceId; "stopOnMultipleConnections" = "true"}
        Set-Variable -Name laProtectedSettings -Option Constant -Value  @{"workspaceKey" = $WorkspaceKey}
        if ($ReInstall) {
            Set-Variable -Name sb_vm -Option Constant -Value { param($vmObj, $osType); OnboardVmiWithLaVmWithReInstall -VMObject $vmObj  @($laExtensionMap[$osType])}
        } else {
            Set-Variable -Name sb_vm -Option Constant -Value { param($vmObj, $osType); OnboardVmiWithLaVmWithoutReInstall -VMObject $vmObj @($laExtensionMap[$osType])}
        }
        
        Set-Variable -Name sb_vmss -Option Constant -Value { param($vmssObj, $osType); OnboardVmiWithLaVmss -VMssObject $vmssObj @($laExtensionMap[$osType])}
        Set-Variable -Name sb_da -Option Constant -Value { param($vmObj, $osType);  Onboard-DaVm -VMObject $vmObj -DaExtensionType @($daExtensionMap[$osType])}
        Set-Variable -Name sb_da_vmss -Option Constant -Value { param($vmssObj, $osType); OnboardDaVmss -VMssObject $vmssObj @($daExtensionMap[$osType])}
        Set-Variable -Name sb_roles -Option Constant -Value $sb_nop_block_roles
    } else {
        #VMI supports Customers onboarding DCR from different subscription
        #Cannot validate DCRResourceId as parameter set ByResourceId will be deprecated for - Get-AzDataCollectionRule
        #move to scrpit valid block.
        
        Set-Variable -Name amaPublicSettings -Option Constant -Value @{'authentication' = @{
                        'managedIdentity' = @{
                        'identifier-name' = 'mi_res_id'
                        'identifier-value' = $($userAssignedIdentityObject.Id) 
                        }
                    }
                }
    
        Set-Variable -Name sb_vm -Option Constant -Value { param($vmObj, $osType); OnboardVmiWithAmaVm -VMObject $vmObj @($amaExtensionMap[$osType])}
        Set-Variable -Name sb_vmss -Option Constant -Value { param($vmssObj, $osType); OnboardVmiWithAmaVmss -VMssObject $vmssObj @($amaExtensionMap[$osType])}
        
        if ($ProcessAndDependencies) {
            Set-Variable -Name sb_da -Option Constant -Value { param($vmObj, $osType); OnboardDaWithAmaSettingsVm -VMObject $vmObj @($daExtensionMap[$osType]) }
            Set-Variable -Name sb_da_vmss -Option Constant -Value { param($vmssObj, $osType); OnboardDaWithAmaSettingsVmss -VMObject $vmObj @($daExtensionMap[$osType]) }
        } else {
            Set-Variable -Name sb_da -Option Constant -Value $sb_nop_block
            Set-Variable -Name sb_da_vmss  -Option Constant -Value $sb_nop_block
        }
        
        if ($TriggerVmssManualVMUpdate) {
            Set-Variable -Name sb_upgrade -Option Constant -Value { param($vmssObj);  UpgradeVmssExtensionManualUpdateEnabled -VMssObject $vmssObj}
        } else {
            Set-Variable -Name sb_upgrade -Option Constant -Value $sb_nop_block
        }
        # remove - in function Names to differentiate cmdlets from user defined function
        Set-Variable -Name sb_roles -Option Constant -Value { param($uamiObj, $rgName) SetManagedIdentityRolesAma -UserAssignedManagedIdentityObject $uamiObj -ResourceGroupName $rgName}
    }

    $Rghashtable = @{}
    # To report on overall status
    $OnboardingStatus = @{
        Succeeded = 0;
        Total     = 0;
    }

    if ($PolicyAssignmentName) {
        #this section is only for VMs
        try {
            $complianceResults = Get-AzPolicyState -PolicyAssignmentName $PolicyAssignmentName
        } catch [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.ErrorResponses.ErrorResponseMessageException] {
            throw [PolicyAssignmentDoesNoExist]::new("$PolicyAssignmentName : Policy Assignment does not exist.",$_)
        }

        foreach ($result in $complianceResults) {
            Write-Verbose($result.ResourceId)
            Write-Verbose($result.ResourceType)
            if ($result.SubscriptionId -ne $SubscriptionId) {
                Write-Output("VM is not in same subscription, this scenario is not currently supported. Skipping this VM.")
                continue
            }

            $vmName = $result.ResourceId.split('/')[8]
            $vmResourceGroup = $result.ResourceId.split('/')[4]

            if ($ResourceGroup -and $ResourceGroup -ne $vmResourceGroup) { continue }
            if ($Name -and $Name -ne $vmName) { continue }

            $vm = Get-AzVM -Name $vmName -ResourceGroupName $vmResourceGroup
            $vmStatus = Get-AzVM -Status -Name $vmName -ResourceGroupName $vmResourceGroup
            # fix to have same property as VM that is retrieved without Name
            $vm | Add-Member -NotePropertyName PowerState -NotePropertyValue $vmStatus.Statuses[1].DisplayStatus

            if ($vm.PowerState -ne 'VM running') {
                continue
            }

            if ($Rghashtable.ContainsKey($vmResourceGroup)) {
                $Rghashtable[$vmResourceGroup]["VirtualMachine"] += @($vm)
            } else {
                $Rghashtable.add($vmResourceGroup,@{"VirtualMachine" = @($vm)})
            }            
        }
    } else {
        Write-Output "Getting list of VM's or VM ScaleSets matching criteria specified"
        # If ResourceGroup value is passed - select all VMs under given ResourceGroupName
        $searchParameters = @{}
        if ($ResourceGroup) {
            $searchParameters.add("ResourceGroupName", $ResourceGroup)
        }
       
        #Virtual Machines not running and those part of a virtual machine scale set will be skipped.
        $Vms = Get-AzVM -Status @searchParameters |
                Where-Object {$_.PowerState -eq 'VM running' -and !($_.VirtualMachineScaleSet)}

        if ($Name) {
            $Vms = $Vms | Where-Object {$_.Name -like $Name}
        }

        $OnboardingStatus.Total += $Vms.Length
        $Vmss = Get-AzVmss @searchParameters
        
        if ($Name) {
            $Vmss = $Vmss | Where-Object {$_.Name -like $Name}
        }
        
        $OnboardingStatus.Total += $Vmss.Length
        #one hashtable with key as rg and has 2 list of values as list of Vms and VMss.
        Write-Output "VMs and VMSS in a non-running state will be skipped."
        Write-Output "" "VM's matching selection criteria:" ""
        Foreach ($vm in $Vms) {
            $rg = $vm.ResourceGroupName
            if ($Rghashtable.ContainsKey($rg)) {
                $Rghashtable[$rg]["VirtualMachine"] += @($vm)
            } else {
                $Rghashtable.add($rg,@{"VirtualMachine" = @($vm)})
            }
            Write-Output "$rg $($vm.Name) : $($vm.PowerState)"
        }
        
        Write-Output "" "VM ScaleSets matching selection criteria:" ""
        Foreach ($vmss in $Vmss) {
            $rg = $vmss.ResourceGroupName
            if ($Rghashtable.ContainsKey($rg)) {
                $Rghashtable[$rg]["VirtualMachineScaleSet"] += @($vm)
            } else {
                $Rghashtable.add($rg,@{"VirtualMachineScaleSet" = @($vm)})
            }
            Write-Output "$rg $($vmss.Name) : $($vmss.PowerState)"
        }
        Write-Output ""
    }
    
    # Validate customer wants to continue
    if ($Approve -or $PSCmdlet.ShouldContinue("Continue?", "")) {
        Write-Output ""
    } else {
        Write-Output "You selected No - exiting"
        return
    }
    
    ForEach ($rgItem in $Rghashtable) {
        try {        
            
            &$sb_roles -uamiObj $userAssignedIdentityObject -rgName $rgItem
            $Vms = $Vmshashtable[$rgItem]["VirtualMachine"]
            $Vmss= $Vmsshashtable[$rgItem]["VirtualMachineScaleSet"]

            Foreach ($vm in $Vms) {
                try {
                    $osType = $vm.StorageProfile.OsDisk.OsType
                    $vm = &$sb_vm -vmObj $vm -osType $osType
                    $vm = &$sb_da -vmObj $vm -osType $osType
                    Write-Output "($($vm.ResourceGroupName)) $($vm.Name) : Successfully onboarded VMInsights"
                    $OnboardingStatus.Succeeded +=1
                } catch [VirtualMachineDoesNotExist] {
                    Write-Output $_.Exception.Message
                    Write-Verbose $_.Exception.InnerException.StackTrace
                    Write-Output "Continuing to the next Virtual Machine..."
                } catch [OperationFailed] {
                    Write-Output $_.Exception.Message
                    Write-Output "Please consider raising a support against owning service - 'VMInsights and Service-Map' if issue persists" 
                    Write-Output "Continuing to the next Virtual Machine..."
                } catch [UnknownException] {
                    Write-Output "UnknownException :"
                    Write-Output $_.Exception.Message
                    Write-Verbose $_.Exception.InnerException.StackTrace
                    Write-Output "Please consider raising a support against owning service - 'VMInsights and Service-Map' if issue persists" 
                    Write-Output "Continuing to the next Virtual Machine..."
                }
            }

            Foreach ($vmss in $Vmss) {
                try {
                    $osType = $vmss.storageprofile.osdisk.ostype
                    $vmss = &$sb_vmss -vmssObj $vmss -osType $osType
                    $vmss = &$sb_da_vmss -vmssObj $vmss -osType $osType
                    &$sb_upgrade -vmssObj $vmss
                    Write-Output "($($vmss.ResourceGroupName)) $($vmss.Name) : Successfully onboarded VMInsights"
                    $OnboardingStatus.Succeeded +=1
                }  catch [VirtualMachineScaleSetDoesNotExist] {
                    Write-Output $_.Exception.Message
                    Write-Verbose $_.Exception.InnerException.StackTrace
                    Write-Output "Continuing to the next Virtual Machine Scale Set..."
                } catch [OperationFailed] {
                    Write-Output $_.Exception.Message
                    Write-Output "Please consider raising a support against owning service - 'VMInsights and Service-Map' if issue persists" 
                    Write-Output "Continuing to the next Virtual Machine Scale Set..."
                } catch [UnknownException] {
                    Write-Output "UnknownException :"
                    Write-Output $_.Exception.Message
                    Write-Verbose $_.Exception.InnerException.StackTrace
                    Write-Output "Please consider raising a support against owning service - 'VMInsights and Service-Map' if issue persists" 
                    Write-Output "Continuing to the next Virtual Machine Scale Set..."
                }
            }
        } catch [ResourceGroupDoesNotExist] {
            Write-Output $_.Exception.Message
            Write-Verbose $_.Exception.StackTrace
            Write-Output "Continuing to the next Resource-Group..."
        }
    }
}
catch [FatalException] {
    Write-Output "FatalException :"
    Write-Output $_.Exception.Message
    Write-Verbose $_.Exception.InnerException.StackTrace
    Write-Output "Exiting the script..."
    exit 1
}
catch {
    DisplayException $_
    Write-Output "Exiting the script..."
    exit 1
}
finally {
    PrintSummaryMessage $OnboardingStatus
}
