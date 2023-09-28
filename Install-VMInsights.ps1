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
    
    
    [Parameter(mandatory = $False, ParameterSetName = 'AzureMonitoringAgent')]
    [Parameter(mandatory = $False, ParameterSetName = 'NonPolicyAssignment')]
    [Parameter(mandatory = $False, ParameterSetName = 'PolicyAssignment')]
    [Switch]$ProcessAndDependencies,
    [Parameter(mandatory = $True, ParameterSetName = 'AzureMonitoringAgent')]
    [Parameter(mandatory = $True, ParameterSetName = 'NonPolicyAssignment')]
    [Parameter(mandatory = $True, ParameterSetName = 'PolicyAssignment')]
    [String]$DcrResourceId,
    [Parameter(mandatory = $True, ParameterSetName = 'AzureMonitoringAgent')]
    [Parameter(mandatory = $True, ParameterSetName = 'NonPolicyAssignment')]
    [Parameter(mandatory = $True, ParameterSetName = 'PolicyAssignment')]
    [String]$UserAssignedManagedIdentityResourceGroup,
    [Parameter(mandatory = $True, ParameterSetName = 'AzureMonitoringAgent')]
    [Parameter(mandatory = $True, ParameterSetName = 'NonPolicyAssignment')]
    [Parameter(mandatory = $True, ParameterSetName = 'PolicyAssignment')]
    [String]$UserAssignedManagedIdentityName,

    [Parameter(mandatory = $True,  ParameterSetName = 'LogAnalyticsAgent')]
    [Parameter(mandatory = $True, ParameterSetName = 'PolicyAssignment')]
    [Parameter(mandatory = $True, ParameterSetName = 'NonPolicyAssignment')]
    [String]$WorkspaceId,
    [Parameter(mandatory = $True,  ParameterSetName = 'LogAnalyticsAgent')]
    [Parameter(mandatory = $True, ParameterSetName = 'PolicyAssignment')]
    [Parameter(mandatory = $True, ParameterSetName = 'NonPolicyAssignment')]
    [String]$WorkspaceKey,
    [Parameter(mandatory = $False, ParameterSetName = 'LogAnalyticsAgent')]
    [Parameter(mandatory = $False, ParameterSetName = 'NonPolicyAssignment')]
    [Parameter(mandatory = $False, ParameterSetName = 'PolicyAssignment')]
    [Switch]$ReInstall
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
    FatalException($errorMessage) : base($errorMessage) {}
    FatalException($errorMessage, $innerException) : base($errorMessage, $innerException) {}
}

class UnknownException : System.Exception {
    UnknownException($errorMessage, $innerException) : base($errorMessage, $innerException) {}
    UnknownException($vmObject, $errorMessage, $innerException) : base((ExtractVmInformation -VMObject $vmObject -Message $errorMessage), $innerException) {}
}

class VirtualMachineDoesNotExist : System.Exception {
    $errorMessage = "Virtual Machine does not exist or unaccessible."
    VirtualMachineDoesNotExist ($vmObject, $innerException) : base((ExtractVmInformation -VMObject $vmObject -Message $errorMessage) , $innerException) {}
}

class VirtualMachineScaleSetDoesNotExist : System.Exception {
    $errorMessage = "Virtual Machine Scale Set does not exist or unaccessible."
    VirtualMachineScaleSetDoesNotExist ($vmssObject, $innerException) : base((ExtractVmInformation -VMObject $vmssObject -Message $errorMessage) , $innerException) {}
}

class ResourceGroupDoesNotExist : System.Exception {
    ResourceGroupDoesNotExist ($vmObject, $innerException) : base("$($vmObject.ResourceGroupName) : Does not exist or unaccessible." , $innerException) {}
}

class OperationFailed : System.Exception {
    OperationFailed($vmObject, $errorMessage) : base((ExtractVmInformation -VMObject $vmObject -Message $errorMessage)) {}
}

class DataCollectionRuleForbidden : FatalException {
    DataCollectionRuleForbidden($dcrResourceId, $innerException) : base("$dcrResourceId : Access to data collection rule is forbidden", $innerException) {}
}

class DataCollectionRuleDoesNotExist : FatalException {
    DataCollectionRuleDoesNotExist($dcrResourceId, $innerException) : base("$dcrResourceId : Data Collection Rule does not exist.", $innerException) {}
}

class DataCollectionRuleIncorrect : FatalException {
    DataCollectionRuleIncorrect($dcrResourceId, $innerException) : base("$dcrResourceId : Data Collection Rule does not exist." , $innerException) {}
}

class PolicyAssignmentDoesNoExist : FatalException {
    PolicyAssignmentDoesNoExist($policyAssignmentName, $innerException) : base("$policyAssignmentName : Policy Assignment does not exist.", $innerException) {}
}

class UserAssignedManagedIdentityDoesNotExist : FatalException {
    UserAssignedManagedIdentityDoesNotExist($uamiobj, $innerException) : base("$($uamiobj.Name) : User Assigned Managed Identity doesn't Exist or unaccessible.", $innerException) {}
}

class ResourceGroupTableElement {
    [System.Collections.ArrayList] $VirtualMachineList
    [System.Collections.ArrayList] $VirtualMachineScaleSetList
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
    Write-Output "Succeeded : $($OnboardingStatus.Succeeded)"
    Write-Output "Failed : $($($OnboardingStatus.Total) - $OnboardingStatus.Succeeded)"
}

function ExtractCloudExceptionMessage {
    param
    (
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    $errorMessage = $ErrorRecord.Exception.Message
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
        [Parameter(mandatory = $True)][String]$ExtensionType,
        [Parameter(mandatory = $True)][String]$ExtensionPublisher
    )

    try {
        $extensions = Get-AzVMExtension -ResourceGroupName $vmResourceGroupName -VMName $vmName
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        #we are not parsing cloud exception, rather we are extracting it.
        $errorCode = ExtractCloudExceptionMessage -ErrorRecord $_
        if ($errorCode -eq "ParentResourceNotFound") {
            throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
        } elseif ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMObject,$_.Exception)   
        } else {
            throw [UnknownException]::new($VMObject, "Failed to lookup extension with type = $ExtensionType, publisher = $ExtensionPublisher", $_.Exception)
        }
    }
    
    foreach ($extension in $extensions) {
        if ($ExtensionType -eq $extension.ExtensionType -and $ExtensionPublisher -eq $extension.Publisher) {
            ScriptLog -VMObject $VMObject -Message "Extension with type = $ExtensionType, publisher = $ExtensionPublisher" -Verbose
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
        [Parameter(mandatory = $True)][String]$ExtensionType,
        [Parameter(mandatory = $True)][String]$ExtensionPublisher
    )

    foreach ($extension in $VMssObject.VirtualMachineProfile.ExtensionProfile.Extensions) {
        if ($ExtensionType -eq $extension.Type -and $ExtensionPublisher -eq $extension.Publisher) {
            ScriptLog -VMObject $VMObject -Message "Extension with type = $ExtensionType , publisher = $ExtensionPublisher found"
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
        [Parameter(mandatory = $True)][String]$ExtensionName
    )

    $vmResourceGroupName = $VMObject.ResourceGroupName
    $vmName = $VMObject.VMName
    
    if (!$PSCmdlet.ShouldProcess("($vmResourceGroupName) $vmName", "Remove $ExtensionName")) {
        return
    }

    try {
        #Remove operation on non existent VM, extension still return a success
        $removeResult = Remove-AzVMExtension -ResourceGroupName $vmResourceGroupName -VMName $vmName -Name $ExtensionName -Force
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractCloudExceptionMessage($_)
        if($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMObject,$_.Exception)       
        } 
        
        throw [UnknownException]::new($VMObject, "Failed to remove extension $ExtensionName", $_.Exception)
    }
    
    if ($removeResult.IsSuccessStatusCode) {
        ScriptLog -VMObject $VMObject -Message "Successfully removed extension $ExtensionName" -Verbose
        return
    }

    throw [OperationFailed]::new($VMObject, "Failed to remove extension $ExtensionName. StatusCode = $($removeResult.StatusCode). ReasonPhrase = $($removeResult.ReasonPhrase)")
}

function NewDCRAssociation {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject
    )

    $vmId = $VMObject.Id
    $invalidOperationParserPattern = "status code (.*)"
    $vmResourceGroupName = $VMObject.ResourceGroupName
    $vmName =  $VMObject.Name

    try {
        # A VM may have zero or more Data Collection Rule Associations
        $dcrAssociationList = Get-AzDataCollectionRuleAssociation -TargetResourceId $vmId
    } catch [System.Management.Automation.ParameterBindingException] {
        throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
    }

    # A VM may have zero or more Data Collection Rule Associations
    foreach ($dcrAssociation in $dcrAssociationList) {
        if ($dcrAssociation.DataCollectionRuleId -eq $DcrResourceId) {
            ScriptLog -VMObject $VMObject -Message "Data Collection Rule $($dcrAssociation.Name) already associated to the VM"
            return $VMObject
        }
    }

    #The Customer is responsible to uninstall the DCR Association themselves
    if (!($PSCmdlet.ShouldProcess("($vmResourceGroupName) $vmName", "Install Data Collection Rule Association"))) {
        return $VMObject
    }

    $dcrassociationName = "VM-Insights-DCR-Association"
    ScriptLog -VMObject $VMObject -Message "Deploying Data Collection Rule Association $dcrassociationName" -Verbose
    try {
        $dcrassociation = New-AzDataCollectionRuleAssociation -TargetResourceId $vmId -AssociationName $dcrassociationName -RuleId $DcrResourceId
    } catch [System.Management.Automation.PSInvalidOperationException] {
        $exceptionMessage = $_.Exception.InnerException.Message
        
        if ($exceptionMessage.Contains('Invalid format of the resource identifier')) {
            throw [DataCollectionRuleIncorrect]::new($DcrResourceId)
        } elseif (!($exceptionMessage -match $invalidOperationParserPattern)){
            throw [UnknownException]::new($VMObject, "Failed to create data collection rule association with $DcrResourceId", $_.Exception)
        } else {
            $statusCode = $matches[1]
            if ($statusCode -eq 'BadRequest') {
                throw [DataCollectionRuleDoesNotExist]::new($DcrResourceId, $_.Exception)
            } elseif ($statusCode -eq 'NotFound') {
                throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
            } elseif ($statusCode -eq 'Forbidden') {
                throw [DataCollectionRuleForbidden]::new($DcrResourceId, $_.Exception)     
            } else {
                throw [UnknownException]::new($VMObject, "Failed to create data collection rule association with with $DcrResourceId. StatusCode = $statusCode", $_.Exception)
            }
        }
    }
    #Tmp fix task:- 21191002
    if (!$dcrassociation -or $dcrassociation -is [Microsoft.Azure.Management.Monitor.Models.ErrorResponseCommonV2Exception]) {
        throw [UnknownException]::new($VMObject, "Failed to create data collection rule association with $DcrResourceId", $dcrassociation)
    }

    return $VMObject
}

function OnboardDaVm {
    <#
	.SYNOPSIS
	Install DA (VM) on AMA with ProcessingAndDependencies Enabled, handling if already installed
	#>
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject,
        [Parameter(mandatory = $False)][Object]$Settings
    )

    $osType = $VMObject.StorageProfile.OsDisk.OsType
    $daExtensionType = $daExtensionMap[$osType].DaExtensionType
    $daExtensionVersion = $daExtensionMap[$osType].DaExtensionVersion
    $extensionName = $daExtensionName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionType $daExtensionType -ExtensionPublisher $daExtensionPublisher

    if ($extension) {
        $extensionName = $extension.Name
        ScriptLog -VMObject $VMObject -Message "Extension $extensionName already installed." -Verbose   
    }
    
    $parameters = @{
        Publisher          = $daExtensionPublisher
        ExtensionType      = $daExtensionType
        ExtensionName      = $extensionName
        TypeHandlerVersion = $daExtensionVersion
    }

    if (Settings) {
        $parameters.add("Settings", $processAndDependenciesPublicSettings)
    }
    return InstallVMExtension -VMObject $VMObject -InstallParameters $parameters
}

function OnboardDaWithAmaSettingsVm {
    <#
	.SYNOPSIS
	Install DA (VM) on AMA with ProcessingAndDependencies Enabled, handling if already installed
	#>
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject
    )

    return OnboardDaVm -VMObject $VMObject -Settings $processAndDependenciesPublicSettings
}

function OnboardDaLaSettingsVm {
    <#
	.SYNOPSIS
	Install DA (VM) with LA settings, handling if already installed
	#>
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject
    )

    return OnboardDaVm -VMObject $VMObject
}

function InstallVMssExtension {
    <#
	.SYNOPSIS
	Install Extension (VMSS), handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject,
        [Parameter(mandatory = $True)][String]$ExtensionName,
        [Parameter(mandatory = $True)][String]$ExtensionVersion,
        [Parameter(mandatory = $True)][String]$ExtensionType,
        [Parameter(mandatory = $True)][String]$ExtensionPublisher,
        [Parameter(mandatory = $False)][Hashtable]$Settings,
        [Parameter(mandatory = $False)][Hashtable]$ProtectedSettings
    )

    $extension = GetVMssExtension -VMssObject $VMssObject -ExtensionType $ExtensionType -ExtensionPublisher $ExtensionPublisher

    if ($extension) {
        ScriptLog -VMObject $VMObject -Message "Extension $($extension.Name) with name already installed."
        if ($Settings) {
            $extension.Settings = $Settings
        }
        
        if ($ProtectedSettings) {
            $extension.ProtectedSetting = $ProtectedSettings
        }

        $extension.TypeHandlerVersion = $ExtensionVersion
        $VMssObject =  UpdateVMssExtension -VMssObject $VMssObject
    } else {

        if (!($PSCmdlet.ShouldProcess("$($VMssObject.ResourceGroupName) $($VMssObject.Name)", "install extension $extensionName"))) {
            return $VMssObject
        }
        
        $parameters = @{
            VirtualMachineScaleSet  = $VMssObject
            Name                    = $ExtensionName
            Publisher               = $ExtensionPublisher
            Type                    = $ExtensionType 
            TypeHandlerVersion      = $ExtensionVersion
        }
        
        if ($Settings) {
            $parameters.add("Settings", $Settings)
        }
        
        if ($ProtectedSettings) {
            $parameters.add("ProtectedSettings", $ProtectedSettings)
        }

        $VMssObject = Add-AzVmssExtension @parameters -AutoUpgradeMinorVersion $True
        ScriptLog -VMObject $VMObject -Message "$extensionName added"
    }

    return $VMssObject
}

function OnboardDaVmss {
    <#
	.SYNOPSIS
	Install DA (VMSS)
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject,
        [Parameter(mandatory = $False)][HashTable]$Settings
    )
    
    $osType = $VMObject.StorageProfile.OsDisk.OsType
    $daExtensionType = $daExtensionMap[$osType].DaExtensionType
    $daExtensionVersion = $daExtensionMap[$osType].DaExtensionVersion

    $parameters = @{
        VirtualMachineScaleSet  = $VMssObject
        ExtensionName           = $daExtensionName
        Publisher               = $daExtensionPublisher
        Type                    = $daExtensionType 
        TypeHandlerVersion      = $daExtensionVersion
    }
    
    if ($Settings) {
        $parameters.add("Settings", $Settings)
    }

    return InstallVMssExtension @parameters
}

function OnboardDaWithAmaSettingsVmss {
    <#
	.SYNOPSIS
	Install DA (VMSS), handling if already installed
	#>
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject
    )
    
    return OnboardDaVmss -VMssObject $VMssObject -Settings $processAndDependenciesPublicSettings
}

function OnboardDaLaSettingsVmss {
     <#
	.SYNOPSIS
	Install DA (VMss) with LA settings, handling if already installed
	#>
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject
    )
    
    return OnboardDaVmss -VMssObject $VMssObject
}

function InstallAmaVm {
    <#
	.SYNOPSIS
	Install AMA (VMSS), handling if already installed
	#>
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject
    )

    $osType = $VMObject.StorageProfile.OsDisk.OsType
    $amaExtensionType = $amaExtensionMap[$osType].AmaExtensionType
    $amaExtensionVersion = $amaExtensionMap[$osType].AmaExtensionVersion
    # Use supplied name unless already deployed, use same name
    $extensionName = $amaExtensionName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionType $amaExtensionType -ExtensionPublisher $amaExtensionPublisher
    
    if ($extension) {
        $extensionName = $extension.Name
        ScriptLog -VMObject $VMObject -Message "Extension $extensionName already installed. Provisioning State: $($extension.ProvisioningState)" -Verbose
    }

    $parameters = @{
        Publisher          = $amaExtensionPublisher
        ExtensionType      = $amaExtensionType
        Name               = $extensionName
        TypeHandlerVersion = $amaExtensionVersion
        Settings           = $amaPublicSettings
    }

    return InstallVMExtension -VMObject $VMObject InstallParameters $parameters 
}

function OnboardVmiWithLaVmWithReInstall {
    <#
	.SYNOPSIS
	Install OMS Extension on Virtual Machines, handling if already installed
	#>
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject
    )

    $osType = $VMObject.StorageProfile.OsDisk.OsType
    $laExtensionType = $laExtensionMap[$osType].laExtensionType
    $laExtensionVersion = $laExtensionMap[$osType].laExtensionVersion
    # Use supplied name unless already deployed, use same name
    $extensionName = $laExtensionName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionType $laExtensionType -ExtensionPublisher $laExtensionPublisher

    if ($extension) {
        $extensionName = $extension.Name
        if ($osType -eq "Linux" -and !($extension.Settings.Contains($laPublicSettings.workspaceId))) {
            ScriptLog -VMObject $VMObject -Message "OmsAgentForLinux does not support updating workspace. An uninstall followed by re-install is required"
            RemoveVMExtension -VMObject $VMObject `
                                -ExtensionType $laExtensionType
        }
    }
    
    $parameters = @{
        Publisher          = $laExtensionPublisher
        ExtensionType      = $laExtensionType
        ExtensionName      = $extensionName
        TypeHandlerVersion = $laExtensionVersion
        Settings           = $laPublicSettings
        ProtectedSettings  = $laProtectedSettings
    }

    return InstallVMExtension -VMObject $VMObject -InstallParameters $parameters
}

function OnboardVmiWithLaVmWithoutReIntall {
    <#
	.SYNOPSIS
	Install OMS Extension on Virtual Machines, handling if already installed
	#>
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject
    )

    $osType = $VMObject.StorageProfile.OsDisk.OsType
    $laExtensionType = $laExtensionMap[$osType].laExtensionType
    $laExtensionVersion = $laExtensionMap[$osType].laExtensionVersion
    # Use supplied name unless already deployed, use same name
    $extensionName = $laExtensionName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionType $laExtensionType -ExtensionPublisher $laExtensionPublisher

    if ($extension) {
        $extensionName = $extension.Name
        if ($osType -eq "Linux" -and !($extension.Settings.Contains($laPublicSettings.workspaceId))) {
            ScriptLog -VMObject $VMObject -Message "OmsAgentForLinux does not support updating workspace. Please try again with Re-Install Flag"
            return $VMObject
        }
    }

    $parameters = @{
        Publisher          = $laExtensionPublisher
        ExtensionType      = $laExtensionType
        ExtensionName      = $extensionName
        TypeHandlerVersion = $laExtensionVersion
        Settings           = $laPublicSettings
        ProtectedSettings  = $laProtectedSettings
    }

    return InstallVMExtension -VMObject $VMObject -InstallParameters $parameters
}

function InstallAmaVMss {
    <#
	.SYNOPSIS
	Install AMA (VMSS), handling if already installed
	#>
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject
    )

    $osType = $VMObject.StorageProfile.OsDisk.OsType
    $amaExtensionType = $amaExtensionMap[$osType].AmaExtensionType
    $amaExtensionVersion = $amaExtensionMap[$osType].AmaExtensionVersion

    $parameters = @{
        VirtualMachineScaleSet  = $VMssObject
        ExtensionName           = $amaExtensionName
        Publisher               = $amaExtensionPublisher
        Type                    = $amaExtensionType 
        TypeHandlerVersion      = $amaExtensionVersion
        Settings                = $processAndDependenciesPublicSettings
    }
    
    return InstallVMssExtension @parameters
}

function OnboardVmiWithLaVmss {
    <#
	.SYNOPSIS
	Install LA (VMSS), handling if already installed
	#>
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject
    )

    $osType = $VMObject.StorageProfile.OsDisk.OsType
    $laExtensionType = $laExtensionMap[$osType].LaExtensionType
    $laExtensionVersion = $laExtensionMap[$osType].LaExtensionVersion

    $parameters = @{
        VirtualMachineScaleSet  = $VMssObject
        ExtensionName           = $laExtensionName
        Publisher               = $laExtensionPublisher
        Type                    = $laExtensionType 
        TypeHandlerVersion      = $laExtensionVersion
        Settings                = $laPublicSettings
        ProtectedSetting        = $laProtectedSettings
    }

    return InstallVMssExtension @parameters
}

function OnboardVmiWithAmaVm {
    <#
	.SYNOPSIS
	Onboard VMI with AMA on Vms
	#>
    param
    (
        [Parameter(mandatory = $True)][Object]$VMObject
    )

    AssignVmUserManagedIdentity -VMssObject $VMObject
    NewDCRAssociation -VMObject $VMObject
    return InstallAmaVm -VMObject $VMObject
}

function OnboardVmiWithAmaVmss {
    <#
	.SYNOPSIS
	Onboard VMI with AMA on VMSS
	#>
    param
    (
        [Parameter(mandatory = $True)][Object]$VMssObject
    )
            
    $VMssObject = AssignVmssManagedIdentity -VMssObject $VMssObject
    NewDCRAssociation -VMObject $VMssObject
    return InstallAmaVMss -VMssObject $VMssObject
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
    
    if (!($PSCmdlet.ShouldProcess($TargetScope, "assign roles $roleDefinitionList to user assigned managed identity : $userAssignedManagedIdentityName"))) {
        return
    }

    foreach ($role in $roleDefinitionList) {
        $roleAssignmentFound = Get-AzRoleAssignment -ObjectId $userAssignedManagedIdentityId -RoleDefinitionName $role -Scope $TargetScope
        if ($roleAssignmentFound) {
            Write-Verbose "Scope $targetScope, $role : role already set"
        } else {
            Write-Verbose "Scope $targetScope, $role : assigning role"
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
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)][Object] $VMObject,
        [Parameter(mandatory = $True)][Object] $InstallParameters
    )

    $extensionName = $InstallParameters.ExtensionName
    
    if (!($PSCmdlet.ShouldProcess("$($VMObject.ResourceGroupName) $($VMObject.Name)", "install extension $extensionName"))) {
        return $VMObject
    }

    ScriptLog -VMObject $VMObject -Message "Deploying/Updating extension $extensionName" -Verbose
    
    try {
        $result = Set-AzVMExtension -ResourceGroupName $($VMObject.ResourceGroupName) -VMName $($VMObject.Name) @InstallParameters -ForceRerun $True
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractCloudExceptionMessage -ErrorRecord $_
        if ($errorCode -eq "ParentResourceNotFound") {
            throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
        } 
        
        if($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMObject, $_.Exception)       
        } 
        
        throw [UnknownException]::new($VMObject, "Failed to update/install extension $extensionName", $_.Exception)
    }

    if ($result.IsSuccessStatusCode) {
        ScriptLog -VMObject $VMObject -Message "Successfully deployed/updated extension"
        return $VMObject
    }

    throw [OperationFailed]::new($VMObject, "Failed to update extension. StatusCode = $($removeResult.StatusCode). ReasonPhrase = $($removeResult.ReasonPhrase)")
}

function UpgradeVmssExtensionWithoutManualUpdate {
    <#
	.SYNOPSIS
	Upgrade VMss Extension
	#>
    param
    (
        [Parameter(mandatory = $True)][Object]$VMssObject
    )

    if ($VMssObject.UpgradePolicy.Mode -ne 'Manual') {
        ScriptLog -VMObject $VMObject -Message "Upgrade mode not Manual. $($VMssObject.UpgradePolicy.Mode)"
        return
    }

    ScriptLog -VMObject $VMObject -Message  "UpgradePolicy is Manual. Please trigger upgrade of VM Scale Set or call with -TriggerVmssManualVMUpdate"
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
    
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    $vmssName = $VMssObject.Name

    if ($VMssObject.UpgradePolicy.Mode -ne 'Manual') {
        ScriptLog -VMssObject $VMObject -Message "Upgrade mode not Manual. $($VMssObject.UpgradePolicy.Mode)"
        return
    }

    try {
        $scaleSetInstances = Get-AzVmssVm -ResourceGroupName $vmssResourceGroupName -VMScaleSetName $vmssName -InstanceView
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractCloudExceptionMessage($_)
        if ($errorCode -eq "ParentResourceNotFound") {
            throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception)
        } elseif ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMssObject, $_.Exception)       
        } else {
            throw [UnknownException]::new($VMssObject, "Failed to upgrade virtual machine scale set", $_.Exception)
        }
    }

    $i = 0
    $instanceCount = $scaleSetInstances.Length
    Foreach ($scaleSetInstance in $scaleSetInstances) {
        if ($scaleSetInstance.LatestModelApplied) {
            continue
        }
        $i++
        ScriptLog -VMObject $VMssObject -Message "$($scaleSetInstance.Name) Updating instance $i of $instanceCount"
        try {
            if (!($PSCmdlet.ShouldProcess("($vmssResourceGroupName) $vmssName", "Upgrading virtual machine scale set instance $($scaleSetInstance.Name)"))) {
                return
            }
            $result = Update-AzVmssInstance -ResourceGroupName $vmssResourceGroupName -VMScaleSetName $vmssName -InstanceId $scaleSetInstance.InstanceId
            if ($result.Status -ne "Succeeded") {
                Write-Output "($vmssResourceGroupName) $vmssName $($scaleSetInstance.Name) : Failed to upgrade virtual machine scale set instance. $($result.Status)"
            }
        } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
            $errorCode = ExtractCloudExceptionMessage($_)
            if ($errorCode -eq "ResourceNotFound") {
                throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception)
            } elseif($errorCode -eq "ResourceGroupNotFound") {
                throw [ResourceGroupDoesNotExist]::new($VMssObject ,$_.Exception)  
            } elseif($errorCode -eq "OperationNotAllowed") {
                Write-Output "Unable to lookup VMSS instance $($scaleSetInstance.Name)"
                DisplayException $_
                Write-Output "Continuing.."
            } else {
                throw [UnknownException]::new($VMssObject, "Failed to upgrade virtual machine scale set instance $($scaleSetInstance.Name)", $_.Exception)
            }
        }
    }
    ScriptLog -VMObject $VMssObject -Message "All virtual machine scale set instances upgraded"
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

    if (!($PSCmdlet.ShouldProcess("($($VMssObject.ResourceGroupName)) $($VMssObject.Name)", "Update virtual machine scale set"))) {
        return
    }

    ScriptLog -VMObject $VMObject -Message "Updating virtual machine scale set" -Verbose
    try {
        $VMssObject = Update-AzVmss -VMScaleSetName $vmssName `
                                    -ResourceGroupName $vmssResourceGroupName `
                                    -VirtualMachineScaleSet $VMssObject `
                                   
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractCloudExceptionMessage($_)
        if ($errorCode -eq "ParentResourceNotFound") {
            throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception)
        } 
        
        if($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMssObject, $_.Exception)       
        } 
            
        throw [UnknownException]::new($VMssObject, "Failed to update virtual machine scale set", $_.Exception)
        
    }
    
    if ($VMssObject.ProvisioningState -eq "Succeeded") {
        ScriptLog -VMObject $VMObject -Message "Successfully updated scale set with extension"
        return $VMssObject
    }

    throw [OperationFailed]::new($VMssObject, "Failed to update virtual machine scale set")
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
        ScriptLog -VMObject $VMssObject -Message "Already assigned with user managed identity $userAssignedManagedIdentityName" -Verbose
    } else {
        
        if (!($PSCmdlet.ShouldProcess("($vmssResourceGroup) $vmssName", "assign managed identity $userAssignedManagedIdentityName"))) {
            return $VMssObject
        }

        try {
            $VMssObject = Update-AzVmss -VMScaleSetName $vmssName `
                                    -ResourceGroupName $vmssResourceGroup `
                                    -VirtualMachineScaleSet $VMssObject `
                                    -IdentityType "UserAssigned" `
                                    -IdentityID $userAssignedManagedIdentityId `
                                   
        } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
            $errorCode = ExtractCloudExceptionMessage($_)
            if ($errorCode -eq "FailedIdentityOperation") {
                throw [UserAssignedManagedIdentityDoesNotExist]::new($UserAssignedManagedIdentityObject, $_.Exception)
            } elseif($errorCode -eq "ResourceGroupNotFound") {
                throw [ResourceGroupDoesNotExist]::new($VMssObject, $_)       
            } elseif ($errorCode -eq "InvalidParameter") {
                throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception) 
            } else {
                throw [UnknownException]::new($VMssObject, "Failed to user assign managed identity $userAssignedManagedIdentityName. ExceptionInfo = $exceptionInfo", $_.Exception)
            }
        }

        if ($VMssObject.ProvisioningState -ne "Succeeded") {
            throw [OperationFailed]::new($VMssObject, "Failed to assign user assigned managed identity $userAssignedManagedIdentityName")
        }
        
        ScriptLog -VMObject $VMssObject -Message "Successfully assigned user assign managed identity $userAssignedManagedIdentityName"
    }

    return $VMssObject
}

function AssignVmUserManagedIdentity {
     <#
	.SYNOPSIS
	Assign managed identity to VM
	#>
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
        ScriptLog -VMObject $VMObject -Message "Already assigned with managed identity $userAssignedManagedIdentityName"
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
        $errorCode = ExtractCloudExceptionMessage($_)
        if ($errorCode -eq "FailedIdentityOperation") {
            throw [UserAssignedManagedIdentityDoesNotExist]::new($userAssignedManagedIdentityName, $_.Exception)
        } elseif($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMObject, $_.Exception)       
        } elseif ($errorCode -eq "InvalidParameter") {
            throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
        } else {
            throw [UnknownException]::new($VMObject, "Failed to assign user managed identity $userAssignedManagedIdentityName. Exception Info = $exceptionInfo", $_.Exception)
        }
    }

    if (!($result.IsSuccessStatusCode)) {
        throw [OperationFailed]::new($VMObject, "Failed to assign user assigned managed identity $userAssignedManagedIdentityName. StatusCode : $($result.StatusCode). ReasonPhrase : $($result.ReasonPhrase)")
    }
    
    Write-Output "($vmResourceGroup) $vmName, $userAssignedManagedIdentityName : Successfully assigned managed identity"
}

function ExtractVmInformation {
    <#
	.SYNOPSIS
	Format VM/VMSS Information for messages
	#>
    param (
        [Parameter(Mandatory=$True)] [Object] $VMObject,
        [Parameter(Mandatory=$True)] [String] $Message
    )

    $resourceGroupName = $VMObject.ResourceGroupName
    $name = $VMObject.Name
    return "($resourceGroupName) $name : " + $Message
}

function ScriptLog {
    <#
	.SYNOPSIS
	Outputs Message to console.
	#>
    param (
        [Parameter(Mandatory=$True)] [Object] $VMObject,
        [Parameter(Mandatory=$false)] [Switch] $Verbose,
        [Parameter(Mandatory=$True)] [String] $Message
    )

    if ($Verbose) {
        Write-Verbose (ExtractVmInformation -VMObject $VMObject + $Message)    
    } else {
        Write-Output (ExtractVmInformation -VMObject $VMObject + $Message)
    }
}

function DisplayException {
    <#
    .SYNOPSIS
    Renders the given exception on the output.
    Does not throw any exceptions.
    #>
    
    param (
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    try {
        Write-Output "ExceptionMessage : $($ErrorRecord.Exception.Message)"
        Write-Verbose "ScriptStackTrace : "
        $ex = $ErrorRecord.Exception
        while ($ex) {
            Write-Verbose "$($ex.StackTrace)"
            $ex = $ex.InnerException
        }
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

    $userAssignedManagedIdentityName = $UserAssignedManagedIdentity.Name

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
                throw [UserAssignedManagedIdentityDoesNotExist]::new($UserAssignedManagedIdentity, $_.Exception) 
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
                    Write-Output "$userAssignedManagedIdentityName : User Assigned Managed Identity doesn't Exist or unaccessible."
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
    Set-Variable -Name sb_nop_block -Option Constant -Value { param($obj) $obj}

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
            Set-Variable -Name sb_vm -Option Constant -Value { param($vmObj) OnboardVmiWithLaVmWithReInstall -VMObject $vmObj}
        } else {
            Set-Variable -Name sb_vm -Option Constant -Value { param($vmObj); OnboardVmiWithLaVmWithoutReIntall -VMObject $vmObj}
        }
        
        Set-Variable -Name sb_vmss -Option Constant -Value { param($vmssObj); OnboardVmiWithLaVmss -VMssObject $vmssObj}
        Set-Variable -Name sb_da -Option Constant -Value { param($vmObj);  OnboardDaLaSettingsVm -VMObject $vmObj}
        Set-Variable -Name sb_da_vmss -Option Constant -Value { param($vmssObj); OnboardDaLaSettingsVmss -VMssObject $vmssObj}
        Set-Variable -Name sb_roles -Option Constant -Value $sb_nop_block_roles
    } else {
        #VMI supports Customers onboarding DCR from different subscription
        #Cannot validate DCRResourceId as parameter set ByResourceId will be deprecated for - Get-AzDataCollectionRule
        Set-Variable -Name amaPublicSettings -Option Constant -Value @{'authentication' = @{
                        'managedIdentity' = @{
                        'identifier-name' = 'mi_res_id'
                        'identifier-value' = $($userAssignedIdentityObject.Id) 
                        }
                    }
        }
        Set-Variable -Name sb_vm -Option Constant -Value { param($vmObj); OnboardVmiWithAmaVm -VMObject $vmObj}
        Set-Variable -Name sb_vmss -Option Constant -Value { param($vmssObj); OnboardVmiWithAmaVmss -VMssObject $vmssObj}
        
        if ($ProcessAndDependencies) {
            Set-Variable -Name sb_da -Option Constant -Value { param($vmObj); OnboardDaWithAmaSettingsVm -VMObject $vmObj}
            Set-Variable -Name sb_da_vmss -Option Constant -Value { param($vmssObj); OnboardDaWithAmaSettingsVmss -VMObject $vmObj}
        } else {
            Set-Variable -Name sb_da -Option Constant -Value $sb_nop_block
            Set-Variable -Name sb_da_vmss -Option Constant -Value $sb_nop_block
        }
    
        Set-Variable -Name sb_roles -Option Constant -Value { param($uamiObj, $rgName) SetManagedIdentityRolesAma -UserAssignedManagedIdentityObject $uamiObj -ResourceGroupName $rgName}
    }

    if ($TriggerVmssManualVMUpdate) {
        Set-Variable -Name sb_upgrade -Option Constant -Value { param($vmssObj);  UpgradeVmssExtensionManualUpdateEnabled -VMssObject $vmssObj}
    } else {
        Set-Variable -Name sb_upgrade -Option Constant -Value $sb_nop_block
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
            throw [PolicyAssignmentDoesNoExist]::new($PolicyAssignmentName ,$_)
        }

        foreach ($result in $complianceResults) {
            
            if ($result.SubscriptionId -ne $SubscriptionId) {
                Write-Output("VM is not in same subscription, this scenario is not currently supported. Skipping this VM.")
                continue
            }

            $vmResourceGroupName = $result.ResourceGroup
            $vmResourceId    = $result.ResourceId
            $searchParameters = @{}
            if ($ResourceGroup) {
                $searchParameters.add("ResourceGroupName", $ResourceGroup)
            }
            
            #Virtual Machines not running and those part of a virtual machine scale set will be skipped.
            $vm = Get-AzVM -Status @searchParameters 
                    | Where-Object {$_.PowerState -eq 'VM running' -and !($_.VirtualMachineScaleSet) -and $_.Name -like $Name -and $_.Id -eq $vmResourceId}
            
            if ($vm) {$OnboardingStatus.Total+=1} else {continue}
        
            if ($Rghashtable.ContainsKey($vmResourceGroupName)) {
                $Rghashtable[$vmResourceGroupName].VirtualMachineList.add($vm)
            } else {
                $rgTableElemObject = [ResourceGroupTableElement]::new()
                $rgTableElemObject.VirtualMachineList = New-Object -TypeName 'System.Collections.ArrayList' ($vm)
                $Rghashtable.add($vmResourceGroupName,$rgTableElemObject)
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
        $Vms = Get-AzVM -Status @searchParameters
                | Where-Object {$_.PowerState -eq 'VM running' -and !($_.VirtualMachineScaleSet) -and $_.Name -like $Name}
        $OnboardingStatus.Total += $Vms.Length
        
        $Vmss = Get-AzVmss @searchParameters | Where-Object {$_.Name -like $Name}
        $OnboardingStatus.Total += $Vmss.Length
        
        Write-Output "VMs and VMSS in a non-running state will be skipped."
        Write-Output "" "VM's matching selection criteria:" ""
        Foreach ($vm in $Vms) {
            $vmResourceGroupName = $vm.ResourceGroupName
            if ($Rghashtable.ContainsKey($vmResourceGroupName) `
                        -and $Rghashtable[$vmResourceGroupName].VirtualMachineList) {
                $Rghashtable[$vmResourceGroupName].VirtualMachineList.add($vm)
            } elseif ($Rghashtable.ContainsKey($vmResourceGroupName)) {
                $rgTableElemObject = $Rghashtable[$vmResourceGroupName]
                $rgTableElemObject.VirtualMachineList = New-Object -TypeName 'System.Collections.ArrayList' ($vm)
            } else {
                $rgTableElemObject = [ResourceGroupTableElement]::new()
                $rgTableElemObject.VirtualMachineList = New-Object -TypeName 'System.Collections.ArrayList' ($vm)
                $Rghashtable.add($vmResourceGroupName,$rgTableElemObject)
            }

            Write-Output "$vmResourceGroupName $($vm.Name) : $($vm.PowerState)"
        }
        
        Write-Output "" "VM ScaleSets matching selection criteria:" ""
        Foreach ($vmss in $Vmss) {
            $vmssResourceGroupName = $vmss.ResourceGroupName
            if ($Rghashtable.ContainsKey($vmssResourceGroupName) `
                        -and $Rghashtable[$vmssResourceGroupName].VirtualMachineScaleList) {
                $Rghashtable[$vmssResourceGroupName].VirtualMachineScaleList.add($vmss)
            } elseif ($Rghashtable.ContainsKey($vmssResourceGroupName)) {
                $rgTableElemObject = $Rghashtable[$vmssResourceGroupName]
                $rgTableElemObject.VirtualMachineScaleSetList = New-Object -TypeName 'System.Collections.ArrayList' ($vmss)
            } else {
                $rgTableElemObject = [ResourceGroupTableElement]::new()
                $rgTableElemObject.VirtualMachineScaleSetList = New-Object -TypeName 'System.Collections.ArrayList' ($vmss)
            }
            Write-Output "$vmssResourceGroupName $($vmss.Name) : $($vmss.PowerState)"
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
                    $vm = &$sb_vm -vmObj $vm
                    $vm = &$sb_da -vmObj $vm
                    ScriptLog -VMObject $vm -Message "Successfully onboarded VMInsights"
                    $OnboardingStatus.Succeeded +=1
                } catch [VirtualMachineDoesNotExist] {
                    DisplayException -ErrorRecord $_
                    Write-Output "Continuing to the next Virtual Machine..."
                } catch [OperationFailed] {
                    DisplayException -ErrorRecord $_
                    Write-Output "Continuing to the next Virtual Machine..."
                } catch [UnknownException] {
                    Write-Output "UnknownException :"
                    DisplayException -ErrorRecord $_
                    Write-Output "Continuing to the next Virtual Machine..."
                }
            }

            Foreach ($vmss in $Vmss) {
                try {
                    $osType = $vmss.storageprofile.osdisk.ostype
                    $vmss = &$sb_vmss -vmssObj $vmss
                    $vmss = &$sb_da_vmss -vmssObj $vmss
                    &$sb_upgrade -vmssObj $vmss
                    ScriptLog -VMObject $vmss -Message "Successfully onboarded VMInsights"
                    $OnboardingStatus.Succeeded +=1
                }  catch [VirtualMachineScaleSetDoesNotExist] {
                    DisplayException -ErrorRecord $_
                    Write-Output "Continuing to the next Virtual Machine Scale Set..."
                } catch [OperationFailed] {
                    DisplayException -ErrorRecord $_
                    Write-Output "Continuing to the next Virtual Machine Scale Set..."
                } catch [UnknownException] {
                    Write-Output "UnknownException :"
                    DisplayException -ErrorRecord $_
                    Write-Output "Continuing to the next Virtual Machine Scale Set..."
                }
            }
        } catch [ResourceGroupDoesNotExist] {
            DisplayException -ErrorRecord $_
            Write-Output "Continuing to the next Resource-Group..."
        }
    }
}
catch [FatalException] {
    Write-Output "FatalException :"
    DisplayException -ErrorRecord $_
    Write-Output "Exiting the script..."
    exit 1
}
catch {
    DisplayException -ErrorRecord $_
    Write-Output "Exiting the script..."
    exit 1
}
finally {
    PrintSummaryMessage $OnboardingStatus
}
