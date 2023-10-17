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

#Assumption - The script assumes the entity running the script has access to all VMs/VMSS in the script.
[CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
param(
    [Parameter(mandatory = $True)][String]$SubscriptionId,
    [Parameter(mandatory = $False)][Switch]$TriggerVmssManualVMUpdate,
    [Parameter(mandatory = $False)][Switch]$Approve,
    [Parameter(mandatory = $False)][String]$ResourceGroup,
    [Parameter(mandatory = $False)][String]$Name = "*",
    [Parameter(mandatory = $False)][String]$PolicyAssignmentName,
    
    [Parameter(mandatory = $False, ParameterSetName = 'AzureMonitoringAgent')][Switch]$ProcessAndDependencies,
    [Parameter(mandatory = $True, ParameterSetName = 'AzureMonitoringAgent')][String]$DcrResourceId,
    [Parameter(mandatory = $True, ParameterSetName = 'AzureMonitoringAgent')][String]$UserAssignedManagedIdentityResourceGroup,
    [Parameter(mandatory = $True, ParameterSetName = 'AzureMonitoringAgent')][String]$UserAssignedManagedIdentityName,

    [Parameter(mandatory = $True,  ParameterSetName = 'LogAnalyticsAgent')][String]$WorkspaceId,
    [Parameter(mandatory = $True,  ParameterSetName = 'LogAnalyticsAgent')][String]$WorkspaceKey,
    [Parameter(mandatory = $False, ParameterSetName = 'LogAnalyticsAgent')][Switch]$ReInstall
)

class FatalException : System.Exception {
    FatalException($errorMessage, $innerException) : base($errorMessage, $innerException) {}
}

class VirtualMachineException : System.Exception {
    VirtualMachineException($vmObject, $errorMessage, $innerException)  : base("$(FormatVmIdentifier -VMObject $vmObject) : $errorMessage", $innerException) {}
}

class VirtualMachineScaleSetException : System.Exception {
    VirtualMachineScaleSetException($vmssObject, $errorMessage, $innerException)  : base("$(FormatVmssIdentifier -VMssObject $vmssObject) : $errorMessage", $innerException) {}
}

class ResourceGroupDoesNotExist : System.Exception {
    ResourceGroupDoesNotExist ($rgName, $innerException) : base("$rgName : Resource-Group does not exist", $innerException) {}
}

class VirtualMachineUnknownException : VirtualMachineException {
    VirtualMachineUnknownException($vmObject, $errorMessage, $innerException) : base($vmObject, $errorMessage, $innerException) {}
}

class VirtualMachineDoesNotExist : VirtualMachineException {
    VirtualMachineDoesNotExist ($vmObject, $innerException) : base($vmObject, "Virtual Machine does not exist", $innerException) {}
}

class VirtualMachineOperationFailed : VirtualMachineException {
    VirtualMachineOperationFailed($vmObject, $errorMessage) : base($vmObject, $errorMessage, $null) {}
}

class VirtualMachinePoweredDown : VirtualMachineException {
    VirtualMachinePoweredDown($vmObject, $errorMessage) : base($vmObject, "Virtual Machine is powered down", $null) {}
}

class VirtualMachineScaleSetUnknownException : VirtualMachineScaleSetException {
    VirtualMachineScaleSetUnknownException($vmssObject, $errorMessage, $innerException) : base($vmssObject, $errorMessage, $innerException) {}
}

class VirtualMachineScaleSetDoesNotExist : VirtualMachineScaleSetException {
    VirtualMachineScaleSetDoesNotExist ($vmssObject, $innerException) : base($vmssObject, "VMSS does not exist", $innerException) {}
}

class VirtualMachineScaleSetOperationFailed : VirtualMachineScaleSetException {
    VirtualMachineScaleSetOperationFailed($vmssObject, $errorMessage) : base($vmssObject, $errorMessage, $null) {}
}

class DataCollectionRuleForbidden : FatalException {
    DataCollectionRuleForbidden($dcrResourceId, $innerException) : base("$dcrResourceId : Access to data collection rule is forbidden", $innerException) {}
}

class DataCollectionRuleDoesNotExist : FatalException {
    DataCollectionRuleDoesNotExist($dcrResourceId, $innerException) : base("$dcrResourceId : Data Collection Rule does not exist.", $innerException) {}
}

class DataCollectionRuleIncorrect : FatalException {
    DataCollectionRuleIncorrect($dcrResourceId, $innerException) : base("$dcrResourceId : Data Collection Rule incorrect format.", $innerException) {}
}

class UserAssignedManagedIdentityDoesNotExist : FatalException {
    UserAssignedManagedIdentityDoesNotExist($uamiobj, $innerException) : base("$($uamiobj.Name) : User Assigned Managed Identity does not exist.", $innerException) {}
}

class ResourceGroupTableElement {
    [System.Collections.ArrayList] $VirtualMachineList = [System.Collections.ArrayList]::new()
    [System.Collections.ArrayList] $VirtualMachineScaleSetList = [System.Collections.ArrayList]::new()
}
class OnboardingCounters {
    [Decimal]$Succeeded = 0
    [Decimal]$Total = 0
}

# Log Analytics Extension constants
Set-Variable -Name laExtensionMap -Option Constant -Value @{ 
    "Windows" = @{ ExtensionType = "MicrosoftMonitoringAgent"
                  TypeHandlerVersion = "1.0"
                  Publisher = "Microsoft.EnterpriseCloud.Monitoring"
                }
    "Linux" = @{  ExtensionType = "OmsAgentForLinux"
                  TypeHandlerVersion = "1.6"
                  Publisher = "Microsoft.EnterpriseCloud.Monitoring"
                }
}
Set-Variable -Name laExtensionName -Option Constant -Value "MMAExtension"

# Azure Monitoring Agent Extension constants
Set-Variable -Name amaExtensionMap -Option Constant -Value @{ 
       "Windows" = @{ExtensionType = "AzureMonitorWindowsAgent"
                    TypeHandlerVersion = "1.16"
                    Publisher = "Microsoft.Azure.Monitor" 
                }
       "Linux" = @{ExtensionType = "AzureMonitorLinuxAgent" 
                   TypeHandlerVersion = "1.16"
                   Publisher = "Microsoft.Azure.Monitor"
                }
}

Set-Variable -Name amaExtensionName -Option Constant -Value "AzureMonitoringAgent"

# Dependency Agent Extension constants
Set-Variable -Name daExtensionMap -Option Constant -Value @{
    "Windows" = @{ExtensionType = "DependencyAgentWindows"
                  TypeHandlerVersion = "9.10"
                  Publisher = "Microsoft.Azure.Monitoring.DependencyAgent"
                }
    "Linux" = @{ExtensionType = "DependencyAgentLinux"
                TypeHandlerVersion = "9.10"
                Publisher = "Microsoft.Azure.Monitoring.DependencyAgent"
            }
}
Set-Variable -Name daExtensionName -Option Constant -Value "DA-Extension"
Set-Variable -Name processAndDependenciesPublicSettings -Option Constant -Value @{"enableAMA" = "true"}

Set-Variable -Name unknownExceptionVirtualMachineConsequentCounterLimit -Option Constant -Value 3
Set-Variable -Name unknownExceptionVirtualMachineScaleSetConsequentCounterLimit -Option Constant -Value 3
Set-Variable -Name unknownExceptionTotalCounterLimit -Option Constant -Value 6

$ErrorActionPreference = "Stop"
#Presence of DCR Resource Id indicates AMA onboarding.
$isAma = "" -ne $DcrResourceId

#
# FUNCTIONS
#
function PrintSummaryMessage {
    <#
	.SYNOPSIS
	Print the Total of eligible VM/VMSS, number of succeeded and failed.
	#>
    param (
        [Parameter(mandatory = $True)][OnboardingCounters] $onboardingCounters
    )
    Write-Host "" "Summary:"
    Write-Host "Total VM/VMSS processed: $($onboardingCounters.Total)"
    Write-Host "Succeeded : $($onboardingCounters.Succeeded)"
    Write-Host "Failed : $($onboardingCounters.Total -  $onboardingCounters.Succeeded)"
}

function ExtractCloudExceptionErrorMessage {
    <#
	.SYNOPSIS
	Extract error codes from the Cloud Exception. 
	#>
    param
    (
        [Parameter(Mandatory=$True,Position=0)]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    if ($ErrorRecord.Exception.Message -match 'ErrorMessage: ([a-zA-Z\s]+)') {
        return $matches[1]
    }

    return $null
}

function ExtractCloudExceptionErrorCode {
    <#
	.SYNOPSIS
	Extract error codes from the Cloud Exception. 
	#>
    param
    (
        [Parameter(Mandatory=$True,Position=0)]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    if ($ErrorRecord.Exception.Message -match 'ErrorCode: ([a-zA-Z]+)') {
        return $matches[1]
    }

    return $null
}

function FormatVmIdentifier {
    <#
    .SYNOPSIS
    Format VM Information for messages
    #>
    param (
        [Parameter(Mandatory=$True)] 
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine] $VMObject
    )
    return "($($VMObject.ResourceGroupName)) $($VMObject.Name)"
}
function FormatVmssIdentifier {
    <#
    .SYNOPSIS
    Format VMSS Information for messages
    #>
    param (
        [Parameter(Mandatory=$True)] 
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet] $VMssObject
    )
    
    return "($($VMssObject.ResourceGroupName)) $($VMssObject.Name)"
}
function DisplayException {
    <#
    .SYNOPSIS
    Renders the given exception on the output.
    Does not throw any exceptions.
    #>
    
    param (
        [Parameter(Mandatory=$True,Position=0)]
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )
    try {
        $ex = $ErrorRecord.Exception
        while ($ex) {
            Write-Host "ExceptionMessage : $($ex.Message)"
            Write-Verbose "StackTrace : "
            Write-Verbose "$($ex.StackTrace)"
            $ex = $ex.InnerException
        }
        Write-Host ""
        try { "ScriptStackTrace:`r`n$($ErrorRecord.ScriptStackTrace)`r`n" | Write-Host } catch { }
    }
    catch {
        # silently ignore
    }
}

function GetVMExtension {
    <#
	.SYNOPSIS
	Return the VM extension of specified Type and Publisher
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$VMObject,
        [Parameter(mandatory = $True)][Hashtable]$ExtensionProperties
    )

    $extensionPublisher = $ExtensionProperties.Publisher
    $extensionType = $ExtensionProperties.ExtensionType

    try {
        $extensions = Get-AzVMExtension -ResourceGroupName $VMObject.ResourceGroupName -VMName $VMObject.Name
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractCloudExceptionErrorCode $_
        if ($errorCode -eq "ParentResourceNotFound") {
            throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
        }
        if ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($($VMObject.ResourceGroupName),$_.Exception)   
        }    
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to lookup extension with type = $extensionType, publisher = $extensionPublisher", $_.Exception)
    }
    
    foreach ($extension in $extensions) {
        if ($extensionType -eq $extension.ExtensionType -and $extensionPublisher -eq $extension.Publisher) {
            Write-Verbose "$(FormatVmIdentifier -VMObject $VMObject) : Extension with type = $extensionType, publisher = $extensionPublisher found."
            return $extension
        }
    }

    return $null
}

function GetVMssExtension {
    <#
	.SYNOPSIS
	Return the VMss extension of specified ExtensionType and ExtensionPublisher
	#>
    param
    (
        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$VMssObject,
        [Parameter(mandatory = $True)][Hashtable]$ExtensionProperties
    )

    $extensionPublisher = $ExtensionProperties.Publisher
    $extensionType = $ExtensionProperties.ExtensionType

    foreach ($extension in $VMssObject.VirtualMachineProfile.ExtensionProfile.Extensions) {
        if ($ExtensionType -eq $extensionType -and $extensionPublisher -eq $extension.Publisher) {
            Write-Verbose "$(FormatVmssIdentifier -VMssObject $VmssObject) : Extension with type = $extensionType , publisher = $extensionPublisher found"
            return $extension
        }
    }

    return $null
}

function RemoveVMExtension {
    <#
	.SYNOPSIS
	Remove a VM Extension, used for OMSAgent to switch workspace.
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$VMObject,
        [Parameter(mandatory = $True)][String]$ExtensionName
    )

    $vmlogheader = FormatVmIdentifier -VMObject $VMObject
    if (!$PSCmdlet.ShouldProcess($vmlogheader, "Remove $ExtensionName")) {
        return $False
    }

    try {
        #Remove operation on non existent VM, extension still return a success
        $removeResult = Remove-AzVMExtension -ResourceGroupName $VMObject.ResourceGroupName -VMName $VMObject.Name -Name $ExtensionName -Force
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractCloudExceptionErrorCode $_
        if($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMObject.ResourceGroupName,$_.Exception)       
        } 
        
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to remove extension $ExtensionName", $_.Exception)
    }
    
    if ($removeResult.IsSuccessStatusCode) {
         Write-Host "$vmlogheader : Successfully removed extension $ExtensionName"
        return $True
    }

    throw [VirtualMachineOperationFailed]::new($VMObject, "Failed to remove extension $ExtensionName. StatusCode = $($removeResult.StatusCode). ReasonPhrase = $($removeResult.ReasonPhrase)")
}

function NewDCRAssociationVm {
    <#
	.SYNOPSIS
	Create a new DCRAssociation.
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$VMObject
    )

    $vmId = $VMObject.Id
    $invalidOperationParserPattern = "status code '([a-zA-Z]+)'"
    $vmlogheader = FormatVmIdentifier -VMObject $VMObject
    try {
        # A VM may have zero or more Data Collection Rule Associations
        $dcrAssociationList = Get-AzDataCollectionRuleAssociation -TargetResourceId $vmId
    } catch [System.Management.Automation.ParameterBindingException] {
        throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
    }

    # A VM may have zero or more Data Collection Rule Associations
    foreach ($dcrAssociation in $dcrAssociationList) {
        if ($dcrAssociation.DataCollectionRuleId -eq $DcrResourceId) {
            Write-Host "$vmlogheader : Data Collection Rule $($dcrAssociation.Name) already associated to the VM"
            return
        }
    }

    #The Customer is responsible to uninstall the DCR Association themselves
    if (!($PSCmdlet.ShouldProcess($vmlogheader, "Install Data Collection Rule Association"))) {
        return
    }

    $dcrassociationName = "VM-Insights-DCR-Association"
    Write-Host "$vmlogheader : Deploying Data Collection Rule Association $dcrassociationName"
    try {
        $dcrassociation = New-AzDataCollectionRuleAssociation -TargetResourceId $vmId -AssociationName $dcrassociationName -RuleId $DcrResourceId
    } catch [System.Management.Automation.PSInvalidOperationException] {
        $exceptionMessage = $_.Exception.Message
        
        if ($exceptionMessage.Contains('Invalid format of the resource identifier')) {
            throw [DataCollectionRuleIncorrect]::new($DcrResourceId)
        } 

        if (!($exceptionMessage -match $invalidOperationParserPattern)){
            throw [VirtualMachineUnknownException]::new($VMObject, "Failed to create data collection rule association with $DcrResourceId", $_.Exception)
        }

        $statusCode = $matches[1]
        if ($statusCode -eq 'BadRequest') {
            throw [DataCollectionRuleDoesNotExist]::new($DcrResourceId, $_.Exception)
        }
        if ($statusCode -eq 'NotFound') {
            throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
        }
        if ($statusCode -eq 'Forbidden') {
            throw [DataCollectionRuleForbidden]::new($DcrResourceId, $_.Exception)     
        } 
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to create data collection rule association with with $DcrResourceId. StatusCode = $statusCode", $_.Exception)
    }

    #Tmp fix task:- 21191002
    if (($null -eq $dcrassociation) -or ($dcrassociation -is [Microsoft.Azure.Management.Monitor.Models.ErrorResponseCommonV2Exception])) {
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to create data collection rule association with $DcrResourceId", $dcrassociation)
    }

    Write-Host "$vmlogheader : Successfully created data collection rule association $dcrassociationName"
}

function NewDCRAssociationVmss {
    <#
	.SYNOPSIS
	Create a new DCRAssociation.
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$VMssObject
    )

    $invalidOperationParserPattern = "status code ([a-zA-Z]+)"
    $vmsslogheader = FormatVmssIdentifier -VMssObject $VMssObject
    $vmssId = $VMssObject.Id

    try {
        # A VMSS may have zero or more Data Collection Rule Associations
        $dcrAssociationList = Get-AzDataCollectionRuleAssociation -TargetResourceId $vmssId
    } catch [System.Management.Automation.ParameterBindingException] {
        throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception)
    }

    foreach ($dcrAssociation in $dcrAssociationList) {
        if ($dcrAssociation.DataCollectionRuleId -eq $DcrResourceId) {
            Write-Host "$vmsslogheader : Data Collection Rule $($dcrAssociation.Name) already associated to the VMSS"
            return
        }
    }

    #The Customer is responsible to uninstall the DCR Association themselves
    if (!($PSCmdlet.ShouldProcess($vmsslogheader, "Install Data Collection Rule Association"))) {
        return
    }

    $dcrassociationName = "VM-Insights-DCR-Association"
    Write-Verbose "$vmsslogheader : Deploying Data Collection Rule Association $dcrassociationName"
    try {
        $dcrassociation = New-AzDataCollectionRuleAssociation -TargetResourceId $vmssId -AssociationName $dcrassociationName -RuleId $DcrResourceId
    } catch [System.Management.Automation.PSInvalidOperationException] {
        $exceptionMessage = $_.Exception.Message
        
        if ($exceptionMessage.Contains('Invalid format of the resource identifier')) {
            throw [DataCollectionRuleIncorrect]::new($DcrResourceId)
        } 
        if (!($exceptionMessage -match $invalidOperationParserPattern)) {
            throw [VirtualMachineScaleSetUnknownException]::new($VMssObject, "Failed to create data collection rule association with with $DcrResourceId. StatusCode = $statusCode", $_.Exception)
        }
        
        $statusCode = $matches[1]
        if ($statusCode -eq 'BadRequest') {
            throw [DataCollectionRuleDoesNotExist]::new($DcrResourceId, $_.Exception)
        }
        if ($statusCode -eq 'NotFound') {
            throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception)
        }
        if ($statusCode -eq 'Forbidden') {
            throw [DataCollectionRuleForbidden]::new($DcrResourceId, $_.Exception)     
        }

        if (!($exceptionMessage -match $invalidOperationParserPattern)){
            throw [VirtualMachineScaleSetUnknownException]::new($VMObject, "Failed to create data collection rule association with $DcrResourceId", $_.Exception)
        }
    }
    #Tmp fix task:- 21191002
    if (($null -eq $dcrassociation) -or ($dcrassociation -is [Microsoft.Azure.Management.Monitor.Models.ErrorResponseCommonV2Exception])) {
        throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, "Failed to create data collection rule association with $DcrResourceId", $dcrassociation)
    }
}

function OnboardDaVm {
    <#
	.SYNOPSIS
	Install DA (VM), handling if already installed
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$VMObject,
        [Parameter(mandatory = $False)][hashtable]$Settings
    )

    $extensionName = $daExtensionName
    $daExtensionConstantProperties = $daExtensionMap[$VMObject.StorageProfile.OsDisk.OsType.ToString()]
    $extension = GetVMExtension -VMObject $VMObject -ExtensionProperties $daExtensionConstantProperties
    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "$(FormatVmIdentifier -VMObject $VMObject) : Extension $extensionName already installed."
    }
    
    $parameters = @{
        Name = $extensionName
    }

    if ($Settings) {
        $parameters.add("Settings", $Settings)
    }

    return InstallVMExtension -VMObject $VMObject -ExtensionConstantProperties $daExtensionConstantProperties -InstallParameters $parameters
}

function InstallVMssExtension {
    <#
	.SYNOPSIS
	Install Extension (VMSS), handling if already installed
	#>
    #check if this supposed to be all the stack. that is functioing call it as well.
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$VMssObject,
        [Parameter(mandatory = $True)][String]$ExtensionName,
        [Parameter(mandatory = $True)][Hashtable]$ExtensionConstantProperties,
        [Parameter(mandatory = $False)][Hashtable]$Settings,
        [Parameter(mandatory = $False)][Hashtable]$ProtectedSettings
    )

    $extension = GetVMssExtension -VMssObject $VMssObject -ExtensionProperties $ExtensionConstantProperties
    $vmsslogheader = FormatVmssIdentifier -VMssObject $VMssObject

    if ($extension) {
        #$extension here is a references of extension property. $VMssObject. (Not a copy)
        Write-Host "$vmsslogheader : Extension $($extension.Name) already installed."
        
        if ($Settings) {
            $extension.Settings = $Settings
        }
        
        if ($ProtectedSettings) {
            $extension.ProtectedSettingS = $ProtectedSettings
        }

        $extension.TypeHandlerVersion = $ExtensionConstantProperties.TypeHandlerVersion
        return $VMssObject
    } 

    if (!($PSCmdlet.ShouldProcess($vmsslogheader, "install extension $ExtensionName"))) {
        return $VMssObject
    }
    
    $parameters = @{}
    
    if ($Settings) {
        $parameters.add("Setting", $Settings)
    }
    
    if ($ProtectedSettings) {
        $parameters.add("ProtectedSetting", $ProtectedSettings)
    }

    $VMssObject = Add-AzVmssExtension -VirtualMachineScaleSet $VMssObject `
                                      -Name $ExtensionName `
                                      -Type $ExtensionConstantProperties.ExtensionType `
                                      -Publisher $ExtensionConstantProperties.Publisher `
                                      -TypeHandlerVersion $ExtensionConstantProperties.TypeHandlerVersion `
                                      -AutoUpgradeMinorVersion $True

    Write-Host "$vmsslogheader : $ExtensionName added"
    return $VMssObject
}

function InstallAmaVm {
    <#
	.SYNOPSIS
	Install AMA (VM), handling if already installed
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$VMObject
    )
   
    # Use supplied name unless already deployed, use same name
    $amaExtensionConstantProperties = $amaExtensionMap[$VMObject.StorageProfile.OsDisk.OsType.ToString()]
    $extensionName = $amaExtensionName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionProperties $amaExtensionConstantProperties

    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "$(FormatVmIdentifier -VMObject $VMObject) : Extension $extensionName already installed. Provisioning State: $($extension.ProvisioningState)"
    }

    $parameters = @{
        Name               = $extensionName
        Settings           = $amaPublicSettings
    }

    return InstallVMExtension -VMObject $VMObject -ExtensionConstantProperties $amaExtensionConstantProperties -InstallParameters $parameters 
}

function OnboardVmiWithLaVmWithReInstall {
    <#
	.SYNOPSIS
	Install LA Extension on Virtual Machines, ReInstall flag provided.
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$VMObject
    )

    $osType = $VMObject.StorageProfile.OsDisk.OsType.ToString()
    $laExtensionConstantProperties = $laExtensionMap[$osType]
    # Use supplied name unless already deployed, use same name
    $extensionName = $laExtensionName
    $vmlogheader = FormatVmIdentifier -VMObject $VMObject
    
    $extension = GetVMExtension -VMObject $VMObject -ExtensionProperties $laExtensionConstantProperties

    if ($extension) {
        $extensionName = $extension.Name
        
        if ($osType -eq "Linux" -and $extension.PublicSettings) {
            $extensionPublicSettingsJson = $extension.PublicSettings | ConvertFrom-Json
            if ($extensionPublicSettingsJson.workspaceId -ne $laPublicSettings.workspaceId) {
                Write-Host "$vmlogheader : Extension $extensionName does not support updating workspace. An uninstall followed by re-install is required"
                if (!(RemoveVMExtension -VMObject $VMObject `
                                    -ExtensionName $extensionName)) {
                    Write-Host "$vmlogheader : Extension $extensionName was not chosen to be removed. Skipping Re-install"
                    return $False
                }
            }
        }
    }
    
    #constants and parameters provided separately. having name as a discreate parameter is a good idea.
    $parameters = @{
        Name               = $extensionName
        Settings           = $laPublicSettings
        ProtectedSettings  = $laProtectedSettings
    }

    return InstallVMExtension -VMObject $VMObject -InstallParameters $parameters -ExtensionConstantProperties $laExtensionConstantProperties
}

function OnboardVmiWithLaVmWithoutReInstall {
    <#
	.SYNOPSIS
	Install LA Extension on Virtual Machines, ReInstall flag not provided.
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$VMObject
    )

    $laExtensionConstantProperties = $laExtensionMap[$VMObject.StorageProfile.OsDisk.OsType.ToString()]
    # Use supplied name unless already deployed, use same name
    $extensionName = $laExtensionName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionProperties $laExtensionConstantProperties

    if ($extension) {
        $extensionName = $extension.Name
        if ($osType -eq "Linux" -and $extension.PublicSettings) {
            $ext = $extension.PublicSettings | ConvertFrom-Json 
            if ($ext.workspaceId -ne $laPublicSettings.workspaceId) {
                Write-Host "$(FormatVmIdentifier -VMObject $VMObject) : OmsAgentForLinux does not support updating workspace. Please try again with Re-Install Flag"
                return $VMObject
            }
        }
    }

    $parameters = @{
        Name               = $extensionName
        Settings           = $laPublicSettings
        ProtectedSettings  = $laProtectedSettings
    }

    return InstallVMExtension -VMObject $VMObject -ExtensionConstantProperties $laExtensionConstantProperties -InstallParameters $parameters
}

function OnboardVmiWithAmaVm {
    <#
	.SYNOPSIS
	Onboard VMI with AMA on Vms
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$VMObject
    )

    $VMObject = AssignVmUserManagedIdentity -VMObject $VMObject
    NewDCRAssociationVm -VMObject $VMObject
    return InstallAmaVm -VMObject $VMObject
}

function OnboardVmiWithAmaVmss {
    <#
	.SYNOPSIS
	Onboard VMI with AMA on VMSIns
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$VMssObject
    )
            
    $VMssObject = AssignVmssUserManagedIdentity -VMssObject $VMssObject
    NewDCRAssociationVmss -VMssObject $VMssObject
    return InstallVMssExtension -VMssObject $VMssObject `
                                -ExtensionName $amaExtensionName `
                                -Settings $amaPublicSettings `
                                -ExtensionConstantProperties $amaExtensionMap[$VMssObject.VirtualMachineProfile.StorageProfile.OsDisk.OsType.ToString()]
}

function SetManagedIdentityRoles {
    <#
	.SYNOPSIS
	Set roles to managed identity.
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)][String]$ResourceGroupId
    )

    $userAssignedManagedIdentityName = $UserAssignedManagedIdentityObject.Name
    $userAssignedManagedIdentityId = $UserAssignedManagedIdentityObject.principalId
    $roleDefinitionList = @("Virtual Machine Contributor", "Azure Connected Machine Resource Administrator", "Log Analytics Contributor") 
    
    if (!($PSCmdlet.ShouldProcess($ResourceGroupId, "Assign roles $roleDefinitionList to user assigned managed identity : $userAssignedManagedIdentityName"))) {
        return
    }

    foreach ($role in $roleDefinitionList) {
        if ($null -ne (Get-AzRoleAssignment -ObjectId $userAssignedManagedIdentityId -RoleDefinitionName $role -Scope $ResourceGroupId)) {
            Write-Verbose "Scope $ResourceGroupId, $role : role already set"
        } else {
            Write-Verbose "Scope $ResourceGroupId, $role : assigning role"
            New-AzRoleAssignment  -ObjectId $userAssignedManagedIdentityId -RoleDefinitionName $role -Scope $ResourceGroupId
            Write-Host "Scope $ResourceGroupId : role assignment for $userAssignedManagedIdentityName with $role succeeded"
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
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine] $VMObject,
        [Parameter(mandatory = $True)][Hashtable] $ExtensionConstantProperties,
        [Parameter(mandatory = $True)][Hashtable] $InstallParameters
    )
    #ExtensionName -> keep as separate parameter, InstlalParameter that is variable.
    $extensionName = $InstallParameters.Name
    $vmlogheader = $(FormatVmIdentifier -VMObject $VMObject)

    if (!($PSCmdlet.ShouldProcess($vmlogheader, "install extension $extensionName"))) {
        return $VMObject
    }

    Write-Host "$vmlogheader : Deploying/Updating extension $extensionName"
    
    try {
        $result = Set-AzVMExtension -ResourceGroupName $($VMObject.ResourceGroupName) `
                                    -VMName $($VMObject.Name) `
                                    @InstallParameters @ExtensionConstantProperties -ForceRerun $True

        if (!$result.IsSuccessStatusCode) {
            throw [VirtualMachineOperationFailed]::new($VMObject, "Failed to update extension. StatusCode = $($removeResult.StatusCode). ReasonPhrase = $($removeResult.ReasonPhrase)")
        }
    
        Write-Host "$vmlogheader : Successfully deployed/updated extension $extensionName"
        return $VMObject
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorMessage = ExtractCloudExceptionErrorMessage $_
        $errorCode = ExtractCloudExceptionErrorCode $_
        if ($errorMessage -eq "Cannot modify extensions in the VM when the VM is not running") {
            throw [VirtualMachinePoweredDown]::new($VMObject, $_.Exception)
        }
        
        if ($errorCode -eq "ParentResourceNotFound") {
            throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
        } 
        
        if($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMObject.ResourceGroupName, $_.Exception)       
        } 
        
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to update/install extension $extensionName", $_.Exception)
    }
}

function UpgradeVmssExtensionManualUpdateDisabled {
    <#
	.SYNOPSIS
	Upgrade VMss Extension without manual update.
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$VMssObject
    )

    $vmsslogheader = FormatVmssIdentifier -VMssObject $VMssObject
    Write-Host "$vmsslogheader : UpgradePolicy is Manual. Please trigger upgrade of VM Scale Set or call with -TriggerVmssManualVMUpdate"
}

function UpgradeVmssExtensionManualUpdateEnabled {
    <#
	.SYNOPSIS
	Upgrade VMss Extension with manual update.
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$VMssObject
    )
    
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    $vmssName = $VMssObject.Name
    $vmsslogheader =  FormatVmssIdentifier -VMssObject $VMssObject
    
    $scaleSetInstances = @()
    try {
        $scaleSetInstances = Get-AzVmssVm -ResourceGroupName $vmssResourceGroupName -VMScaleSetName $vmssName
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractCloudExceptionErrorCode($_)
        if ($errorCode -eq "ParentResourceNotFound") {
            throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception)
        }
        if ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMssObject.ResourceGroupName, $_.Exception)       
        } 
        
        throw [VirtualMachineScaleSetUnknownException]::new($VMssObject, "Failed to upgrade VMSS", $_.Exception)
    }

    #sort scaleSetInstances by name because we do not know if scaleSetInstances are sorted.

    $i = 0
    $instanceCount = $scaleSetInstances.Length
    Foreach ($scaleSetInstance in $scaleSetInstances) {
        $i++
        Write-Host "Upgrading $i of $instanceCount"
        $scaleSetInstanceName = $($scaleSetInstance.Name)
        if ($scaleSetInstance.LatestModelApplied) {
            Write-Verbose "$vmsslogheader : Latest model already applied for $scaleSetInstanceName, $i of $instanceCount"
            continue
        }
        if (!($PSCmdlet.ShouldProcess($vmsslogheader, "Upgrading VMSS instance name $scaleSetInstanceName"))) {
            continue
        }
        Write-Verbose "$vmsslogheader : Upgrading VMSS instance name $scaleSetInstanceName, $i of $instanceCount"
        try {
            $result = Update-AzVmssInstance -ResourceGroupName $vmssResourceGroupName -VMScaleSetName $vmssName -InstanceId $scaleSetInstance.InstanceId
            if ($result.Status -ne "Succeeded") {
                Write-Host "$vmsslogheader : Failed to upgrade VMSS instance name $scaleSetInstanceName. $($result.Status)"
            } else {
                Write-Verbose "$vmsslogheader : Upgrade VMSS instance name $scaleSetInstanceName, $i of $instanceCount"
            }
        } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
            $errorCode = ExtractCloudExceptionErrorCode($_)
            if ($errorCode -eq "ResourceNotFound") {
                throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception)
            }
            if($errorCode -eq "ResourceGroupNotFound") {
                throw [ResourceGroupDoesNotExist]::new($VMssObject.ResourceGroupName ,$_.Exception)  
            }
            if($errorCode -eq "OperationNotAllowed") {
                Write-Host "$vmsslogheader : Unable to lookup VMSS instance name $scaleSetInstanceName. Continuing..."
                DisplayException $_
            } 
            #Counter -> consdider throwing exception is hard.
            throw [VirtualMachineScaleSetUnknownException]::new($VMssObject, "Failed to upgrade VMSS instance name $scaleSetInstanceName", $_.Exception)
        }
    }
    
}

function UpdateVMssExtension {
    <#
	.SYNOPSIS
	Update VMss Extension
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$VMssObject
    )

    $vmsslogheader = FormatVMssIdentifier -VMssObject $VMssObject

    if (!($PSCmdlet.ShouldProcess($vmsslogheader, "Update VMSS"))) {
        return $VMssObject
    }

    Write-Host "$vmsslogheader : Updating VMSS"
    try {
        $VMssObject = Update-AzVmss -VMScaleSetName $VMssObject.Name `
                                    -ResourceGroupName $VMssObject.ResourceGroupName `
                                    -VirtualMachineScaleSet $VMssObject
        if ($VMssObject.ProvisioningState -ne "Succeeded") {
            throw [VirtualMachineScaleSetOperationFailed]::new($VMssObject, "Failed to update VMSS")
        }
        Write-Host "$vmsslogheader : Successfully updated scale set with extension"
        return $VMssObject                           
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractCloudExceptionErrorCode($_)
        if ($errorCode -eq "ParentResourceNotFound") {
            throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception)
        } 
        
        if($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($($VMssObject.ResourceGroupName), $_.Exception)       
        }
            
        throw [VirtualMachineScaleSetUnknownException]::new($VMssObject, "Failed to update VMSS", $_.Exception)
    }
}

function AssignVmssUserManagedIdentity {
    <#
	.SYNOPSIS
	Assign managed identity to VMss
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$VMssObject
    )

    $userAssignedManagedIdentityName = $UserAssignedManagedIdentityObject.Name
    $vmsslogheader = FormatVmssIdentifier -VMssObject $VmssObject

    if (!($PSCmdlet.ShouldProcess($vmsslogheader, "Assign managed identity $userAssignedManagedIdentityName"))) {
        return $VMssObject
    }

    Write-Host "$vmsslogheader : Assigning user assign managed identity $userAssignedManagedIdentityName"
    try {
        $VMssObject = Update-AzVmss -VMScaleSetName $VMssObject.Name `
                                -ResourceGroupName  $VMssObject.ResourceGroupName `
                                -VirtualMachineScaleSet $VMssObject `
                                -IdentityType "UserAssigned" `
                                -IdentityID $UserAssignedManagedIdentityObject.Id
        if ($VMssObject.ProvisioningState -ne "Succeeded") {
            throw [VirtualMachineOperationScaleSetFailed]::new($VMssObject, "Failed to assign user assigned managed identity $userAssignedManagedIdentityName")
        }
        
        Write-Host "$vmsslogheader : Successfully assigned user assign managed identity $userAssignedManagedIdentityName"
        return $VMssObject
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractCloudExceptionErrorCode($_)
        if ($errorCode -eq "FailedIdentityOperation") {
            throw [UserAssignedManagedIdentityDoesNotExist]::new($UserAssignedManagedIdentityObject, $_.Exception)
        }
        if($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMssObject.ResourceGroupName, $_.Exception)       
        } 
        if ($errorCode -eq "InvalidParameter") {
            throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception) 
        } 
            
        throw [VirtualMachineScaleSetUnknownException]::new($VMssObject, "Failed to user assign managed identity $userAssignedManagedIdentityName", $_.Exception)
    }
}

function AssignVmUserManagedIdentity {
     <#
	.SYNOPSIS
	Assign managed identity to VM
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$VMObject
    )

    $userAssignedManagedIdentityName = $UserAssignedManagedIdentityObject.Name
    $vmlogheader = FormatVmIdentifier -VMObject $VMObject
    
    if (!($PSCmdlet.ShouldProcess($vmlogheader, "Assign managed identity $userAssignedManagedIdentityName"))) {
        return $VMObject
    }

    Write-Host "$vmlogheader : Assigning managed identity $userAssignedManagedIdentityName"

    try {
        $result = Update-AzVM -VM $VMObject `
                                -ResourceGroupName $VMObject.ResourceGroupName `
                                -IdentityType "UserAssigned" `
                                -IdentityID $UserAssignedManagedIdentityObject.Id `
                                                            
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractCloudExceptionErrorCode($_)
        if ($errorCode -eq "FailedIdentityOperation") {
            throw [UserAssignedManagedIdentityDoesNotExist]::new($userAssignedManagedIdentityName, $_.Exception)
        }
        if ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($($VMObject.ResourceGroupName), $_.Exception)       
        }
        if  ($errorCode -eq "InvalidParameter") {
            throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
        }
        
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to update virtual machine with $userAssignedManagedIdentityName", $_.Exception)
    }

    if (!($result.IsSuccessStatusCode)) {
        throw [VirtualMachineOperationFailed]::new($VMObject, "Failed to assign managed identity $userAssignedManagedIdentityName. StatusCode : $($result.StatusCode). ReasonPhrase : $($result.ReasonPhrase)")
    }
    
    Write-Host "$vmlogheader : Successfully assigned managed identity $userAssignedManagedIdentityName"
    return $VMObject
}

function SetManagedIdentityRolesAma {
    <#
    .SYNOPSIS
    Set roles to managed identity
    #>
    param(
        [Parameter(Mandatory = $True)][String] $ResourceGroupName
    )
    
    $userAssignedManagedIdentityName = $UserAssignedManagedIdentityObject.Name
    try { 
        $rgObj = Get-AzResourceGroup -Name $ResourceGroupName
    } catch { 
        throw [ResourceGroupDoesNotExist]::new($ResourceGroupName)
    }

    try {
        SetManagedIdentityRoles -ResourceGroupId $rgObj.ResourceId
    } catch [ErrorResponseException] {
        $excepMessage = $_.Exception.Message
        if ($excepMessage.Contains('Conflict')) {
            Write-Verbose "$userAssignedManagedIdentityName : $role has been assigned already"
        }
        if ($excepMessage.Contains('BadRequest')) {
            [FatalException]::new("$userAssignedManagedIdentityName : User Assigned Managed Identity doesn't exist", $_.Exception)
        } 
        if ($excepMessage.Contains('NotFound')) {
            [ResourceGroupDoesNotExist]::new($($VMObject.ResourceGroupName))
        }
        Write-Host "$ResourceGroupId : Failed to assign managed identity to resource-group. ExceptionInfo = $excepMessage"
    }
}

function PopulateRgHashTableVm {
    <#
    .SYNOPSIS
    Populate Resource group hash table for VMs
    #>
    param(
        [Parameter(Mandatory=$True)][Hashtable]$Rghashtable,
        [Parameter(Mandatory=$True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine] $VMObject
    )

    $vmResourceGroupName = $VMObject.ResourceGroupName
    $rgTableElemObject = $Rghashtable[$vmResourceGroupName]
    if ($null -eq $rgTableElemObject) {
        $rgTableElemObject = [ResourceGroupTableElement]::new()
        $Rghashtable.Add($vmResourceGroupName,$rgTableElemObject)
    }
    $rgTableElemObject.VirtualMachineList.Add($VMObject)  > $null
}

function PopulateRgHashTableVmss {
    <#
    .SYNOPSIS
    Populate Resource group hash table for VMSS
    #>
    param(
        [Parameter(Mandatory=$True)][Hashtable]$Rghashtable,
        [Parameter(Mandatory=$True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet] $VMssObject
    )

    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    $rgTableElemObject = $Rghashtable[$vmssResourceGroupName]
    if ($null -eq $rgTableElemObject) {
        $rgTableElemObject = [ResourceGroupTableElement]::new()
        $Rghashtable.Add($vmssResourceGroupName,$rgTableElemObject)
    }
    $rgTableElemObject.VirtualMachineScaleSetList.Add($VMssObject)  > $null
}

#
# Main Script
#
#
#
try {
    # To report on overall status
    $onboardingCounters = [OnboardingCounters]::new()
    $unknownExceptionVirtualMachineScaleSetConsequentCounter = 0
    $unknownExceptionVirtualMachineConsequentCounter = 0
    $unknownExceptionTotalCounter = 0
    # First make sure we are authenticed and Select the subscription supplied and input parameters are valid.
    $account =  Get-AzContext
    if ($null -eq $account.Account) {
        Write-Host "Account Context not found, please login"
        Connect-AzAccount -subscriptionid $SubscriptionId
    }
    else {
        if ($account.Subscription.Id -eq $SubscriptionId) {
            Write-Verbose "Subscription: $SubscriptionId is already selected."
            $account
        }
        else {
            Write-Host "Current Subscription:"
            $account
            Write-Host "Changing to subscription: $SubscriptionId"
            Select-AzSubscription -SubscriptionId $SubscriptionId
        }
    }

    #script block
    Set-Variable -Name sb_nop_block_roles -Option Constant -Value { param($obj, $rg)} 
    Set-Variable -Name sb_nop_block -Option Constant -Value { param($obj) $obj}
    $Rghashtable = @{}

    Write-Host("Performing script input parameter validation")
    if ($ResourceGroup) {
        try { 
            #Existence test only.
            Get-AzResourceGroup -Name $ResourceGroup
        } catch { 
            throw [FatalException]::new("$ResourceGroup : Invalid ResourceGroup", $_.Exception)
        }
    }

    if ($UserAssignedManagedIdentityName) {
        try {
            Write-Verbose "Validating ($UserAssignedManagedIdentityResourceGroup, $UserAssignedManagedIdentityName)"
            Set-Variable -Name UserAssignedManagedIdentityObject `
                    -Option Constant `
                    -Value (Get-AzUserAssignedIdentity -Name $UserAssignedManagedIdentityName -ResourceGroupName $UserAssignedManagedIdentityResourceGroup)   
        } catch {
            throw [FatalException]::new($_.Exception.Message, $_.Exception)
        }
    }
 
    if (!$isAma) {
        #Cannot validate Workspace existence with WorkspaceId, WorkspaceKey parameters.
        Set-Variable -Name laPublicSettings -Option Constant -Value @{"workspaceId" = $WorkspaceId; "stopOnMultipleConnections" = "true"}
        Set-Variable -Name laProtectedSettings -Option Constant -Value  @{"workspaceKey" = $WorkspaceKey}
        if ($ReInstall) {
            Set-Variable -Name sb_vm -Option Constant -Value { param($vmObj) OnboardVmiWithLaVmWithReInstall -VMObject $vmObj}
        } else {
            Set-Variable -Name sb_vm -Option Constant -Value { param($vmObj) OnboardVmiWithLaVmWithoutReInstall -VMObject $vmObj}
        }
        
        Set-Variable -Name sb_vmss -Option Constant -Value {param($vmssObj) InstallVMssExtension -VMssObject $vmssObj -ExtensionName $laExtensionName -ExtensionConstantProperties $laExtensionMap[$vmssObj.VirtualMachineProfile.StorageProfile.OsDisk.OsType.ToString()] `
                                                                              -Settings $laPublicSettings -ProtectedSetting $laProtectedSettings}
        Set-Variable -Name sb_da -Option Constant -Value { param($vmObj)  OnboardDaVm -VMObject $vmObj}
        Set-Variable -Name sb_da_vmss -Option Constant -Value { param($vmssObj) InstallVMssExtension -VMssObject $vmssObj `
                                                                                      -ExtensionName $daExtensionName `
                                                                                      -ExtensionConstantProperties $daExtensionMap[$vmssObj.VirtualMachineProfile.StorageProfile.OsDisk.OsType.ToString()]}
        Set-Variable -Name sb_roles -Option Constant -Value $sb_nop_block_roles
    } else {
        #VMI supports Customers onboarding DCR from different subscription
        #Cannot validate DCRResourceId as parameter set ByResourceId will be deprecated for - Get-AzDataCollectionRule
        Set-Variable -Name amaPublicSettings -Option Constant -Value `
                   @{
                        'authentication' = @{ 
                            'managedIdentity' = @{
                                'identifier-name' = 'mi_res_id'
                                'identifier-value' = $($UserAssignedManagedIdentityObject.Id) 
                            }
                        }
                    }
        Set-Variable -Name sb_vm -Option Constant -Value { param($vmObj) OnboardVmiWithAmaVm -VMObject $vmObj}
        Set-Variable -Name sb_vmss -Option Constant -Value { param($vmssObj) OnboardVmiWithAmaVmss -VMssObject $vmssObj}
        
        if ($ProcessAndDependencies) {
            Set-Variable -Name sb_da -Option Constant -Value {param($vmObj) OnboardDaVm -VMObject $vmObj -Settings $processAndDependenciesPublicSettings}
            Set-Variable -Name sb_da_vmss -Option Constant -Value { param($vmssObj) InstallVMssExtension -VMssObject $vmssObj `
                                                                                      -ExtensionName $daExtensionName `
                                                                                      -Settings $processAndDependenciesPublicSettings -ExtensionConstantProperties $daExtensionMap[$vmssObj.VirtualMachineProfile.StorageProfile.OsDisk.OsType.ToString()]}
        } else {
            Set-Variable -Name sb_da -Option Constant -Value $sb_nop_block
            Set-Variable -Name sb_da_vmss -Option Constant -Value $sb_nop_block
        }
    
        Set-Variable -Name sb_roles -Option Constant -Value { param($rgName) SetManagedIdentityRolesAma -ResourceGroupName $rgName}
    }

    if ($TriggerVmssManualVMUpdate) {
        Set-Variable -Name sb_upgrade -Option Constant -Value { param($vmssObj)  UpgradeVmssExtensionManualUpdateEnabled -VMssObject $vmssObj}
    } else {
        Set-Variable -Name sb_upgrade -Option Constant -Value  { param($vmssObj)  UpgradeVmssExtensionManualUpdateDisabled -VMssObject $vmssObj}
    }

    if ($PolicyAssignmentName) {
        #this section is only for VMs
        $searchParameters = @{}

        if ($ResourceGroup) {
            $searchParameters.add("ResourceGroupName",  $ResourceGroup)
        }

        Write-Host "Looking up resources in policy assingment $PolicyAssignmentName"
        $policyStateInfo = Get-AzPolicyState @searchParameters `
                            -Filter "PolicyAssignmentName eq '$PolicyAssignmentName' and ResourceType eq 'Microsoft.Compute/virtualMachines'"
        
        $policyAssignmentNameResources = @{}
        foreach ($policyAssignmentNameResourceInfo in $policyStateInfo) {
            $policyAssignmentNameResources.Add($policyAssignmentNameResourceInfo.ResourceId, $True)
        }

        #Virtual Machines part of a VMSS will be skipped.
        Get-AzVM @searchParameters 
        | Where-Object {!($_.VirtualMachineScaleSet) -and $_.Name -like $Name -and $policyAssignmentNameResources.ContainsKey($_.Id)}
        | ForEach-Object {$onboardingCounters.Total +=1 ;
                           PopulateRgHashTableVm -Rghashtable $Rghashtable -VMObject $_}
    } else {
        Write-Host "Getting list of VM's or VM ScaleSets matching criteria specified"
        # If ResourceGroup value is passed - select all VMs under given ResourceGroupName
        $searchParameters = @{}
        if ($ResourceGroup) {
            $searchParameters.add("ResourceGroupName", $ResourceGroup)
        }
       
        Get-AzVM @searchParameters
            | Where-Object {!($_.VirtualMachineScaleSet) -and $_.Name -like $Name}
            | ForEach-Object {$onboardingCounters.Total +=1 ; PopulateRgHashTableVm -Rghashtable $Rghashtable -VMObject $_}
        
        #VMI does not support VMSS with flexible orchestration.
        Get-AzVmss @searchParameters 
            | Where-Object {$_.Name -like $Name -and $_.OrchestrationMode -ne 'Flexible'}
            | ForEach-Object {$onboardingCounters.Total +=1 ; PopulateRgHashTableVmss -RgHashTable $Rghashtable -VMssObject $_}
    }
    
    Write-Host "VMs and VMSS in a non-running state will be skipped."    
    Foreach ($rgName in $Rghashtable.Keys) {
        Write-Host "" "ResourceGroup = $rgName"
        if ($Rghashtable[$rgName].VirtualMachineList.Length -gt 0) {
            Write-Host "" "" "VM's matching selection criteria :" ""
            $Rghashtable[$rgName].VirtualMachineList | ForEach-Object {Write-Host "`t$($_.Name)"}
        }
        if ($Rghashtable[$rgName].VirtualMachineScaleSetList.Length -gt 0) {
            Write-Host "" "" "VM ScaleSets matching selection criteria :" ""
            $Rghashtable[$rgName].VirtualMachineScaleSetList | ForEach-Object {Write-Host "`t$($_.Name)"}
        }
    }
    Write-Host ""

    # Validate customer wants to continue
    if ($Approve -or $PSCmdlet.ShouldContinue("Continue?", "")) {
        Write-Host ""
    } else {
        Write-Host "You selected No - exiting"
        return
    }
    
    ForEach ($rgItem in $Rghashtable.Keys) {
        try {             
            &$sb_roles -rgName $rgItem
            $Vms = $Rghashtable[$rgItem].VirtualMachineList
            $Vmss = $Rghashtable[$rgItem].VirtualMachineScaleSetList

            Foreach ($vm in $Vms) {
                try {
                    $vm = &$sb_vm -vmObj $vm
                    $vm = &$sb_da -vmObj $vm
                    Write-Host "$(FormatVmIdentifier -VMObject $vm) : Successfully onboarded VMInsights"
                    $onboardingCounters.Succeeded +=1
                    $unknownExceptionVirtualMachineConsequentCounter = 0
                } catch [VirtualMachineUnknownException] {
                    if ($unknownExceptionVirtualMachineConsequentCounter -gt $unknownExceptionVirtualMachineConsequentCounterLimit) {
                        [FatalException]::new("Unknown Exceptions consistently seen more than $unknownExceptionVirtualMachineConsequentCounterLimit times", $_.Exception)
                    }
                    if ($unknownExceptionTotalCounter -gt $unknownExceptionTotalCounterLimit) {
                        [FatalException]::new("Unknown Exceptions seen more than $unknownExceptionTotalCounter times", $_.Exception)
                    }
                    Write-Host "UnknownException :"
                    $unknownExceptionTotalCounter+=1
                    $unknownExceptionVirtualMachineConsequentCounter+=1
                    DisplayException $_
                    Write-Host "Continuing to the next Virtual Machine..."
                } catch [VirtualMachineException] {
                    Write-Host "Virtual Machine Exception :"
                    DisplayException $_
                    Write-Host "Continuing to the next Virtual Machine..."
                }
            }

            Foreach ($vmss in $Vmss) {
                try {
                    $vmss = &$sb_vmss -vmssObj $vmss
                    $vmss = &$sb_da_vmss -vmssObj $vmss
                    $vmss = UpdateVMssExtension -VMssObject $vmss
                    if ($vmss.UpgradePolicy.Mode -ne 'Manual') {
                        Write-Host "$vmsslogheader : Upgrade mode is $($VMssObject.UpgradePolicy.Mode). Contuning..."
                        continue
                    }
                    &$sb_upgrade -vmssObj $vmss
                    Write-Host "$(FormatVmssIdentifier -VMssObject $vmss) : Successfully onboarded VMInsights"
                    $onboardingCounters.Succeeded +=1
                    $unknownExceptionVirtualMachineScaleSetConsequentCounter = 0
                } catch [VirtualMachineScaleSetUnknownException] {
                    if ($unknownExceptionVirtualMachineScaleSetConsequentCounter -gt $unknownExceptionVirtualMachineScaleSetConsequentCounterLimit) {
                        [FatalException]::new("Unknown Exceptions consistently seen more than $unknownExceptionVirtualMachineScaleSetConsequentCounterLimit times", $_.Exception)
                    }
                    if ($unknownExceptionTotalCounter -gt $unknownExceptionTotalCounterLimit) {
                        [FatalException]::new("Unknown Exceptions seen more than $unknownExceptionTotalCounter times", $_.Exception)
                    }
                    $unknownExceptionTotalCounter+=1
                    $unknownExceptionVirtualMachineScaleSetConsequentCounter+=1
                    Write-Host "UnknownException :"
                    DisplayException $_
                    Write-Host "Continuing to the next VMSS..."
                } catch [VirtualMachineScaleSetException] {
                    Write-Host "VMSS Exception :"
                    DisplayException $_
                    Write-Host "Continuing to the next VMSS..."
                }
            }
        } catch [ResourceGroupDoesNotExist] {
            Write-Host "Resource-Group Exception :"
            DisplayException $_
            Write-Host "Continuing to the next Resource-Group..."
        }
    }
}
catch [FatalException] {
    Write-Host "FatalException :"
    DisplayException $_
    Write-Host "Exiting the script..."
    exit 1
}
catch {
    Write-Host "UnknownFatalException :"
    DisplayException $_
    Write-Host "Exiting the script..."
    exit 1
}
finally {
    PrintSummaryMessage  $onboardingCounters
}
