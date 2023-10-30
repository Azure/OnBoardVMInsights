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
This script installs VM extensions for Log Analytics/Azure Monitoring Agent (AMA) and Dependency Agent if needed for VM Insights.
If AMA is onboarded, a Data Collection Rule (DCR) and a User Assigned Managed Identity (UAMI) is also associated with the VM's and VMSS.

.DESCRIPTION
This script installs or re-configures the following on VM's and VMSS under a Subscription.
1. Log Analytics VM Extension configured to supply Log Analytics Workspace and Dependency Agent VM Extension.
2. Azure Monitor Agent along with Data Collection Rule association, User Assigned Managed Identity, and Dependency Agent VM Extension (optional).


Scope can further narrowed down to:
- Resource Group
- Specific VM/VMSS
- Policy Assignment Scope

Script will show you list of VM's/VMSS that will apply to and let you confirm to continue.
Use -Approve Switch to run without prompting, if all required parameters are provided.

If the Log Analyitcs Agent extension is already configured with a workspace, use -ReInstall Switch to update the workspace.
Use -WhatIf to get info about expected effect of the commands in the script.

.PARAMETER SubscriptionId
Subscription identifier for the VMs or VMSS
If using PolicyAssignmentName parameter, VMs part of the parameter SubscriptionId are considered.

.PARAMETER ResourceGroup
<Optional> Name of the Resource Group of VMs or VMSS.

.PARAMETER PolicyAssignmentName
<Optional> Name of policy assignment for the VMs or VMSS in its scope.

.PARAMETER Name
<Optional> Name qualifier to match on VM/VMSS's name in the scope. Default behavior is match all. 

.PARAMETER TriggerVmssManualVMUpdate
<Optional> Set this flag to trigger update of VM instances in a scale set whose upgrade policy is set to Manual.

.PARAMETER Approve
<Optional> Set this flag to provide the approval for the installation to start with no confirmation prompt for the listed VM's/VMSS.

.PARAMETER Whatif
<Optional> Set this flag to get info about expected effect of the commands in the script.

.PARAMETER Confirm
<Optional> Set this flag to confirm every command in the script.


.PARAMETER WorkspaceId
Log Analytics WorkspaceID (GUID).

.PARAMETER WorkspaceKey
Log Analytics Workspace primary or secondary key.

.PARAMETER ReInstall
<Optional> Set this flag to trigger removal of existing Log analytics extension and re-installation to migrate log analytics workspaces. 


.PARAMETER DcrResourceId
Data Collection Rule (DCR) azure resource ID identifier.

.PARAMETER UserAssignedManagedIdentityResourceGroup
Name of User Assigned Managed Identity (UAMI) resource group.

.PARAMETER UserAssignedManagedIdentityName
Name of User Assigned Managed Identity (UAMI).

.PARAMETER ProcessAndDependencies
<Optional> Set this flag to onboard Dependency Agent with Azure Monitoring Agent (AMA) settings.

.EXAMPLE
Install-VMInsights.ps1 -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup>
Onboard VMI for all VM's or VMSS in a Resource Group in a subscription with Legacy Agent (LA).

.EXAMPLE
Install-VMInsights.ps1 -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup> -ReInstall
Specify ReInstall to switch workspace with Legacy Agent (Linux) - OMSAgent.

.EXAMPLE
Install-VMInsights.ps1 -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -PolicyAssignmentName a4f79f8ce891455198c08736
Specify PolicyAssignmentName to onboard VMI for VMs part of the policy assignment scope with Legacy Agent (LA).

.EXAMPLE
Install-VMInsights.ps1 -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup>  -DcrResourceId <DataCollectionRuleResourceId> -UserAssignedManagedIdentityName <UserAssignedIdentityName> -UserAssignedManagedIdentityResourceGroup <UserAssignedIdentityResourceGroup>
Onboard VMI for all VM's or VMSS in a Resource Group in a subscription with Azure Monitoring Agent (AMA).
Specify DcrResourceId to associate a data collection rule with VM or VMSS
Specify UserAssignedManagedIdentityName and UserAssignedManagedIdentityResourceGroup for AMA authentication purposes.

.EXAMPLE
Install-VMInsights.ps1 -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup> -ProcessAndDependencies -DcrResourceId <DataCollectionRuleResourceId> -UserAssignedManagedIdentityName <UserAssignedIdentityName> -UserAssignedManagedIdentityResourceGroup <UserAssignedIdentityResourceGroup>
The above command will onboard Assign a UAMI to a VM/VMss for AMA, Onboard AMA and associate a DCR with the VM/Vmss
Specify ProcessAndDependencies to onboard VM's or VMSS with Dependency Agent (DA).

.EXAMPLE
Install-VMInsights.ps1 -SubscriptionId <SubscriptionId> -PolicyAssignmentName a4f79f8ce891455198c08736  -DcrResourceId <DataCollectionRuleResourceId> -UserAssignedManagedIdentityName <UserAssignedIdentityName> -UserAssignedManagedIdentityResourceGroup <UserAssignedIdentityResourceGroup>
Specify PolicyAssignmentName to onboard VMI for VMs part of the policy assignment scope with Azure Monitoring Agent (AMA).

.LINK
This script is posted to and further documented at the following location:
http://aka.ms/OnBoardVMInsights
#>

<#CmdletBinding ConfirmImpact level Info: High - Irreversible action. For example: A resource being deleted. 
                                          Medium (Default) - Resource properties being updated.
                                          Low -  Local variables operations.
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

$ErrorActionPreference = "Stop"

class FatalException : System.Exception {
    FatalException([String]$errorMessage, [Exception]$innerException) : base($errorMessage, $innerException) {}
}

class VirtualMachineException : System.Exception {
    VirtualMachineException([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObject, [String]$errorMessage, [Exception]$innerException)  : base("$(FormatVmIdentifier -VMObject $vmObject) : $errorMessage", $innerException) {}
}

class VirtualMachineScaleSetException : System.Exception {
    VirtualMachineScaleSetException([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObject, [String]$errorMessage, [Exception]$innerException)  : base("$(FormatVmssIdentifier -VMssObject $vmssObject) : $errorMessage", $innerException) {}
}

class ResourceGroupDoesNotExist : System.Exception {
    ResourceGroupDoesNotExist ([String]$rgName, [Exception]$innerException) : base("$rgName : Resource-Group does not exist", $innerException) {}
}

class VirtualMachineUnknownException : VirtualMachineException {
    VirtualMachineUnknownException([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObject,
                                   [String]$errorMessage,
                                   [Exception]$innerException) : base($vmObject, $errorMessage, $innerException) {}
}

class VirtualMachineDoesNotExist : VirtualMachineException {
    VirtualMachineDoesNotExist ([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObject,
                                [Exception]$innerException) : base($vmObject, "VM does not exist", $innerException) {}
}

class VirtualMachineOperationFailed : VirtualMachineException {
    VirtualMachineOperationFailed([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObject,
                                  [String]$errorMessage) : base($vmObject, $errorMessage, $null) {}
}

class VirtualMachinePoweredDown : VirtualMachineException {
    VirtualMachinePoweredDown([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObject,
                              [String]$errorMessage) : base($vmObject, "VM is powered down", $null) {}
}

class VirtualMachineScaleSetUnknownException : VirtualMachineScaleSetException {
    VirtualMachineScaleSetUnknownException([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObject,
                                           [String]$errorMessage,
                                           [Exception]$innerException) : base($vmssObject, $errorMessage, $innerException) {}
}

class VirtualMachineScaleSetDoesNotExist : VirtualMachineScaleSetException {
    VirtualMachineScaleSetDoesNotExist ([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObject,
                                        [Exception]$innerException) : base($vmssObject, "VMSS does not exist", $innerException) {}
}

class VirtualMachineScaleSetOperationFailed : VirtualMachineScaleSetException {
    VirtualMachineScaleSetOperationFailed([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObject,
                                          [String]$errorMessage) : base($vmssObject, $errorMessage, $null) {}
}

class DataCollectionRuleForbidden : FatalException {
    DataCollectionRuleForbidden([String]$dcrResourceId,
                                [Exception]$innerException) : base("$dcrResourceId : Access to Data Collection Rule is forbidden", $innerException) {}
}

class DataCollectionRuleDoesNotExist : FatalException {
    DataCollectionRuleDoesNotExist([String]$dcrResourceId,
                                   [Exception]$innerException) : base("$dcrResourceId : Data Collection Rule does not exist.", $innerException) {}
}

class DataCollectionRuleIncorrect : FatalException {
    DataCollectionRuleIncorrect([String]$dcrResourceId,
                                [Exception]$innerException) : base("$dcrResourceId : Data Collection Rule incorrect format.", $innerException) {}
}

class UserAssignedManagedIdentityDoesNotExist : FatalException {
    UserAssignedManagedIdentityDoesNotExist($uamiobj,
                                            [Exception]$innerException) : base("$($uamiobj.Name) : User Assigned Managed Identity does not exist.", $innerException) {}
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
    "Linux" =  @{  ExtensionType = "OmsAgentForLinux"
                   TypeHandlerVersion = "1.6"
                   Publisher = "Microsoft.EnterpriseCloud.Monitoring"
                }
}
Set-Variable -Name laDefaultExtensionName -Option Constant -Value "MMAExtension"

# Azure Monitoring Agent Extension constants
Set-Variable -Name amaExtensionConstantMap -Option Constant -Value @{ 
       "Windows" = @{ ExtensionType = "AzureMonitorWindowsAgent"
                      TypeHandlerVersion = "1.16"
                      Publisher = "Microsoft.Azure.Monitor" 
                    }
       "Linux" =   @{ ExtensionType = "AzureMonitorLinuxAgent" 
                      TypeHandlerVersion = "1.16"
                      Publisher = "Microsoft.Azure.Monitor"
                    }
}
Set-Variable -Name amaDefaultExtensionName -Option Constant -Value "AzureMonitoringAgent"

# Dependency Agent Extension constants
Set-Variable -Name daExtensionConstantsMap -Option Constant -Value @{
    "Windows" = @{ExtensionType = "DependencyAgentWindows"
                  TypeHandlerVersion = "9.10"
                  Publisher = "Microsoft.Azure.Monitoring.DependencyAgent"
                }
    "Linux" = @{ExtensionType = "DependencyAgentLinux"
                TypeHandlerVersion = "9.10"
                Publisher = "Microsoft.Azure.Monitoring.DependencyAgent"
            }
}
Set-Variable -Name daDefaultExtensionName -Option Constant -Value "DA-Extension"

Set-Variable -Name unknownExceptionVirtualMachineConsequentCounterLimit -Option Constant -Value 3
Set-Variable -Name unknownExceptionVirtualMachineScaleSetConsequentCounterLimit -Option Constant -Value 3
Set-Variable -Name unknownExceptionTotalCounterLimit -Option Constant -Value 6

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
        [Parameter(mandatory = $True)]
        [OnboardingCounters]
        $OnboardingCounters
    )
    Write-Host "Summary:"
    Write-Host "Total VM/VMSS processed: $($OnboardingCounters.Total)"
    Write-Host "Succeeded : $($OnboardingCounters.Succeeded)"
    Write-Host "Failed : $($OnboardingCounters.Total -  $OnboardingCounters.Succeeded)"
}

function ExtractCloudExceptionErrorMessage {
    <#
	.SYNOPSIS
	Extract error code from the Cloud Exception. 
	#>
    param
    (
        [Parameter(Mandatory=$True,Position=0)]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    if ($ErrorRecord.Exception.Message -match 'ErrorMessage: ([^\s]+)') {
        return $matches[1]
    }

    return $null
}

function ExtractCloudExceptionErrorCode {
    <#
	.SYNOPSIS
	Extract error code from the Cloud Exception. 
	#>
    param
    (
        [Parameter(Mandatory=$True,Position=0)]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    if ($ErrorRecord.Exception.Message -match 'ErrorCode: ([^\s]+)') {
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
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]
        $VMObject
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
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]
        $VMssObject
    )
    
    return "($($VMssObject.ResourceGroupName)) $($VMssObject.Name)"
}

function DisplayException {
    <#
    .SYNOPSIS
    Renders the given exception on the console.
    Does not throw any exceptions.
    #>
    param (
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    try {
        $ex = $ErrorRecord.Exception
        while ($ex) {
            Write-Host "ExceptionMessage : $($ex.Message)"
            Write-Verbose "StackTrace :"
            Write-Verbose "$($ex.StackTrace)"
            $ex = $ex.InnerException
        }
        Write-Host "ScriptStackTrace :`r`n$($ErrorRecord.ScriptStackTrace)"
    }
    catch {
        # silently ignore
    }
}

function PopulateRgHashTableVm {
    <#
    .SYNOPSIS
    Populate Resource-group hash table for VMs
    #>
    param(
        [Parameter(Mandatory=$True)]
        [Hashtable]
        $Rghashtable,
        [Parameter(Mandatory=$True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]
        $VMObject
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
    Populate Resource-group hash table for VMSS
    #>
    param(
        [Parameter(Mandatory=$True)]
        [Hashtable]
        $Rghashtable,
        [Parameter(Mandatory=$True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]
        $VMssObject
    )

    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    $rgTableElemObject = $Rghashtable[$vmssResourceGroupName]
    if ($null -eq $rgTableElemObject) {
        $rgTableElemObject = [ResourceGroupTableElement]::new()
        $Rghashtable.Add($vmssResourceGroupName,$rgTableElemObject)
    }
    $rgTableElemObject.VirtualMachineScaleSetList.Add($VMssObject)  > $null
}

function GetVMExtension {
    <#
	.SYNOPSIS
	Return the VM extension of specified Type and Publisher.
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]
        $VMObject,
        [Parameter(mandatory = $True)][Hashtable]
        $ExtensionProperties
    )

    $extensionPublisher = $ExtensionProperties.Publisher
    $extensionType = $ExtensionProperties.ExtensionType

    try {
        $extensions = Get-AzVMExtension -ResourceGroupName $VMObject.ResourceGroupName -VMName $VMObject.Name
        foreach ($extension in $extensions) {
            if ($extension.ExtensionType -eq $extensionType -and $extension.Publisher -eq $extensionPublisher) {
                return $extension
            }
        }
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
    
    return $null
}

function GetVMssExtension {
    <#
	.SYNOPSIS
	Return the VMSS extension of specified ExtensionType and ExtensionPublisher.
	#>
    param
    (
        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]
        $VMssObject,
        [Parameter(mandatory = $True)]
        [Hashtable]
        $ExtensionProperties
    )

    $extensionPublisher = $ExtensionProperties.Publisher
    $extensionType = $ExtensionProperties.ExtensionType

    $extensions = $VMssObject.VirtualMachineProfile.ExtensionProfile.Extensions

    foreach ($extension in $extensions) {
        if ($extension.Type -eq $extensionType -and $extension.Publisher -eq $extensionPublisher) {
            return $extension
        }
    }

    return $null
}

function RemoveVMExtension {
    <#
	.SYNOPSIS
	Remove a VM Extension.
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]
        $VMObject,
        [Parameter(mandatory = $True)]
        [String]
        $ExtensionName,
        [Parameter(mandatory = $True)]
        [hashtable]
        $ExtensionProperties
    )

    $vmlogheader = FormatVmIdentifier -VMObject $VMObject
    $extensionType = $ExtensionProperties.ExtensionType
    $extensionPublisher = $ExtensionProperties.Publisher

    if (!$PSCmdlet.ShouldProcess($vmlogheader, "Remove $ExtensionName, type $extensionType, publisher $extensionPublisher")) {
        return $False
    }

    try {
        #Remove operation on non existent VM, extension still return a success
        $removeResult = Remove-AzVMExtension -ResourceGroupName $VMObject.ResourceGroupName -VMName $VMObject.Name -Name $ExtensionName -Force
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractCloudExceptionErrorCode $_
        if ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMObject.ResourceGroupName,$_.Exception)       
        } 
        
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to remove extension $ExtensionName, type $extensionType, publisher $extensionPublisher", $_.Exception)
    }
    
    if ($removeResult.IsSuccessStatusCode) {
         Write-Host "$vmlogheader : Successfully removed extension $ExtensionName, type $extensionType, publisher $extensionPublisher"
        return $True
    }

    throw [VirtualMachineOperationFailed]::new($VMObject, "Failed to remove extension $ExtensionName, type $extensionType, publisher $extensionPublisher. StatusCode = $($removeResult.StatusCode). ReasonPhrase = $($removeResult.ReasonPhrase)")
}

#VMI supports Customers onboarding DCR from different subscription to which it has access to.
#Cannot validate DCRResourceId parameter Get-AzDataCollectionRule -ResourceId is getting deprecated.        
function NewDCRAssociationVm {
    <#
	.SYNOPSIS
	Create a new DCRAssociation with VMs.
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]
        $VMObject
    )

    $vmId = $VMObject.Id
    $vmlogheader = FormatVmIdentifier -VMObject $VMObject
    
    try {
        # A VM may have zero or more Data Collection Rule Associations.
        $dcrAssociationList = Get-AzDataCollectionRuleAssociation -TargetResourceId $vmId 
        foreach ($dcra in $dcrAssociationList) {
            if ($dcra.DataCollectionRuleId -eq $DcrResourceId) {
                Write-Host "$vmlogheader : Data Collection Rule Id $DcrResourceId already associated to the VM"
                return
            }
        }
    } catch [System.Management.Automation.ParameterBindingException] {
        throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
    }

    if (!($PSCmdlet.ShouldProcess($vmlogheader, "Install Data Collection Rule Association"))) {
        return
    }

    $dcrAssociationName = "VM-Insights-DCR-Association-$(New-Guid)"
    Write-Host "$vmlogheader : Deploying Data Collection Rule Association $dcrAssociationName"
    try {
        #TBF by AMCS team - New-AzDataCollectionRuleAssociation allows creating multiple DCRAs for the same {DCR,VMSS} combination.
        $dcrAssociation = New-AzDataCollectionRuleAssociation -TargetResourceId $vmId -AssociationName $dcrAssociationName -RuleId $DcrResourceId
    } catch [System.Management.Automation.PSInvalidOperationException] {
        $exceptionMessage = $_.Exception.Message
        
        if ($exceptionMessage.Contains('Invalid format of the resource identifier')) {
            throw [DataCollectionRuleIncorrect]::new($DcrResourceId)
        } 

        if (!($exceptionMessage -match "status code '([^\s]+)'")) {
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
    if (($null -eq $dcrAssociation) -or ($dcrAssociation -is [Microsoft.Azure.Management.Monitor.Models.ErrorResponseCommonV2Exception])) {
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to create data collection rule association with $DcrResourceId", $dcrassociation)
    }

    Write-Host "$vmlogheader : Successfully created data collection rule association"
}

function NewDCRAssociationVmss {
    <#
	.SYNOPSIS
	Create a new DCR Association with VMSS.
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]
        $VMssObject
    )

    $vmsslogheader = FormatVmssIdentifier -VMssObject $VMssObject
    $vmssId = $VMssObject.Id

    try {
        # A VMSS may have zero or more Data Collection Rule Associations.
        $dcrAssociationList = Get-AzDataCollectionRuleAssociation -TargetResourceId $vmssId 
        foreach ($dcra in $dcrAssociationList) {
            if ($dcra.DataCollectionRuleId -eq $DcrResourceId) {
                Write-Host "$vmsslogheader : Data Collection Rule Id $DcrResourceId already associated to the VMSS"
                return
            }
        }
    } catch [System.Management.Automation.ParameterBindingException] {
        throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception)
    }

    #The Customer is responsible to uninstall the DCR Association themselves.
    if (!($PSCmdlet.ShouldProcess($vmsslogheader, "Install Data Collection Rule Association"))) {
        return
    }

    $dcrAssociationName = "VM-Insights-DCR-Association-$(New-Guid)"
    Write-Host "$vmsslogheader : Deploying Data Collection Rule Association $dcrAssociationName"
    try {
        #TBF by AMCS team - New-AzDataCollectionRuleAssociation allows creating multiple DCRAs for the same {DCR,VMSS} combination.
        $dcrAssociation = New-AzDataCollectionRuleAssociation -TargetResourceId $vmssId -AssociationName $dcrAssociationName -RuleId $DcrResourceId
    } catch [System.Management.Automation.PSInvalidOperationException] {
        $exceptionMessage = $_.Exception.Message
        
        if ($exceptionMessage.Contains('Invalid format of the resource identifier')) {
            throw [DataCollectionRuleIncorrect]::new($DcrResourceId)
        } 
        
        if (!($exceptionMessage -match "status code '([^\s]+)'")) {
            throw [VirtualMachineScaleSetUnknownException]::new($VMssObject, "Failed to create data collection rule association with $DcrResourceId", $_.Exception)
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

        throw [VirtualMachineUnknownException]::new($VMssObject, "Failed to create data collection rule association with with $DcrResourceId. StatusCode = $statusCode", $_.Exception)
    }
    #Tmp fix task:- 21191002
    if (($null -eq $dcrAssociation) -or ($dcrAssociation -is [Microsoft.Azure.Management.Monitor.Models.ErrorResponseCommonV2Exception])) {
        throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, "Failed to create data collection rule association with $DcrResourceId", $dcrAssociation)
    }
}

function OnboardDaVm {
    <#
	.SYNOPSIS
	Onboard DA on VM, handling if already installed.
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]
        $VMObject,
        [Parameter(mandatory = $True)]
        [hashtable]
        $Settings
    )

    $extensionName = $daDefaultExtensionName
    $daExtensionConstantProperties = $daExtensionConstantsMap[$VMObject.StorageProfile.OsDisk.OsType.ToString()]
    $extension = GetVMExtension -VMObject $VMObject -ExtensionProperties $daExtensionConstantProperties
    # Use supplied name unless already deployed, use same name.
    if ($extension) {
        $extensionName = $extension.Name
        Write-Host "$(FormatVmIdentifier -VMObject $VMObject) : Extension $extensionName, type $($daExtensionConstantProperties.ExtensionType), publisher $($daExtensionConstantProperties.Publisher) already installed. Provisioning State: $($extension.ProvisioningState)"
    }
    
    $parameters = @{"Settings" = $Settings}
    
    return SetVMExtension -VMObject $VMObject `
                          -ExtensionName $extensionName `
                          -ExtensionConstantProperties $daExtensionConstantProperties `
                          -InstallParameters $parameters
}

function OnboardAmaVm {
    <#
	.SYNOPSIS
	Onboard AMA on VM, handling if already installed.
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]
        $VMObject
    )
    
    $amaExtensionConstantProperties = $amaExtensionConstantMap[$VMObject.StorageProfile.OsDisk.OsType.ToString()]
    $extensionName = $amaDefaultExtensionName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionProperties $amaExtensionConstantProperties
    # Use supplied name unless already deployed, use same name.
    if ($extension) {
        $extensionName = $extension.Name
        Write-Host "$(FormatVmIdentifier -VMObject $VMObject) : Extension $extensionName, type $($amaExtensionConstantProperties.ExtensionType), publisher $($amaExtensionConstantProperties.Publisher) already installed. Provisioning State: $($extension.ProvisioningState)"
    }

    $parameters = @{"Settings" = $amaPublicSettings}

    return SetVMExtension -VMObject $VMObject `
                          -ExtensionName $extensionName `
                          -ExtensionConstantProperties $amaExtensionConstantProperties `
                          -InstallParameters $parameters 
}

function OnboardLaVmWithReInstall {
    <#
	.SYNOPSIS
	Onboard LA on VM, ReInstall flag provided.
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]
        $VMObject
    )

    $osType = $VMObject.StorageProfile.OsDisk.OsType.ToString()
    $laExtensionConstantProperties = $laExtensionMap[$osType]
    # Use supplied name unless already deployed, use same name.
    $extensionName = $laDefaultExtensionName
    $vmlogheader = FormatVmIdentifier -VMObject $VMObject
    
    $extension = GetVMExtension -VMObject $VMObject -ExtensionProperties $laExtensionConstantProperties
    # Use supplied name unless already deployed, use same name.
    if ($extension) {
        $extensionName = $extension.Name
        Write-Host "$vmlogheader : Extension $extensionName, type $($laExtensionConstantProperties.ExtensionType), publisher $($laExtensionConstantProperties.Publisher) already installed. Provisioning State: $($extension.ProvisioningState)"
        if ($osType -eq "Linux" -and $extension.PublicSettings) {
            $extensionPublicSettingsJson = $extension.PublicSettings | ConvertFrom-Json
            if ($extensionPublicSettingsJson.workspaceId -ne $laPublicSettings.workspaceId) {
                Write-Host "$vmlogheader : OmsAgentForLinux does not support updating workspace. An uninstall followed by re-install is required."

                if (!(RemoveVMExtension -VMObject $VMObject `
                                        -ExtensionName $extensionName `
                                        -ExtensionProperties $laExtensionConstantProperties)) {
                    Write-Host "$vmlogheader : Extension $extensionName was not removed. Skipping replacement."
                    return $VMObject
                }
            }
        }
    }
    
    $parameters = @{
        Settings           = $laPublicSettings
        ProtectedSettings  = $laProtectedSettings
    }

    return SetVMExtension -VMObject $VMObject `
                          -ExtensionName $extensionName `
                          -ExtensionConstantProperties $laExtensionConstantProperties `
                          -InstallParameters $parameters
}

function OnboardLaVmWithoutReInstall {
    <#
	.SYNOPSIS
	Onboard LA on VM, ReInstall flag not provided.
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]
        $VMObject
    )

    $osType = $VMObject.StorageProfile.OsDisk.OsType.ToString()
    $laExtensionConstantProperties = $laExtensionMap[$osType]
    $extensionName = $laDefaultExtensionName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionProperties $laExtensionConstantProperties
    $vmlogheader = FormatVmIdentifier -VMObject $VMObject
    # Use supplied name unless already deployed, use same name
    if ($extension) {
        $extensionName = $extension.Name
        Write-Host "$vmlogheader : Extension $extensionName, type $($laExtensionConstantProperties.ExtensionType), publisher $($laExtensionConstantProperties.Publisher) already installed. Provisioning State: $($extension.ProvisioningState)"
        if ($osType -eq "Linux" -and $extension.PublicSettings) {
            $ext = $extension.PublicSettings | ConvertFrom-Json 
            if ($ext.workspaceId -ne $laPublicSettings.workspaceId) {
                Write-Host "$vmlogheader : OmsAgentForLinux does not support changing the workspace. Use the -Reinstall flag to make the change."

                return $VMObject
            }
        }
    }

    $parameters = @{
        Settings           = $laPublicSettings
        ProtectedSettings  = $laProtectedSettings
    }

    return SetVMExtension -VMObject $VMObject `
                          -ExtensionName $extensionName `
                          -ExtensionConstantProperties $laExtensionConstantProperties `
                          -InstallParameters $parameters
}

function OnboardVmiWithAmaVm {
    <#
	.SYNOPSIS
	Onboard VMI with AMA on VM.
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]
        $VMObject
    )

    $VMObject = AssignVmUserManagedIdentity -VMObject $VMObject
    NewDCRAssociationVm -VMObject $VMObject
    return OnboardAmaVm -VMObject $VMObject
}

function OnboardVmiWithAmaVmss {
    <#
	.SYNOPSIS
	Onboard VMI with AMA on VMSS
	#>
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]
        $VMssObject
    )
            
    $VMssObject = AssignVmssUserManagedIdentity -VMssObject $VMssObject
    NewDCRAssociationVmss -VMssObject $VMssObject
    return SetVMssExtension -VMssObject $VMssObject `
                                -ExtensionName $amaDefaultExtensionName `
                                -Settings $amaPublicSettings `
                                -ExtensionConstantProperties $amaExtensionConstantMap[$VMssObject.VirtualMachineProfile.StorageProfile.OsDisk.OsType.ToString()]
}

function SetManagedIdentityRoles {
    <#
	.SYNOPSIS
	Set roles to user managed identity.
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)]
        [String]
        $ResourceGroupId,
        [Parameter(Mandatory = $True)]
        [String]
        $Role
    )

    $uamiName = $UserAssignedManagedIdentityObject.Name
    
    if (!($PSCmdlet.ShouldProcess($ResourceGroupId, "Assign $Role to user managed identity $uamiName"))) {
        return
    }

    Write-Verbose "Scope $ResourceGroupId : Assigning role $Role"
    try {
        New-AzRoleAssignment -ObjectId $($UserAssignedManagedIdentityObject.principalId) -RoleDefinitionName $Role -Scope $ResourceGroupId
    } catch {
        $excepMessage = $_.Exception.Message
        if ($excepMessage.Contains('Conflict')) {
            Write-Verbose "$uamiName : Role $Role has been assigned already"
        }
        if ($excepMessage.Contains('BadRequest')) {
            throw [FatalException]::new("$uamiName : User Assigned Managed Identity doesn't exist", $_.Exception)
        }
        if ($excepMessage.Contains('NotFound')) {
            throw [ResourceGroupDoesNotExist]::new($($VMObject.ResourceGroupName))
        }
    }
    Write-Verbose "Scope $ResourceGroupId : $Role has been successfully assigned to $uamiName"
}

function SetVMssExtension {
    <#
	.SYNOPSIS
	Install/Update Extension VMSS, handling if already installed
	#>
    #check if this supposed to be all the stack. that is functioing call it as well.
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]
        $VMssObject,
        [Parameter(mandatory = $True)]
        [String]
        $ExtensionName,
        [Parameter(mandatory = $True)]
        [Hashtable]
        $ExtensionConstantProperties,
        [Parameter(mandatory = $False)]
        [Hashtable]
        $Settings,
        [Parameter(mandatory = $False)]
        [Hashtable]
        $ProtectedSettings
    )

    $extension = GetVMssExtension -VMssObject $VMssObject -ExtensionProperties $ExtensionConstantProperties
    $extensionType = $ExtensionConstantProperties.ExtensionType
    $extensionPublisher = $ExtensionConstantProperties.Publisher
    $vmsslogheader = FormatVmssIdentifier -VMssObject $VMssObject

    if ($extension) {
        Write-Host "$vmsslogheader : Extension $ExtensionName, type $extensionType, publisher $extensionPublisher already installed."

        if ($Settings) {
            $extension.Settings = $Settings
        }
        
        if ($ProtectedSettings) {
            $extension.ProtectedSettingS = $ProtectedSettings
        }

        $extension.TypeHandlerVersion = $ExtensionConstantProperties.TypeHandlerVersion
        return $VMssObject
    } 

    if (!($PSCmdlet.ShouldProcess($vmsslogheader, "Install extension $ExtensionName, type $extensionType, publisher $extensionPublisher"))) {
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
                                      -AutoUpgradeMinorVersion $True `
                                      @parameters

    Write-Host "$vmsslogheader : Extension $ExtensionName, type $extensionType, publisher $extensionPublisher added."
    return $VMssObject
}

function SetVMExtension {
    <#
	.SYNOPSIS
	Install/Update VM Extension, handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]
        $VMObject,
        [Parameter(mandatory = $True)]
        [String]
        $ExtensionName,
        [Parameter(mandatory = $True)]
        [Hashtable]
        $ExtensionConstantProperties,
        [Parameter(mandatory = $True)]
        [Hashtable]
        $InstallParameters
    )
    
    $vmlogheader = $(FormatVmIdentifier -VMObject $VMObject)
    $extensionType = $ExtensionConstantProperties.ExtensionType
    $extensionPublisher = $ExtensionConstantProperties.Publisher

    if (!($PSCmdlet.ShouldProcess($vmlogheader, "Install/Update extension $ExtensionName, type $extensionType, publisher $extensionPublisher"))) {
        return $VMObject
    }

    Write-Host "$vmlogheader : Installing/Updating extension $ExtensionName, type $extensionType, publisher $extensionPublisher"
    
    try {
        $result = Set-AzVMExtension -ResourceGroupName $($VMObject.ResourceGroupName) `
                                    -VMName $($VMObject.Name) `
                                    -Name $ExtensionName `
                                    @InstallParameters @ExtensionConstantProperties -ForceRerun $True

        if (!$result.IsSuccessStatusCode) {
            throw [VirtualMachineOperationFailed]::new($VMObject, "Failed to update extension. StatusCode = $($result.StatusCode). ReasonPhrase = $($result.ReasonPhrase)")
        }
    
        Write-Host "$vmlogheader : Successfully installed/updated extension $ExtensionName, type $extensionType, publisher $extensionPublisher"
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
        
        if ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMObject.ResourceGroupName, $_.Exception)       
        } 
        
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to install/update extension $ExtensionName, type $extensionType, publisher $extensionPublisher", $_.Exception)
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
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]
        $VMssObject
    )

    $vmsslogheader = FormatVmssIdentifier -VMssObject $VMssObject
    Write-Host "$vmsslogheader : UpgradePolicy is Manual. Please trigger upgrade of VMSS or call with -TriggerVmssManualVMUpdate"
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
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]
        $VMssObject
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

    $i = 0
    $instanceCount = $scaleSetInstances.Length
    Foreach ($scaleSetInstance in $scaleSetInstances) {
        $i++
        Write-Host "Upgrading $scaleSetInstanceName, $i of $instanceCount"

        $scaleSetInstanceName = $($scaleSetInstance.Name)
        if ($scaleSetInstance.LatestModelApplied) {
            Write-Verbose "$vmsslogheader : Latest model already applied for $scaleSetInstanceName, $i of $instanceCount"
            continue
        }
        if (!($PSCmdlet.ShouldProcess($vmsslogheader, "Upgrade VMSS instance name $scaleSetInstanceName"))) {
            continue
        }
        Write-Verbose "$vmsslogheader : Upgrading VMSS instance name $scaleSetInstanceName, $i of $instanceCount"
        try {
            $result = Update-AzVmssInstance -ResourceGroupName $vmssResourceGroupName -VMScaleSetName $vmssName -InstanceId $scaleSetInstance.InstanceId
            if ($result.Status -ne "Succeeded") {
                Write-Host "$vmsslogheader : Failed to upgrade VMSS instance name $scaleSetInstanceName, $i of $instanceCount. $($result.Status)"

            } else {
                Write-Verbose "$vmsslogheader : Upgrade VMSS instance name $scaleSetInstanceName, $i of $instanceCount"
            }
        } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
            $errorCode = ExtractCloudExceptionErrorCode($_)
            if ($errorCode -eq "ResourceNotFound") {
                throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception)
            }
            if ($errorCode -eq "ResourceGroupNotFound") {
                throw [ResourceGroupDoesNotExist]::new($VMssObject.ResourceGroupName ,$_.Exception)  
            }
            if ($errorCode -eq "OperationNotAllowed") {
                Write-Host "$vmsslogheader : Unable to lookup VMSS instance name $scaleSetInstanceName. Continuing..."
                DisplayException -ErrorRecord $_
            } 
            
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
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]
        $VMssObject
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
        
        if ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($($VMssObject.ResourceGroupName), $_.Exception)       
        }
            
        throw [VirtualMachineScaleSetUnknownException]::new($VMssObject, "Failed to update VMSS", $_.Exception)
    }
}

function AssignVmssUserManagedIdentity {
    <#
	.SYNOPSIS
	Assign user managed identity to VMSS
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]
        $VMssObject
    )

    $userAssignedManagedIdentityName = $UserAssignedManagedIdentityObject.Name
    $vmsslogheader = FormatVmssIdentifier -VMssObject $VmssObject

    if (!($PSCmdlet.ShouldProcess($vmsslogheader, "Assign user managed identity $userAssignedManagedIdentityName"))) {
        return $VMssObject
    }

    Write-Host "$vmsslogheader : Assigning user managed identity $userAssignedManagedIdentityName"
    try {
        $VMssObject = Update-AzVmss -VMScaleSetName $VMssObject.Name `
                                -ResourceGroupName  $VMssObject.ResourceGroupName `
                                -VirtualMachineScaleSet $VMssObject `
                                -IdentityType "UserAssigned" `
                                -IdentityID $UserAssignedManagedIdentityObject.Id
        if ($VMssObject.ProvisioningState -ne "Succeeded") {
            throw [VirtualMachineOperationScaleSetFailed]::new($VMssObject, "Failed to assign user managed identity $userAssignedManagedIdentityName")
        }
        
        Write-Host "$vmsslogheader : Successfully assigned user managed identity $userAssignedManagedIdentityName"
        return $VMssObject
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractCloudExceptionErrorCode($_)
        if ($errorCode -eq "FailedIdentityOperation") {
            throw [UserAssignedManagedIdentityDoesNotExist]::new($UserAssignedManagedIdentityObject, $_.Exception)
        }
        if ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMssObject.ResourceGroupName, $_.Exception)       
        } 
        if ($errorCode -eq "InvalidParameter") {
            throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception) 
        } 
            
        throw [VirtualMachineScaleSetUnknownException]::new($VMssObject, "Failed to assign user managed identity $userAssignedManagedIdentityName", $_.Exception)
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
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]
        $VMObject
    )

    $userAssignedManagedIdentityName = $UserAssignedManagedIdentityObject.Name
    $vmlogheader = FormatVmIdentifier -VMObject $VMObject
    
    if (!($PSCmdlet.ShouldProcess($vmlogheader, "Assign user managed identity $userAssignedManagedIdentityName"))) {
        return $VMObject
    }

    Write-Host "$vmlogheader : Assigning user managed identity $userAssignedManagedIdentityName"

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
        if ($errorCode -eq "InvalidParameter") {
            throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
        }
        
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to update virtual machine with $userAssignedManagedIdentityName", $_.Exception)
    }

    if (!($result.IsSuccessStatusCode)) {
        throw [VirtualMachineOperationFailed]::new($VMObject, "Failed to assign managed identity $userAssignedManagedIdentityName. StatusCode : $($result.StatusCode). ReasonPhrase : $($result.ReasonPhrase)")
    }
    
    Write-Host "$vmlogheader : Successfully assigned user managed identity $userAssignedManagedIdentityName"
    return $VMObject
}

function SetManagedIdentityRolesAma {
    <#
    .SYNOPSIS
    Set Roles to a managed identity
    #>
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $ResourceGroupName
    )
    
    try { 
        $rgObj = Get-AzResourceGroup -Name $ResourceGroupName
    } catch { 
        throw [ResourceGroupDoesNotExist]::new($ResourceGroupName)
    }

    foreach ($role in @("Virtual Machine Contributor", "Azure Connected Machine Resource Administrator", "Log Analytics Contributor")) {
        SetManagedIdentityRoles -ResourceGroupId $rgObj.ResourceId `
                                -Role $role
    }
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
            Get-AzResourceGroup -Name $ResourceGroup >$null
        } catch { 
            throw [FatalException]::new("$ResourceGroup : Invalid ResourceGroup", $_.Exception)
        }
    }
    
    if (!$isAma) {
        #Cannot validate Workspace existence with WorkspaceId, WorkspaceKey parameters.
        Set-Variable -Name laPublicSettings -Option Constant -Value @{"workspaceId" = $WorkspaceId; "stopOnMultipleConnections" = "true"}
        Set-Variable -Name laProtectedSettings -Option Constant -Value  @{"workspaceKey" = $WorkspaceKey}
        if ($ReInstall) {
            Set-Variable -Name sb_vm -Option Constant -Value { param([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObj) OnboardLaVmWithReInstall -VMObject $vmObj}
        } else {
            Set-Variable -Name sb_vm -Option Constant -Value { param([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObj) OnboardLaVmWithoutReInstall -VMObject $vmObj}
        }
        
        Set-Variable -Name sb_vmss -Option Constant -Value {param([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObj) SetVMssExtension -VMssObject $vmssObj `
                                                                                                                                                            -ExtensionName $laDefaultExtensionName `
                                                                                                                                                            -ExtensionConstantProperties $laExtensionMap[$vmssObj.VirtualMachineProfile.StorageProfile.OsDisk.OsType.ToString()] `
                                                                                                                                                            -Settings $laPublicSettings -ProtectedSetting $laProtectedSettings}
        Set-Variable -Name sb_da -Option Constant -Value { param([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObj)  OnboardDaVm -VMObject $vmObj -Settings @{}}
        Set-Variable -Name sb_da_vmss -Option Constant -Value { param([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObj) SetVMssExtension -VMssObject $vmssObj `
                                                                                                                                                                  -ExtensionName $daDefaultExtensionName `
                                                                                                                                                                   -ExtensionConstantProperties $daExtensionConstantsMap[$vmssObj.VirtualMachineProfile.StorageProfile.OsDisk.OsType.ToString()]}
        Set-Variable -Name sb_roles -Option Constant -Value $sb_nop_block_roles
    } else {
        try {
            Write-Verbose "Validating ($UserAssignedManagedIdentityResourceGroup, $UserAssignedManagedIdentityName)"
            Set-Variable -Name UserAssignedManagedIdentityObject `
                         -Option Constant `
                         -Value (Get-AzUserAssignedIdentity -Name $UserAssignedManagedIdentityName -ResourceGroupName $UserAssignedManagedIdentityResourceGroup)   
        } catch {
            throw [FatalException]::new($_.Exception.Message, $_.Exception)
        }
        
        Set-Variable -Name amaPublicSettings -Option Constant -Value `
                   @{
                        'authentication' = @{ 
                            'managedIdentity' = @{
                                'identifier-name' = 'mi_res_id'
                                'identifier-value' = $($UserAssignedManagedIdentityObject.Id) 
                            }
                        }
                    }
        Set-Variable -Name sb_vm -Option Constant -Value { param([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObj) OnboardVmiWithAmaVm -VMObject $vmObj}
        Set-Variable -Name sb_vmss -Option Constant -Value { param([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObj) OnboardVmiWithAmaVmss -VMssObject $vmssObj}
        
        if (!$ProcessAndDependencies) {
            Set-Variable -Name sb_da -Option Constant -Value $sb_nop_block
            Set-Variable -Name sb_da_vmss -Option Constant -Value $sb_nop_block
        } else {
            Set-Variable -Name processAndDependenciesPublicSettings -Option Constant -Value @{"enableAMA" = "true"}
            Set-Variable -Name sb_da -Option Constant -Value {param([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObj) OnboardDaVm -VMObject $vmObj `
                                                                                                                                            -Settings $processAndDependenciesPublicSettings}
            Set-Variable -Name sb_da_vmss -Option Constant -Value { param([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObj) SetVMssExtension -VMssObject $vmssObj `
                                                                                                                                                                                  -ExtensionName $daDefaultExtensionName `
                                                                                                                                                                                  -Settings $processAndDependenciesPublicSettings `
                                                                                                                                                                                  -ExtensionConstantProperties $daExtensionConstantsMap[$vmssObj.VirtualMachineProfile.StorageProfile.OsDisk.OsType.ToString()]}
        }
    
        Set-Variable -Name sb_roles -Option Constant -Value { param([String]$rgName) SetManagedIdentityRolesAma -ResourceGroupName $rgName}
    }

    if ($TriggerVmssManualVMUpdate) {
        Set-Variable -Name sb_upgrade -Option Constant -Value { param([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObj)  UpgradeVmssExtensionManualUpdateEnabled -VMssObject $vmssObj}
    } else {
        Set-Variable -Name sb_upgrade -Option Constant -Value  { param([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObj)  UpgradeVmssExtensionManualUpdateDisabled -VMssObject $vmssObj}
    }

    $searchParameters = @{}
    if ($ResourceGroup) {
        $searchParameters.add("ResourceGroupName", $ResourceGroup)
    }

    if ($PolicyAssignmentName) {
        #this section is only for VMs
        Write-Host "Looking up Virtual Machines in policy assingment $PolicyAssignmentName"

        $policyAssignmentNameResources = @{}
        Get-AzPolicyState @searchParameters -Filter "PolicyAssignmentName eq '$PolicyAssignmentName' and ResourceType eq 'Microsoft.Compute/virtualMachines'"
                          | ForEach-Object {
                            $policyAssignmentNameResources.Add($_.ResourceId, $True)
                          }

        #Virtual Machines part of a VMSS will be skipped.
        Get-AzVM @searchParameters
            | Where-Object {!($_.VirtualMachineScaleSet) -and $_.Name -like $Name -and $policyAssignmentNameResources.ContainsKey($_.Id)}
            | ForEach-Object {
                $onboardingCounters.Total +=1 ;
                PopulateRgHashTableVm -Rghashtable $Rghashtable -VMObject $_
              }
    } else {
        Write-Host "Getting list of VMs or VM Scale Sets matching specified criteria."

        # If ResourceGroup value is passed - select all VMs under given ResourceGroupName
        
        Get-AzVM @searchParameters
            | Where-Object {!($_.VirtualMachineScaleSet) -and $_.Name -like $Name}
            | ForEach-Object { 
                $onboardingCounters.Total +=1 ; 
                PopulateRgHashTableVm -Rghashtable $Rghashtable -VMObject $_
              }
        
        #VMI does not support VMSS with flexible orchestration.
        Get-AzVmss @searchParameters 
            | Where-Object {$_.Name -like $Name -and $_.OrchestrationMode -ne 'Flexible'}
            | ForEach-Object {
                $onboardingCounters.Total +=1 ; 
                PopulateRgHashTableVmss -RgHashTable $Rghashtable -VMssObject $_
              }
    }

    $rgList = Sort-Object -InputObject $Rghashtable.Keys
    Write-Host "VM's and VMSS matching selection criteria :"
    Foreach ($rg in $rgList) {
        $rgTableObj  = $Rghashtable[$rg]
        $vmList = $rgTableObj.VirtualMachineList
        $vmssList = $rgTableObj.VirtualMachineScaleSetList
        Write-Host "" "ResourceGroup : $rg"

        if ($vmList.Length -gt 0) {
            $vmList = Sort-Object -Property Name -InputObject $vmList
            $vmList | ForEach-Object { Write-Host " " "$($_.Name)" }
            $rgTableObj.VirtualMachineList = $vmList
        }

        if ($vmssList.Length -gt 0) {
            $vmssList = Sort-Object -Property Name -InputObject $vmssList
            $vmssList | ForEach-Object { Write-Host " " "$($_.Name)" }
            $rgTableObj.VirtualMachineScaleSetList = $vmssList
        }
    }
    Write-Host ""

    # Validate customer wants to continue
    if ($Approve -or $PSCmdlet.ShouldContinue("Continue?", "")) {
        Write-Host ""
    } else {
        Write-Host "You selected No - exiting"
        $onboardingCounters.Total = 0
        exit 1
    }
    
    ForEach ($rg in $rgList) {
        try {
            $rgTableObj  = $Rghashtable[$rg]
            &$sb_roles -rgName $rg
            
            foreach ($vm in $rgTableObj.VirtualMachineList) {
                try {
                    $vm = &$sb_vm -vmObj $vm
                    $vm = &$sb_da -vmObj $vm
                    Write-Host "$(FormatVmIdentifier -VMObject $vm) : Successfully onboarded VMInsights"
                    $onboardingCounters.Succeeded +=1
                    $unknownExceptionVirtualMachineConsequentCounter = 0
                } catch [VirtualMachineUnknownException] {
                    if ($unknownExceptionVirtualMachineConsequentCounter -gt $unknownExceptionVirtualMachineConsequentCounterLimit) {
                        throw [FatalException]::new("More than $unknownExceptionVirtualMachineConsequentCounterLimit unexpected exceptions encountered consequtively", $_.Exception)
                    }
                    if ($unknownExceptionTotalCounter -gt $unknownExceptionTotalCounterLimit) {
                        throw [FatalException]::new("More than $unknownExceptionTotalCounterLimit unexpected exceptions encountered", $_.Exception)
                    }
                    Write-Host "Unexpected VM Exception :"
                    $unknownExceptionTotalCounter+=1
                    $unknownExceptionVirtualMachineConsequentCounter+=1
                    DisplayException -ErrorRecord $_
                    Write-Host "Continuing to the next VM..."
                } catch [VirtualMachineException] {
                    Write-Host "VM Exception :"
                    DisplayException -ErrorRecord $_
                    Write-Host "Continuing to the next VM..."
                }
            }

            foreach ($vmss in $rgTableObj.VirtualMachineScaleSetList) {
                try {
                    $vmsslogheader = FormatVmssIdentifier -VMssObject $vmss
                    $vmss = &$sb_vmss -vmssObj $vmss
                    $vmss = &$sb_da_vmss -vmssObj $vmss
                    $vmss = UpdateVMssExtension -VMssObject $vmss
                    if ($vmss.UpgradePolicy.Mode -eq 'Manual') {
                        &$sb_upgrade -vmssObj $vmss    
                    } else {
                        Write-Host "$vmsslogheader : Upgrade mode is $($vmss.UpgradePolicy.Mode)."

                    }
                    
                    Write-Host "$vmsslogheader : Successfully onboarded VMInsights"
                    $onboardingCounters.Succeeded +=1
                    $unknownExceptionVirtualMachineScaleSetConsequentCounter = 0
                } catch [VirtualMachineScaleSetUnknownException] {
                    if ($unknownExceptionVirtualMachineScaleSetConsequentCounter -gt $unknownExceptionVirtualMachineScaleSetConsequentCounterLimit) {
                        throw [FatalException]::new("More than $unknownExceptionVirtualMachineScaleSetConsequentCounterLimit unexpected exceptions encountered consequtively", $_.Exception)
                    }
                    if ($unknownExceptionTotalCounter -gt $unknownExceptionTotalCounterLimit) {
                        throw [FatalException]::new("More than $unknownExceptionTotalCounterLimit unexpected exceptions encountered", $_.Exception)
                    }
                    $unknownExceptionTotalCounter+=1
                    $unknownExceptionVirtualMachineScaleSetConsequentCounter+=1
                    Write-Host "Unexpected VMSS Exception :"
                    DisplayException -ErrorRecord $_
                    Write-Host "Continuing to the next VMSS..."
                } catch [VirtualMachineScaleSetException] {
                    Write-Host "VMSS Exception :"
                    DisplayException -ErrorRecord $_
                    Write-Host "Continuing to the next VMSS..."
                }
            }
        } catch [ResourceGroupDoesNotExist] {
            Write-Host "Resource-Group Exception :"
            DisplayException -ErrorRecord $_
            Write-Host "Continuing to the next Resource-Group..."
        }
    }
}
catch [FatalException] {
    Write-Host "Fatal Exception :"

    DisplayException -ErrorRecord $_
    Write-Host "Exiting..."
    exit 1
}
catch {
    Write-Host "Unexpected Fatal Exception :"

    DisplayException -ErrorRecord $_
    Write-Host "Exiting..."
    exit 1
}
finally {
    PrintSummaryMessage  $onboardingCounters
}
