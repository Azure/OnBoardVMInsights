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


Scope can further narrowed down to :
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
<Optional> Name of the Resource Group of VMs or VMSS. It accepts wildcard characters. The default behavior is to match all.

.PARAMETER PolicyAssignmentName
<Optional> Name of policy assignment to onboard VMI for VMs part of its scope with Azure Monitoring Agent (AMA)/Log Analytics Agent (LA)

.PARAMETER Name
<Optional> Name qualifier to match on VM/VMSS's name in the scope. It accepts wildcard characters. The default behavior is to match all.

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
This script is posted to and further documented at the following location :
http://aka.ms/OnBoardVMInsights
#>

<#CmdletBinding ConfirmImpact level Info : High - Customer data-flow disruptive action.
                                           Medium - Everything else that changes the system configuration. 
#>
#Assumption - The script assumes the entity running the script has access to all VMs/VMSS in the script.
[CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
param(
    [Parameter(mandatory = $True)][String]$SubscriptionId,
    [Parameter(mandatory = $False)][Switch]$TriggerVmssManualVMUpdate,
    [Parameter(mandatory = $False)][Switch]$Approve,
    [Parameter(mandatory = $False)][String]$ResourceGroup = "*",
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
    ResourceGroupDoesNotExist ([String]$rgName, [Exception]$innerException) : base("$rgName : Resource Group does not exist", $innerException) {}
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
    UserAssignedManagedIdentityDoesNotExist($uamiName,
                                            [Exception]$innerException) : base("$uamiName : User Assigned Managed Identity does not exist.", $innerException) {}
}

class UserAssignedManagedIdentityResourceGroupDoesNotExist : FatalException {
    UserAssignedManagedIdentityResourceGroupDoesNotExist($uamiResourceGroup,
                                            [Exception]$innerException) : base("$uamiResourceGroup : User Assigned Managed Identity does not exist.", $innerException) {}
}

class UserAssignedManagedIdentityUnknownException : FatalException {
    UserAssignedManagedIdentityUnknownException([String]$errorMessage,
                                                [Exception]$innerException) : base($errorMessage, $innerException) {}
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
    "Windows" = @{  ExtensionType = "MicrosoftMonitoringAgent"
                    TypeHandlerVersion = "1.0"
                    Publisher = "Microsoft.EnterpriseCloud.Monitoring"
                }
    "Linux" =  @{   ExtensionType  = "OmsAgentForLinux"
                    TypeHandlerVersion  = "1.6"
                    Publisher = "Microsoft.EnterpriseCloud.Monitoring"
                }
}
Set-Variable -Name laDefaultExtensionName -Option Constant -Value "MMAExtension"

# Azure Monitoring Agent Extension constants
Set-Variable -Name amaExtensionConstantMap -Option Constant -Value @{ 
       "Windows" = @{  ExtensionType = "AzureMonitorWindowsAgent"
                       TypeHandlerVersion = "1.16"
                       Publisher = "Microsoft.Azure.Monitor" 
                    }
       "Linux" =   @{  ExtensionType = "AzureMonitorLinuxAgent" 
                       TypeHandlerVersion = "1.16"
                       Publisher = "Microsoft.Azure.Monitor"
                    }
}
Set-Variable -Name amaDefaultExtensionName -Option Constant -Value "AzureMonitoringAgent"

# Dependency Agent Extension constants
Set-Variable -Name daExtensionConstantsMap -Option Constant -Value @{
    "Windows" = @{ ExtensionType = "DependencyAgentWindows"
                   TypeHandlerVersion = "9.10"
                   Publisher = "Microsoft.Azure.Monitoring.DependencyAgent"
                }
    "Linux" = @{ ExtensionType = "DependencyAgentLinux"
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
    Write-Host "Summary :"
    Write-Host "Total VM/VMSS to be processed : $($OnboardingCounters.Total)"
    Write-Host "Succeeded : $($OnboardingCounters.Succeeded)"
    Write-Host "Failed : $($OnboardingCounters.Total - $OnboardingCounters.Succeeded)"
}

function ExtractCloudExceptionErrorMessage {
    <#
	.SYNOPSIS
	Extract error code from the Cloud Exception. 
	#>
    param
    (
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    if ($ErrorRecord.Exception.Message -match 'ErrorMessage : ([^\s]+)') {
        return $matches[1]
    }

    return $null
}

function ExtractExceptionErrorCode {
    <#
	.SYNOPSIS
	Extract error code from the Cloud Exception. 
	#>
    param
    (
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    if ($ErrorRecord.Exception.Message -match 'ErrorCode : ([^\s]+)') {
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
        Write-Host "ScriptStackTrace :" $ErrorRecord.ScriptStackTrace

    }
    catch {
        # silently ignore
    }
}

function GetRgObject {

    <#
    .SYNOPSIS
    PopulateRgHashTableVMs/VMss util function
    #>
    param(
        [Parameter(Mandatory=$True)]
        [Hashtable]
        $Rghashtable,
        [Parameter(Mandatory=$True)]
        [String]
        $ResourceGroupName
    )

    $rgTableElemObject = $Rghashtable[$ResourceGroupName]
    if ($null -eq $rgTableElemObject) {
        $rgTableElemObject = [ResourceGroupTableElement]::new()
        $Rghashtable.Add($ResourceGroupName,$rgTableElemObject)
    }

    return $rgTableElemObject
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

    $rgTableElemObject = UtilPopulateRgHashTable -Rghashtable $Rghashtable -ResourceGroupName $VMObject.ResourceGroupName
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

    $rgTableElemObject = UtilPopulateRgHashTable -Rghashtable $Rghashtable -ResourceGroupName $VMssObject.ResourceGroupName
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
        [Parameter(mandatory = $True)]
        [Hashtable]
        $ExtensionProperties
    )

    $extensionType = $ExtensionProperties.ExtensionType
    $publisher = $ExtensionProperties.Publisher

    try {
        $extensions = Get-AzVMExtension -ResourceGroupName $VMObject.ResourceGroupName -VMName $VMObject.Name
        foreach ($extension in $extensions) {
            if ($extension.ExtensionType -eq $extensionType -and $extension.Publisher -eq $publisher) {
                return $extension
            }
        }
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractExceptionErrorCode -ErrorRecord $_
        if ($errorCode -eq "ParentResourceNotFound") {
            throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
        }
        if ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($($VMObject.ResourceGroupName),$_.Exception)   
        }    
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to locate extension with type = $extensionType.$publisher", $_.Exception)
    }
    
    return $null
}

function GetVMssExtension {
    <#
	.SYNOPSIS
	Return the VMSS extension of specified ExtensionType and Publisher.
	#>
    param
    (
        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]
        $VMssObject,
        [Parameter(mandatory = $True)]
        [String]
        $ExtensionType,
        [Parameter(mandatory = $True)]
        [String]
        $Publisher
    )

    $extensions = $VMssObject.VirtualMachineProfile.ExtensionProfile.Extensions

    foreach ($extension in $extensions) {
        if ($extension.Type -eq $ExtensionType -and $extension.Publisher -eq $Publisher) {
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

    if (!$PSCmdlet.ShouldProcess($vmlogheader, "Remove $ExtensionName, type $extensionType.$extensionPublisher")) {
        return $False
    }

    try {
        #Remove operation on non existent VM, extension still return a success
        $removeResult = Remove-AzVMExtension -ResourceGroupName $VMObject.ResourceGroupName `
                                             -VMName $VMObject.Name `
                                             -Name $ExtensionName -Confirm:$false -Force
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractExceptionErrorCode -ErrorRecord $_
        if ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMObject.ResourceGroupName,$_.Exception)       
        } 
        
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to remove extension $ExtensionName, type $extensionType.$extensionPublisher", $_.Exception)
    }
    
    if ($removeResult.IsSuccessStatusCode) {
         Write-Host "$vmlogheader : Successfully removed extension $ExtensionName, type $extensionType.$extensionPublisher"
        return $True
    }

    throw [VirtualMachineOperationFailed]::new($VMObject, "Failed to remove extension $ExtensionName, type $extensionType.$extensionPublisher. StatusCode = $($removeResult.StatusCode). ReasonPhrase = $($removeResult.ReasonPhrase)")
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
                Write-Host "$vmlogheader : Data Collection Rule Id $DcrResourceId already associated with the VM."

                return
            }
        }
    } catch [System.Management.Automation.ParameterBindingException] {
        throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
    }

    if (!($PSCmdlet.ShouldProcess($vmlogheader, "Install Data Collection Rule Association"))) {
        return
    }

    #Customer can associate multiple DCRs to a VM.
    $dcrAssociationName = "VM-Insights-DCR-Association-$(New-Guid)"
    Write-Host "$vmlogheader : Deploying Data Collection Rule Association $dcrAssociationName"
    try {
        #TBF by AMCS team - New-AzDataCollectionRuleAssociation allows creating multiple DCRAs for the same {DCR,VMSS} combination.
        $dcrAssociation = New-AzDataCollectionRuleAssociation -TargetResourceId $vmId `
                                                              -AssociationName $dcrAssociationName `
                                                              -RuleId $DcrResourceId `
                                                              -Confirm:$false
    } catch [System.Management.Automation.PSInvalidOperationException] {
        $exceptionMessage = $_.Exception.Message
        
        if ($exceptionMessage.Contains('Invalid format of the resource identifier')) {
            throw [DataCollectionRuleIncorrect]::new($DcrResourceId)
        } 

        if (!($exceptionMessage -match "status code '([^\s]+)'")) {
            throw [VirtualMachineUnknownException]::new($VMObject, "Failed to create Data Collection Rule Association with $DcrResourceId", $_.Exception)
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

        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to create Data Collection Rule Association with with $DcrResourceId. StatusCode = $statusCode", $_.Exception)
    }

    #Tmp fix task :- 21191002
    if (($null -eq $dcrAssociation) -or ($dcrAssociation -is [Microsoft.Azure.Management.Monitor.Models.ErrorResponseCommonV2Exception])) {
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to create Data Collection Rule Association with $DcrResourceId", $dcrassociation)
    }

    Write-Host "$vmlogheader : Successfully created Data Collection Rule Association"
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
                Write-Host "$vmsslogheader : Data Collection Rule Id $DcrResourceId already associated with the VMSS."

                return
            }
        }
    } catch [System.Management.Automation.ParameterBindingException] {
        throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception)
    }

    if (!($PSCmdlet.ShouldProcess($vmsslogheader, "Install Data Collection Rule Association"))) {
        return
    }

    #Customer can associate multiple DCRs to a VMSS.
    $dcrAssociationName = "VM-Insights-DCR-Association-$(New-Guid)"
    Write-Host "$vmsslogheader : Deploying Data Collection Rule Association $dcrAssociationName"
    try {
        #BUG! To be fixed by AMCS team - New-AzDataCollectionRuleAssociation allows creating multiple DCRAs for the same {DCR,VMSS} combination.
        $dcrAssociation = New-AzDataCollectionRuleAssociation -TargetResourceId $vmssId `
                                                              -AssociationName $dcrAssociationName `
                                                              -RuleId $DcrResourceId `
                                                              -Confirm:$false
    } catch [System.Management.Automation.PSInvalidOperationException] {
        $exceptionMessage = $_.Exception.Message
        
        if ($exceptionMessage.Contains('Invalid format of the resource identifier')) {
            throw [DataCollectionRuleIncorrect]::new($DcrResourceId)
        } 
        
        if (!($exceptionMessage -match "status code '([^\s]+)'")) {
            throw [VirtualMachineScaleSetUnknownException]::new($VMssObject, "Failed to create Data Collection Rule Association with $DcrResourceId", $_.Exception)
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

        throw [VirtualMachineUnknownException]::new($VMssObject, "Failed to create Data Collection Rule Association with with $DcrResourceId. StatusCode = $statusCode", $_.Exception)
    }
    #Tmp fix task :- 21191002
    if (($null -eq $dcrAssociation) -or ($dcrAssociation -is [Microsoft.Azure.Management.Monitor.Models.ErrorResponseCommonV2Exception])) {
        throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, "Failed to create Data Collection Rule Association with $DcrResourceId", $dcrAssociation)
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
        $InstallParameters
    )

    $extensionName = $daDefaultExtensionName
    $daExtensionConstantProperties = $daExtensionConstantsMap[$VMObject.StorageProfile.OsDisk.OsType.ToString()]
    $extension = GetVMExtension -VMObject $VMObject -ExtensionProperties $daExtensionConstantProperties
    # Use supplied name unless already deployed, use same name.
    if ($extension) {
        $extensionName = $extension.Name
        Write-Host "$(FormatVmIdentifier -VMObject $VMObject) : Extension $extensionName, type $($daExtensionConstantProperties.ExtensionType).$($daExtensionConstantProperties.Publisher) already installed. Provisioning State : $($extension.ProvisioningState)"
    }
    
    return SetVMExtension -VMObject $VMObject `
                          -ExtensionName $extensionName `
                          @daExtensionConstantProperties `
                          -InstallParameters $InstallParameters
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
        $VMObject,
        [Parameter(mandatory = $True)]
        [hashtable]
        $InstallParameters
    )
    
    $amaExtensionConstantProperties = $amaExtensionConstantMap[$VMObject.StorageProfile.OsDisk.OsType.ToString()]
    $extensionName = $amaDefaultExtensionName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionProperties $amaExtensionConstantProperties
    # Use supplied name unless already deployed, use same name.
    if ($extension) {
        $extensionName = $extension.Name
        Write-Host "$(FormatVmIdentifier -VMObject $VMObject) : Extension $extensionName, type $($amaExtensionConstantProperties.ExtensionType).$($amaExtensionConstantProperties.Publisher) already installed. Provisioning State : $($extension.ProvisioningState)"
    }
    
    return SetVMExtension -VMObject $VMObject `
                          -ExtensionName $extensionName `
                          @amaExtensionConstantProperties `
                          -InstallParameters $InstallParameters
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
        $VMObject,
        [Parameter(mandatory = $True)]
        [hashtable]
        $InstallParameters
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
        Write-Host "$vmlogheader : Extension $extensionName, type $($laExtensionConstantProperties.ExtensionType).$($laExtensionConstantProperties.Publisher) already installed. Provisioning State : $($extension.ProvisioningState)"
        if ($osType -eq "Linux" -and $extension.PublicSettings) {
            $extensionPublicSettingsJson = $extension.PublicSettings | ConvertFrom-Json
            if ($extensionPublicSettingsJson.workspaceId -ne $InstallParameters.Settings.workspaceId) {
                Write-Host "$vmlogheader : OmsAgentForLinux requires an uninstall followed by a re-install to change the workspace."

                if (!(RemoveVMExtension -VMObject $VMObject `
                                        -ExtensionName $extensionName `
                                        -ExtensionProperties $laExtensionConstantProperties)) {
                    #since there is no data loss, this is counted as a success.
                    Write-Host "$vmlogheader : Extension $extensionName was not removed. Skipping replacement."
                    return $VMObject
                }
            }
        }
    }
    
    return SetVMExtension -VMObject $VMObject `
                          -ExtensionName $extensionName `
                          @laExtensionConstantProperties `
                          -InstallParameters $InstallParameters
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
        $VMObject,
        [Parameter(mandatory = $True)]
        [hashtable]
        $InstallParameters
    )

    $osType = $VMObject.StorageProfile.OsDisk.OsType.ToString()
    $laExtensionConstantProperties = $laExtensionMap[$osType]
    $extensionName = $laDefaultExtensionName
    $extension = GetVMExtension -VMObject $VMObject -ExtensionProperties $laExtensionConstantProperties
    $vmlogheader = FormatVmIdentifier -VMObject $VMObject
    # Use supplied name unless already deployed, use same name
    if ($extension) {
        $extensionName = $extension.Name
        Write-Host "$vmlogheader : Extension $extensionName, type $($laExtensionConstantProperties.ExtensionType).$($laExtensionConstantProperties.Publisher) already installed. Provisioning State : $($extension.ProvisioningState)"
        if ($osType -eq "Linux" -and $extension.PublicSettings) {
            $extensionPublicSettingsJson = $extension.PublicSettings | ConvertFrom-Json 
            if ($extensionPublicSettingsJson.workspaceId -ne $InstallParameters.Settings.workspaceId) {
                Write-Host "$vmlogheader : OmsAgentForLinux does not support changing the workspace. Use the -Reinstall flag to make the change."
                return $VMObject
            }
        }
    }

    return SetVMExtension -VMObject $VMObject `
                          -ExtensionName $extensionName `
                          @laExtensionConstantProperties `
                          -InstallParameters $InstallParameters
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
        $VMObject,
        [Parameter(mandatory = $True)]
        [hashtable]
        $InstallParameters
    )

    $VMObject = AssignVmUserManagedIdentity -VMObject $VMObject
    NewDCRAssociationVm -VMObject $VMObject
    return OnboardAmaVm -VMObject $VMObject -InstallParameters $InstallParameters
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
        $VMssObject,
        [Parameter(mandatory = $True)]
        [hashtable]
        $InstallParameters
    )
            
    $VMssObject = AssignVmssUserManagedIdentity -VMssObject $VMssObject
    NewDCRAssociationVmss -VMssObject $VMssObject
    return OnboardVMssExtension -VMssObject $VMssObject `
                            -ExtensionName $amaDefaultExtensionName `
                            -ExtensionConstantProperties `
                              $amaExtensionConstantMap[$VMssObject.VirtualMachineProfile.StorageProfile.OsDisk.OsType.ToString()] `
                            -InstallParameters $InstallParameters
}

function SetManagedIdentityRoles {
    <#
	.SYNOPSIS
	Set roles to User Assigned Managed Identity.
	#>
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $True)]
        [String]
        $ResourceGroupId,
        [Parameter(Mandatory = $True)]
        [object]
        $UserAssignedManagedIdentity,
        [Parameter(Mandatory = $True)]
        [String[]]
        $Roles
    )

    $uamiName = $UserAssignedManagedIdentity.Name
    if (!($PSCmdlet.ShouldProcess($ResourceGroupId, "Assign $Roles to User Assigned Managed Identity $uamiName"))) {
        return
    }

    Write-Host "$ResourceGroupId : Assigning roles"
    foreach ($role in $Roles) {
        Write-Verbose "Assigning role $role"
        try {
            New-AzRoleAssignment -ObjectId $($UserAssignedManagedIdentity.principalId) `
                                 -RoleDefinitionName $role `
                                 -Scope $ResourceGroupId `
                                 -Confirm:$false
        } catch {
            $excepMessage = $_.Exception.Message
            if ($excepMessage.Contains('Conflict')) {
                Write-Verbose "$uamiName : Role $role has been assigned already"
            }
            if ($excepMessage.Contains('BadRequest')) {
                throw [FatalException]::new("$uamiName : User Assigned Managed Identity doesn't exist", $_.Exception)
            }
            if ($excepMessage.Contains('NotFound')) {
                throw [ResourceGroupDoesNotExist]::new($($VMObject.ResourceGroupName))
            }
        }
        Write-Verbose "$ResourceGroupId : $role has been successfully assigned to $uamiName"
    }
}

function OnboardVMssExtension {
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
        [String]
        $ExtensionType,
        [Parameter(mandatory = $True)]
        [String]
        $TypeHandlerVersion,
        [Parameter(mandatory = $True)]
        [String]
        $Publisher,
        [Parameter(mandatory = $True)]
        [Hashtable]
        $InstallParameters
    )

    $extension = GetVMssExtension -VMssObject $VMssObject -ExtensionType $ExtensionType -Publisher $Publisher
    $vmsslogheader = FormatVmssIdentifier -VMssObject $VMssObject

    if ($extension) {
        if (!($PSCmdlet.ShouldProcess($vmsslogheader, "Update extension $($extension.Name), type $ExtensionType.$Publisher"))) {
            return $VMssObject
        }
        Write-Host "$vmsslogheader : Extension $($extension.Name), type $ExtensionType.$Publisher already installed."
        $InstallParameters.GetEnumerator() | ForEach-Object { $extension.($_.Key) = $_.Value }
        $extension.TypeHandlerVersion = $TypeHandlerVersion
        return $VMssObject
    } 

    if (!($PSCmdlet.ShouldProcess($vmsslogheader, "Install extension $ExtensionName, type $ExtensionType.$Publisher"))) {
        return $VMssObject
    }
    
    $VMssObject = Add-AzVmssExtension -VirtualMachineScaleSet $VMssObject `
                                      -Name $ExtensionName `
                                      -Type $ExtensionType `
                                      -Publisher $Publisher `
                                      -TypeHandlerVersion $TypeHandlerVersion `
                                      -AutoUpgradeMinorVersion $True `
                                      @InstallParameters `
                                      -Confirm:$false


    Write-Host "$vmsslogheader : Extension $ExtensionName, type $ExtensionType.$Publisher added."
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
        [String]
        $ExtensionType,
        [Parameter(mandatory = $True)]
        [String]
        $Publisher,
        [Parameter(mandatory = $True)]
        [String]
        $TypeHandlerVersion,
        [Parameter(mandatory = $True)]
        [Hashtable]
        $InstallParameters
    )
    
    $vmlogheader = $(FormatVmIdentifier -VMObject $VMObject)
    
    if (!($PSCmdlet.ShouldProcess($vmlogheader, "Install/Update extension $ExtensionName, type $ExtensionType.$Publisher"))) {
        return $VMObject
    }

    Write-Host "$vmlogheader : Installing/Updating extension $ExtensionName, type $ExtensionType.$Publisher"
    
    try {
        $result = Set-AzVMExtension -ResourceGroupName $($VMObject.ResourceGroupName) `
                                    -VMName $($VMObject.Name) `
                                    -Name $ExtensionName `
                                    -ExtensionType $ExtensionType `
                                    -Publisher $Publisher `
                                    -TypeHandlerVersion $TypeHandlerVersion `
                                    @InstallParameters -ForceRerun $True

        if (!$result.IsSuccessStatusCode) {
            throw [VirtualMachineOperationFailed]::new($VMObject, "Failed to update extension. StatusCode = $($result.StatusCode). ReasonPhrase = $($result.ReasonPhrase)")
        }
    
        Write-Host "$vmlogheader : Successfully installed/updated extension $ExtensionName, type $ExtensionType.$Publisher"
        return $VMObject
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorMessage = ExtractCloudExceptionErrorMessage -ErrorRecord $_
        $errorCode = ExtractExceptionErrorCode -ErrorRecord $_
        if ($errorMessage -eq "Cannot modify extensions in the VM when the VM is not running") {
            throw [VirtualMachinePoweredDown]::new($VMObject, $_.Exception)
        }
        
        if ($errorCode -eq "ParentResourceNotFound") {
            throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
        } 
        
        if ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMObject.ResourceGroupName, $_.Exception)       
        } 
        
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to install/update extension $ExtensionName, type $ExtensionType.$Publisher", $_.Exception)
    }
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
        $scaleSetInstances = Get-AzVmssVm -ResourceGroupName $vmssResourceGroupName -VMScaleSetName $vmssName -InstanceView
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractExceptionErrorCode -ErrorRecord $_
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
    $unexpectedUpgradeExceptionCounter = 0
    $unexpectedUpgradeExceptionLimit = 5 
    Foreach ($scaleSetInstance in $scaleSetInstances) {
        if ($scaleSetInstance.InstanceView.Statuses.DisplayStatus -contains "VM deallocated") {
            Write-Host "VMSS instance $scaleSetInstanceName, $i of $instanceCount deallocated"
            Write-Host "Continuing ..."
            continue
        }

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
            $result = Update-AzVmssInstance -ResourceGroupName $vmssResourceGroupName `
                                            -VMScaleSetName $vmssName `
                                            -InstanceId $scaleSetInstance.InstanceId `
                                            -Confirm:$false
            if ($result.Status -ne "Succeeded") {
                Write-Host "$vmsslogheader : Failed to upgrade VMSS instance name $scaleSetInstanceName, $i of $instanceCount. $($result.Status)"

            } else {
                Write-Verbose "$vmsslogheader : Upgrade VMSS instance name $scaleSetInstanceName, $i of $instanceCount"
            }
        } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
            $errorCode = ExtractExceptionErrorCode -ErrorRecord $_
            if ($errorCode -eq "ResourceNotFound") {
                throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception)
            }
            if ($errorCode -eq "ResourceGroupNotFound") {
                throw [ResourceGroupDoesNotExist]::new($VMssObject.ResourceGroupName ,$_.Exception)  
            }
            if ($errorCode -eq "OperationNotAllowed") {
                Write-Host "$vmsslogheader : Unable to locate VMSS instance name $scaleSetInstanceName. Continuing ..."
                DisplayException -ErrorRecord $_
            } 
            if ($unexpectedUpgradeExceptionCounter -lt $unexpectedUpgradeExceptionLimit) {
                throw [VirtualMachineScaleSetUnknownException]::new($VMssObject, "Failed to upgrade VMSS instance name $scaleSetInstanceName", $_.Exception)
            }
            Write-Host "$vmsslogheader : Failed to upgrade VMSS instance name $scaleSetInstanceName, $i of $instanceCount. ErrorCode $errorCode. Continuing ..." 
            $unexpectedUpgradeExceptionCounter+=1
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
                                    -VirtualMachineScaleSet $VMssObject `
                                    -Confirm:$false
        if ($VMssObject.ProvisioningState -ne "Succeeded") {
            throw [VirtualMachineScaleSetOperationFailed]::new($VMssObject, "Failed to update VMSS")
        }
        Write-Host "$vmsslogheader : Successfully updated scale set with extension"
        return $VMssObject                           
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractExceptionErrorCode -ErrorRecord $_
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
	Assign User Assigned Managed Identity to VMSS
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
    
    if (!($PSCmdlet.ShouldProcess($vmsslogheader, "Assign User Assigned Managed Identity $userAssignedManagedIdentityName"))) {
        return $VMssObject
    }

    Write-Host "$vmsslogheader : Assigning User Assigned Managed Identity $userAssignedManagedIdentityName"
    try {
        $VMssObject = Update-AzVmss -VMScaleSetName $VMssObject.Name `
                                -ResourceGroupName  $VMssObject.ResourceGroupName `
                                -VirtualMachineScaleSet $VMssObject `
                                -IdentityType "UserAssigned" `
                                -IdentityID $UserAssignedManagedIdentityObject.Id `
                                -Confirm:$false
        if ($VMssObject.ProvisioningState -ne "Succeeded") {
            throw [VirtualMachineOperationScaleSetFailed]::new($VMssObject, "Failed to assign User Assigned Managed Identity $userAssignedManagedIdentityName")
        }
        
        Write-Host "$vmsslogheader : Successfully assigned User Assigned Managed Identity $userAssignedManagedIdentityName"
        return $VMssObject
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractExceptionErrorCode -ErrorRecord $_
        if ($errorCode -eq "FailedIdentityOperation") {
            throw [UserAssignedManagedIdentityDoesNotExist]::new($userAssignedManagedIdentityName, $_.Exception)
        }
        if ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($VMssObject.ResourceGroupName, $_.Exception)       
        } 
        if ($errorCode -eq "InvalidParameter") {
            throw [VirtualMachineScaleSetDoesNotExist]::new($VMssObject, $_.Exception) 
        } 
            
        throw [VirtualMachineScaleSetUnknownException]::new($VMssObject, "Failed to assign User Assigned Managed Identity $userAssignedManagedIdentityName", $_.Exception)
    }
}

function AssignVmUserManagedIdentity {
     <#
	.SYNOPSIS
	Assign User Assigned Managed Identity to VM
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
    
    if (!($PSCmdlet.ShouldProcess($vmlogheader, "Assign User Assigned Managed Identity $userAssignedManagedIdentityName"))) {
        return $VMObject
    }

    Write-Host "$vmlogheader : Assigning User Assigned Managed Identity $userAssignedManagedIdentityName"

    try {
        $result = Update-AzVM -VM $VMObject `
                                -ResourceGroupName $VMObject.ResourceGroupName `
                                -IdentityType "UserAssigned" `
                                -IdentityID $UserAssignedManagedIdentityObject.Id `
                                -Confirm:$false
    } catch [Microsoft.Azure.Commands.Compute.Common.ComputeCloudException] {
        $errorCode = ExtractExceptionErrorCode -ErrorRecord $_
        if ($errorCode -eq "FailedIdentityOperation") {
            throw [UserAssignedManagedIdentityDoesNotExist]::new($userAssignedManagedIdentityName, $_.Exception)
        }
        if ($errorCode -eq "ResourceGroupNotFound") {
            throw [ResourceGroupDoesNotExist]::new($($VMObject.ResourceGroupName), $_.Exception)       
        }
        if ($errorCode -eq "InvalidParameter") {
            throw [VirtualMachineDoesNotExist]::new($VMObject, $_.Exception)
        }
        
        throw [VirtualMachineUnknownException]::new($VMObject, "Failed to update VM with $userAssignedManagedIdentityName", $_.Exception)
    }

    if (!($result.IsSuccessStatusCode)) {
        throw [VirtualMachineOperationFailed]::new($VMObject, "Failed to assign User Assigned Managed Identity $userAssignedManagedIdentityName. StatusCode : $($result.StatusCode). ReasonPhrase : $($result.ReasonPhrase)")
    }
    
    Write-Host "$vmlogheader : Successfully assigned User Assigned Managed Identity $userAssignedManagedIdentityName"
    return $VMObject
}

function SetManagedIdentityRolesAma {
    <#
    .SYNOPSIS
    Set Roles to a User Assigned Managed Identity
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

    $roles = @("Virtual Machine Contributor", "Azure Connected Machine Resource Administrator", "Log Analytics Contributor")
    SetManagedIdentityRoles -ResourceGroupId $rgObj.ResourceId `
                            -UserAssignedManagedIdentity $UserAssignedManagedIdentityObject `
                            -Roles $roles
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
            Write-Verbose "Subscription : $SubscriptionId is already selected."
            $account
        }
        else {
            Write-Host "Current Subscription :"
            $account
            Write-Host "Changing to subscription : $SubscriptionId"
            Select-AzSubscription -SubscriptionId $SubscriptionId
        }
    }

    #script block
    Set-Variable -Name sb_nop_block_roles -Option Constant -Value { param($obj, $rg)} 
    Set-Variable -Name sb_nop_block_upgrade -Option Constant -Value { param($obj)}
    Set-Variable -Name sb_nop_block -Option Constant -Value { param($obj) $obj}
    $Rghashtable = @{}
    
    if (!$isAma) {
        #Cannot validate Workspace existence with WorkspaceId, WorkspaceKey parameters.
        Set-Variable -Name laInstallParameters -Option Constant -Value `
            @{"Settings" = @{"workspaceId" = $WorkspaceId; "stopOnMultipleConnections" = "true"};
              "ProtectedSettings" = @{"workspaceKey" = $WorkspaceKey}
             }
        Set-Variable -Name daInstallParameters -Option Constant -Value `
            @{"Settings" = @{"enableAMA" = "false"}}
        
        if ($ReInstall) {
            Set-Variable -Name sb_vm -Option Constant -Value { `
                param([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObj) `
                OnboardLaVmWithReInstall -VMObject $vmObj `
                                         -InstallParameters $laInstallParameters 
            }
        } else {
            Set-Variable -Name sb_vm -Option Constant -Value { `
                param([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObj) `
                OnboardLaVmWithoutReInstall -VMObject $vmObj `
                                            -InstallParameters $laInstallParameters
            }
        }
        
        Set-Variable -Name sb_vmss -Option Constant -Value { `
            param([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObj) `
            OnboardVMssExtension -VMssObject $vmssObj `
                             -ExtensionName $laDefaultExtensionName `
                             -ExtensionConstantProperties `
                                $laExtensionMap[$vmssObj.VirtualMachineProfile.StorageProfile.OsDisk.OsType.ToString()] `
                             -InstallParameters $laInstallParameters
        }
        
        Set-Variable -Name sb_da -Option Constant -Value { `
            param([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObj) `
            OnboardDaVm -VMObject $vmObj -InstallParameters $daInstallParameters
        }

        Set-Variable -Name sb_da_vmss -Option Constant -Value { `
            param([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObj) `
            OnboardVMssExtension -VMssObject $vmssObj `
                             -ExtensionName $daDefaultExtensionName `
                             -ExtensionConstantProperties `
                                $daExtensionConstantsMap[$vmssObj.VirtualMachineProfile.StorageProfile.OsDisk.OsType.ToString()] `
                             -InstallParameters $daInstallParameters
        }

        Set-Variable -Name sb_roles -Option Constant -Value $sb_nop_block_roles
    } else {
            try {
                Write-Verbose "Validating ($UserAssignedManagedIdentityResourceGroup, $UserAssignedManagedIdentityName)"
                Set-Variable -Name UserAssignedManagedIdentityObject -Option Constant -Value `
                                    $(Get-AzUserAssignedIdentity -Name $UserAssignedManagedIdentityName `
                                                                 -ResourceGroupName $UserAssignedManagedIdentityResourceGroup)
            } catch {
                $errorCode = ExtractExceptionErrorCode -ErrorRecord $_
                if ($errorCode -eq "ResourceNotFound") {
                    throw [UserAssignedManagedIdentityDoesNotExist]::new($UserAssignedManagedIdentityName, $_.Exception)
                }
                
                if ($errorCode -eq "ResourceGroupNotFound") {
                    throw [UserAssignedManagedIdentityResourceGroupDoesNotExist]::new($UserAssignedManagedIdentityResourceGroup, $_.Exception)
                }

                throw [UserAssignedManagedIdentityUnknownException]::new("($UserAssignedManagedIdentityResourceGroup) $UserAssignedManagedIdentityName : Unable to locate User Assigned Managed Identity.", $_.Exception)
            }
        
        Set-Variable -Name amaInstallParameters -Option Constant -Value `
            @{"Settings" = @{
                        'authentication' = @{ 
                            'managedIdentity' = @{
                                'identifier-name' = 'mi_res_id'
                                'identifier-value' = $($UserAssignedManagedIdentityObject.Id) 
                            }
                        }
                    }
            }
        Set-Variable -Name sb_vm -Option Constant -Value { `
            param([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObj) `
            OnboardVmiWithAmaVm -VMObject $vmObj -InstallParameters $amaInstallParameters
        }
        Set-Variable -Name sb_vmss -Option Constant -Value { `
            param([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObj) `
            OnboardVmiWithAmaVmss -VMssObject $vmssObj -InstallParameters $amaInstallParameters
        }
        
        if (!$ProcessAndDependencies) {
            Set-Variable -Name sb_da -Option Constant -Value $sb_nop_block
            Set-Variable -Name sb_da_vmss -Option Constant -Value $sb_nop_block
        } else {
            Set-Variable -Name daInstallParameters -Option Constant -Value @{"Settings" = @{"enableAMA" = "true"}}
            Set-Variable -Name sb_da -Option Constant -Value { `
                param([Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$vmObj) `
                OnboardDaVm -VMObject $vmObj -InstallParameters $daInstallParameters
            }

            Set-Variable -Name sb_da_vmss -Option Constant -Value { `
                param([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObj) `
                OnboardVMssExtension -VMssObject $vmssObj `
                                 -ExtensionName $daDefaultExtensionName `
                                 -ExtensionConstantProperties `
                                    $daExtensionConstantsMap[$vmssObj.VirtualMachineProfile.StorageProfile.OsDisk.OsType.ToString()] `
                                 -InstallParameters $daInstallParameters
            }
        }
    
        Set-Variable -Name sb_roles -Option Constant -Value { `
            param([String]$rgName) SetManagedIdentityRolesAma -ResourceGroupName $rgName
        }
    }

    if ($TriggerVmssManualVMUpdate) {
        Set-Variable -Name sb_upgrade -Option Constant -Value { `
            param([Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$vmssObj) `
            UpgradeVmssExtensionManualUpdateEnabled -VMssObject $vmssObj
        }
    } else {
        Set-Variable -Name sb_upgrade -Option Constant -Value $sb_nop_block_upgrade
    }

    if ($PolicyAssignmentName) {
        #this section is only for VMs
        Write-Host "Looking up Virtual Machines in policy assingment $PolicyAssignmentName"

        $policyAssignmentNameResources = @{}
        Get-AzPolicyState `
            -Filter "PolicyAssignmentName eq '$PolicyAssignmentName' and ResourceType eq 'Microsoft.Compute/virtualMachines'"
            | ForEach-Object {
                $policyAssignmentNameResources.Add($_.ResourceId, $True)
              }

        try {
            #Virtual Machines part of a VMSS will be skipped.
            Get-AzVM -ResourceGroupName $ResourceGroup -Name $Name
                | Where-Object {!($_.VirtualMachineScaleSet) -and $policyAssignmentNameResources.ContainsKey($_.Id)}
                | ForEach-Object {
                    $onboardingCounters.Total +=1 ;
                    PopulateRgHashTableVm -Rghashtable $Rghashtable -VMObject $_
                }
        } catch {} 
    } else {
        Write-Host "Getting list of VMs or VM Scale Sets matching specified criteria."
        try {
            Get-AzVM -ResourceGroupName $ResourceGroup -Name $Name
                | Where-Object {!($_.VirtualMachineScaleSet)}
                | ForEach-Object { 
                    $onboardingCounters.Total +=1 ; 
                    PopulateRgHashTableVm -Rghashtable $Rghashtable -VMObject $_
                }
        } catch {}

        try {
            #VMI does not support VMSS with flexible orchestration.
            Get-AzVmss -ResourceGroupName $ResourceGroup -Name $Name
                | Where-Object {$_.OrchestrationMode -ne 'Flexible'}
                | ForEach-Object {
                    $onboardingCounters.Total +=1 ; 
                    PopulateRgHashTableVmss -RgHashTable $Rghashtable -VMssObject $_
                }
        } catch {} 
    }

    $rgList = Sort-Object -InputObject $Rghashtable.Keys
    Write-Host "VM's and VMSS matching selection criteria :"
    $ManualUpgrade = 0
    Foreach ($rg in $rgList) {
        $rgTableObj  = $Rghashtable[$rg]
        $vmList = $rgTableObj.VirtualMachineList
        $vmssList = $rgTableObj.VirtualMachineScaleSetList
        Write-Host "" "ResourceGroup : $rg"

        if ($vmList.Length -gt 0) {
            $vmList = Sort-Object -Property Name -InputObject $vmList
            $vmList | ForEach-Object { Write-Host " $($_.Name)" }
            $rgTableObj.VirtualMachineList = $vmList
        }
        
        if ($vmssList.Length -gt 0) {
            $vmssList = Sort-Object -Property Name -InputObject $vmssList
            $vmssList | ForEach-Object { Write-Host " $($_.Name). Upgrade mode $($_.UpgradePolicy.Mode)"; `
                                         if ($_.UpgradePolicy.Mode -eq "Manual") {$ManualUpgrade+=1}
                                       }
            $rgTableObj.VirtualMachineScaleSetList = $vmssList
        }
    }

    if ($ManualUpgrade -gt 0 -and !$TriggerVmssManualVMUpdate) {
        Write-Host "Found VMSS with Manaual upgrade. Please provide 'TriggerVmssManualVMUpdate' to perform upgrade." 
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
                    Write-Host "Continuing to the next VM ..."
                } catch [VirtualMachineException] {
                    Write-Host "VM Exception :"
                    DisplayException -ErrorRecord $_
                    Write-Host "Continuing to the next VM ..."
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
                    Write-Host "Continuing to the next VMSS ..."
                } catch [VirtualMachineScaleSetException] {
                    Write-Host "VMSS Exception :"
                    DisplayException -ErrorRecord $_
                    Write-Host "Continuing to the next VMSS ..."
                }
            }
        } catch [ResourceGroupDoesNotExist] {
            Write-Host "Resource Group Exception :"
            DisplayException -ErrorRecord $_
            Write-Host "Continuing to the next Resource Group ..."
        }
    }
}
catch [FatalException] {
    Write-Host "Fatal Exception :"
    DisplayException -ErrorRecord $_
    Write-Host "Exiting ..."
    exit 2
}
catch {
    Write-Host "Unexpected Fatal Exception :"
    DisplayException -ErrorRecord $_
    Write-Host "Exiting ..."
    exit 3
}
finally {
    PrintSummaryMessage  $onboardingCounters
}
