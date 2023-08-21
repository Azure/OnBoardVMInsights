<#PSScriptInfo

.VERSION 1.9

.GUID 76a487ef-47bf-4537-8942-600a66a547b1

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
This script installs VM extensions for Log Analytics and Dependency Agent as needed for VM Insights.

.DESCRIPTION
This script installs or re-configures following on VM's and VM Scale Sets:
- Log Analytics VM Extension configured to supplied Log Analytics Workspace
- Dependency Agent VM Extension

Can be applied to:
- Subscription
- Resource Group in a Subscription
- Specific VM/VM Scale Set
- Compliance results of a policy for a VM or VM Extension

Script will show you list of VM's/VM Scale Sets that will apply to and let you confirm to continue.
Use -Approve switch to run without prompting, if all required parameters are provided.

If the extensions are already installed will not install again.
Use -ReInstall switch if you need to for example update the workspace.

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

.PARAMETER ResourceGroup
<Optional> Resource Group to which the VMs or VM Scale Sets belong to

.PARAMETER Name
<Optional> To install to a single VM/VM Scale Set

.PARAMETER PolicyAssignmentName
<Optional> Take the input VM's to operate on as the Compliance results from this Assignment
If specified will only take from this source.

.PARAMETER ReInstall
<Optional> If for a VM/VM Scale Set, the Log Analytics Agent is already configured for a different workspace, provide this parameter to switch to the new workspace

.PARAMETER TriggerVmssManualVMUpdate
<Optional> Set this flag to trigger update of VM instances in a scale set whose upgrade policy is set to Manual

.PARAMETER Approve
<Optional> Gives the approval for the installation to start with no confirmation prompt for the listed VM's/VM Scale Sets

.PARAMETER UserAssignedManagedIdentityResourceId
Azure Resource Id of UserAssignedManagedIdentity needed for Azure Monitor Agent

.EXAMPLE
.\Install-VMInsights.ps1 -WorkspaceRegion eastus -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup>
Install for all VM's in a Resource Group in a subscription

.EXAMPLE
.\Install-VMInsights.ps1 -WorkspaceRegion eastus -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup> -ReInstall
Specify to ReInstall extensions even if already installed, for example to update to a different workspace

.EXAMPLE
.\Install-VMInsights.ps1 -WorkspaceRegion eastus -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -PolicyAssignmentName a4f79f8ce891455198c08736 -ReInstall
Specify to use a PolicyAssignmentName for source, and to ReInstall (move to a new workspace)

.LINK
This script is posted to and further documented at the following location:
http://aka.ms/OnBoardVMInsights
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(mandatory = $true)][string]$SubscriptionId,
    [Parameter(mandatory = $false)][string]$ResourceGroup,
    [Parameter(mandatory = $false)][string]$Name,
    [Parameter(mandatory = $false)][string]$PolicyAssignmentName,
    [Parameter(mandatory = $false)][switch]$ReInstall,
    [Parameter(mandatory = $false)][switch]$TriggerVmssManualVMUpdate,
    [Parameter(mandatory = $false)][switch]$Approve,
    [Parameter(mandatory = $true, ParameterSetName = 'LogAnalyticsAgent')][string]$WorkspaceId,
    [Parameter(mandatory = $true, ParameterSetName = 'LogAnalyticsAgent')][string]$WorkspaceKey,
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

# Azure Monitoring Agent Extension constants
Set-Variable -Name amaExtensionMap -Option Constant -Value @{ "Windows" = "AzureMonitorWindowsAgent"; "Linux" = "AzureMonitorLinuxAgent" }
Set-Variable -Name amaExtensionVersionMap -Option Constant -Value @{ "Windows" = "1.16"; "Linux" = "1.16" }
Set-Variable -Name amaExtensionPublisher -Option Constant -Value "Microsoft.Azure.Monitor"
Set-Variable -Name amaExtensionName -Option Constant -Value "AzureMonitoringAgent"
Set-Variable -Name amaPublicSettings -Option Constant -Value @{'authentication' = @{
                        'managedIdentity' = @{
                        'identifier-name' = 'mi_res_id'
                        }
                      }
                    }
Set-Variable -Name amaProtectedSettings = @{}

# Dependency Agent Extension constants
$daExtensionMap = @{ "Windows" = "DependencyAgentWindows"; "Linux" = "DependencyAgentLinux" }
$daExtensionVersionMap = @{ "Windows" = "9.10"; "Linux" = "9.10" }
$daExtensionPublisher = "Microsoft.Azure.Monitoring.DependencyAgent"
$daExtensionName = "DAExtension"

# Data Collection Rule Association constants
$dcraExtensionType = "Microsoft.Insights/dataCollectionRules"
$dcraName = "/Microsoft.Insights/VMInsights-Dcr-Association"
$dcraExtensionVersion = "2019-11-01-preview"

#
# FUNCTIONS
#
function Get-VMExtension {
    <#
	.SYNOPSIS
	Return the VM extension of specified ExtensionType
	#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(mandatory = $true)][string]$vmResourceGroupName,
        [Parameter(mandatory = $true)][string]$ExtensionType
    )
    try {
        $vm = Get-AzureRmVM -Name $VMName -ResourceGroupName $vmResourceGroupName -DisplayHint Expand
    } catch {
        throw $_
    }
    $extensions = $vm.Extensions

    foreach ($extension in $extensions) {
        if ($ExtensionType -eq $extension.VirtualMachineExtensionType) {
            Write-Verbose("$VMName : Extension: $ExtensionType found on VM")
            $extension
            return
        }
    }
    Write-Verbose("$VMName : Extension: $ExtensionType not found on VM")
}

function Remove-VMssExtension {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(mandatory = $true)][string]$VMResourceGroupName,
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(mandatory = $true)][string]$ExtensionType,
        [Parameter(mandatory = $true)][string]$ExtensionName
    )

    try {
        $extension = Get-VMssExtension -VMName $VMName -VMResourceGroup $VMResourceGroupName -ExtensionType $ExtensionType
    }
    catch {
        $message = "$VMName : Failed to lookup $ExtensionType"
        $OnboardingStatus.Failed += $message
        throw $_
    }
    if ($extension) {
        try {
            $removeResult = Remove-AzVmssExtension -ResourceGroupName $VMResourceGroupName -VMName $VMName -Name $ExtensionName -Force
        }
        catch {
            Write-Output ("$VMName : Failed to remove extension : $ExtensionType")
            $OnboardingStatus.Failed += $message
            throw $_
        }
        if ($removeResult -and $removeResult.IsSuccessStatusCode) {
            $message = "$VMName : Successfully removed $ExtensionType"
            Write-Verbose($message)
        }
        else {
            $statusCode = $removeResult.StatusCode
            $errorMessage = $removeResult.ReasonPhrase
            $message = "$VMName : Failed to remove $ExtensionType. StatusCode = $statusCode. ErrorMessage = $errorMessage."
            $OnboardingStatus.Failed += $message
            throw $message
        }
    }
}

function Remove-VMExtension {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(mandatory = $true)][string]$VMResourceGroupName,
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(mandatory = $true)][string]$ExtensionType,
        [Parameter(mandatory = $true)][string]$ExtensionName
    )

    try {
        $extension = Get-VMExtension -VMName $VMName -VMResourceGroup $VMResourceGroupName -ExtensionType $ExtensionType
    } catch {
        $message = "$VMName : Failed to lookup extension $ExtensionType"
        $OnboardingStatus.Failed += $message
        throw $_
    }
    if ($extension) {
        try {
            $removeResult = Remove-AzureRmVMExtension -ResourceGroupName $VMResourceGroupName -VMName $VMName -Name $ExtensionName -Force
        } catch {
            $message = "$VMName : Failed to remove extension : $ExtensionType"
            $OnboardingStatus.Failed += $message
            throw $message
        }
        if ($removeResult) {
            if ($removeResult.IsSuccessStatusCode) {
                $message = "$VMName : Successfully removed $ExtensionType"
                Write-Verbose($message)
            }
            else {
                $statusCode = $removeResult.StatusCode
                $ErrorMessage = $removeResult.ReasonPhrase
                $message = "$VMName : Failed to remove $ExtensionType. StatusCode = $statusCode. ErrorMessage = $ErrorMessage."
                $OnboardingStatus.Failed += $message
                throw $message
            }
        } else {
            $message = "$VMName : Failed to remove $ExtensionType"
            $OnboardingStatus.Failed += $message
            throw $message
        }
    }
}

function Install-DCRAssociation {
    <#
	.SYNOPSIS
	Install DCRA Extension, handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)][string]$TargetResourceId,
        [Parameter(Mandatory = $true)][string]$TargetName,
        [Parameter(mandatory = $true)][string]$DcrResourceId
    )

    try {
        $dcrAssociationList = Get-AzDataCollectionRuleAssociation -TargetResourceId $TargetResourceId
        # A VM can be associated with multiple Data Collection Rule Associations
        foreach ($dcrAssociation in $dcrAssociationList) {
            if ($dcrAssociation.DataCollectionRuleId -eq $DcrResourceId) {
                $message = "$TargetName : Data Collection Rule Association already configured for this Data Collection Rule Id."
                Write-Output($message)
                return
            }
        }
    } catch {
        $message = "Exception : $TargetName : Failed to lookup the Data Collection Rule : $TargetResourceId"
        $OnboardingStatus.Failed += $message
        throw $_
    }

    #The Customer is responsible to uninstall the DCR Association themselves
    if ($PSCmdlet.ShouldProcess($TargetName, "Install Data Collection Rule Association")) {
        $dcrassociationName = "VM-Insights-$TargetName-Association"
        Write-Verbose("$TargetName : Deploying Data Collection Rule Association with name $dcrassociationName")
        try {
            $dcrassociation = New-AzDataCollectionRuleAssociation -TargetResourceId $TargetResourceId -AssociationName $dcrassociationName -RuleId $DcrResourceId
            if ($dcrassociation -is [ErrorResponseCommonV2Exception]) {
                #Tmp fix task:- 21191002
                throw
            }
        } catch {
           $message = "$TargetName : Failed to create Data Collection Rule Association for $TargetResourceId"
           $OnboardingStatus.Failed += $message
           throw $_
        }
    }
}

function Install-VMExtension {
    <#
	.SYNOPSIS
	Install VM Extension, handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(mandatory = $true)][string]$VMLocation,
        [Parameter(mandatory = $true)][string]$VMResourceGroupName,
        [Parameter(mandatory = $true)][string]$ExtensionType,
        [Parameter(mandatory = $true)][string]$ExtensionName,
        [Parameter(mandatory = $true)][string]$ExtensionPublisher,
        [Parameter(mandatory = $true)][string]$ExtensionVersion,
        [Parameter(mandatory = $false)][hashtable]$PublicSettings,
        [Parameter(mandatory = $false)][hashtable]$ProtectedSettings,
        [Parameter(mandatory = $false)][boolean]$ReInstall,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    # Use supplied name unless already deployed, use same name
    $extensionName = $ExtensionName

    try {
        $extension = Get-VMExtension -VMName $VMName -VMResourceGroup $VMResourceGroupName -ExtensionType $ExtensionType
        $extensionName = $extension.Name
    }
    catch {
        $message = "$VMName : Failed to lookup $ExtensionType"
        $OnboardingStatus.Failed += $message
        throw $_
    }
    if ($extension) {
        $extensionName = $extension.Name
        $message = "$VMName : $ExtensionType extension with name " + $extension.Name + " already installed. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings
        Write-Output ($message)
        if ($extension.Settings) {
            if ($mmaExtensionMap.Values -contains $ExtensionType) {
                if ($extension.Settings -and $extension.Settings.ToString().Contains($PublicSettings.workspaceId)) {
                    $message = "$VMName : Extension $ExtensionType already configured for this workspace. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings
                    Write-Output($message)
                    return
                } else {
                    if ($ReInstall -ne $true) {
                        $message = "$VMName : Extension $ExtensionType present, run with -ReInstall again to move to new workspace. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings
                        Write-Output ($message)
                        return
                    }
                }
            }

            if ($amaExtensionMap.Values -contains $ExtensionType) {
                if ($extension.Settings -and $extension.Settings.ToString().Contains($PublicSettings.authentication.managedIdentity.'identifier-value')) {
                    $message = "$VMName : Extension $ExtensionType already configured with this user assigned managed identity. Provisioning State: " + $extension.ProvisioningState + "`n" + $extension.Settings
                    Write-Output($message)
                    return
                }
            }

            if ($daExtensionMap.Values -contains $ExtensionType) {
                if ($extension.Settings -and $extension.Settings.ToString().Contains($PublicSettings.enableAMA)) {
                    $message = "$VMName : Extension $ExtensionType already configured with AMA enabled. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings
                    Write-Output($message)
                    return
                }
            }
        }

    }

    if ($PSCmdlet.ShouldProcess($VMName, "install extension $ExtensionType")) {

        $parameters = @{
            ResourceGroupName  = $VMResourceGroupName
            VMName             = $VMName
            Location           = $VMLocation
            Publisher          = $ExtensionPublisher
            ExtensionType      = $ExtensionType
            ExtensionName      = $extensionName
            TypeHandlerVersion = $ExtensionVersion
        }

        if ($PublicSettings) {
            $parameters.Add("Settings", $PublicSettings)
        }

        if ($ProtectedSettings) {
            $parameters.Add("ProtectedSettings", $ProtectedSettings)
        }

        if ($ExtensionType -eq "OmsAgentForLinux") {
            Write-Output("$VMName : ExtensionType: $ExtensionType does not support updating workspace. Uninstalling and Re-Installing")
            Remove-VMExtension -VMResourceGroupName $VMResourceGroupName `
                               -VMName $VMName `
                               -ExtensionType $ExtensionType `
                               -ExtensionName $ExtensionName
        }

        Write-Verbose("$VMName : Deploying/Updating $ExtensionType with name $extensionName")
        try {
            $result = Set-AzVMExtension @parameters
            if ($result -and $result.IsSuccessStatusCode) {
                Write-Output("$VMName : Successfully deployed/updated $ExtensionType")
            }
            else {
                throw $_
            }
        } catch {
            $message = "$VMName : Failed to deploy/update $ExtensionType"
            $OnboardingStatus.Failed += $message
            throw $_
        }
    }

}

function Get-VMssExtension {
    <#
	.SYNOPSIS
	Return the VM extension of specified ExtensionType
	#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $True)][System.Object]$VMss,
        [Parameter(mandatory = $true)][string]$ExtensionType
    )
    foreach ($extension in $VMss.VirtualMachineProfile.ExtensionProfile.Extensions) {
        if ($ExtensionType -eq $extension.Type) {
            $VMScaleSetName = $VMss.Name
            Write-Verbose("$VMScaleSetName : Extension: $ExtensionType found on VMSS")
            return
        }
    }
    Write-Verbose("$VMScaleSetName : Extension: $ExtensionType not found on VMSS")
}

function Install-VMssExtension {
    <#
	.SYNOPSIS
	Install VM Extension, handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $True)][string]$VMScaleSetName,
        [Parameter(Mandatory = $True)][string]$VMScaleSetResourceGroupName,
        [Parameter(Mandatory = $True)][string]$ExtensionType,
        [Parameter(Mandatory = $True)][string]$ExtensionName,
        [Parameter(Mandatory = $True)][string]$ExtensionPublisher,
        [Parameter(Mandatory = $True)][string]$ExtensionVersion,
        [Parameter(mandatory = $false)][hashtable]$PublicSettings,
        [Parameter(mandatory = $false)][hashtable]$ProtectedSettings,
        [Parameter(mandatory = $false)][boolean]$ReInstall = $false
    )

    # Use supplied name unless already deployed, use same name
    $extensionName = $ExtensionName
    try {
        $scalesetObject = Get-AzureRMVMSS -VMScaleSetName $VMScaleSetName -ResourceGroupName $VMScaleSetResourceGroupName
    } catch {
        $message = "$VMScaleSetName : Failed to lookup VMss in $VMScaleSetResourceGroupName"
        $OnboardingStatus.Failed += $message
        throw $_
    }
    try {
        $extension = Get-VMssExtension -VMss $scalesetObject -ExtensionType $ExtensionType
    } catch {
        $message = "$VMName : Failed to lookup $ExtensionType"
        $OnboardingStatus.Failed += $message
        throw $_
    }

    if ($extension) {
        Write-Verbose("$VMScaleSetName : $ExtensionType extension with name " + $extension.Name + " already installed. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings)
        $extensionName = $extension.Name
    }

    if ($PSCmdlet.ShouldProcess($VMScaleSetName, "install extension $ExtensionType")) {

        $parameters = @{
            VirtualMachineScaleSet  = $scalesetObject
            Name                    = $extensionName
            Publisher               = $ExtensionPublisher
            Type                    = $ExtensionType
            TypeHandlerVersion      = $ExtensionVersion
            AutoUpgradeMinorVersion = $true
        }

        if ($PublicSettings) {
            $parameters.Add("Setting", $PublicSettings)
        }

        if ($ProtectedSettings) {
            $parameters.Add("ProtectedSetting", $ProtectedSettings)
        }

        Write-Verbose("$VMScaleSetName : Adding $ExtensionType with name $extensionName")
        $scalesetObject = Add-AzureRmVmssExtension @parameters

        Write-Verbose("$VMScaleSetName Updating scale set with $ExtensionType extension")
        try {
            $result = Update-AzureRmVmss -VMScaleSetName $VMScaleSetName -ResourceGroupName $VMScaleSetResourceGroupName -VirtualMachineScaleSet $scalesetObject
        } catch {
            $message = "$VMScaleSetName : failed updating scale set with $ExtensionType extension"
            $OnboardingStatus.Failed += $message
            throw $_
        }
        if ($result -and $result.ProvisioningState -eq "Succeeded") {
            $message = "$VMScaleSetName : Successfully updated scale set with $ExtensionType extension"
            Write-Output($message)
            $OnboardingStatus.Succeeded += $message
        }
        else {
            $message = "$VMScaleSetName : failed updating scale set with $ExtensionType extension"
            $OnboardingStatus.Failed += $message
            throw $message
        }
    }
}

function Util-Assign-ManagedIdentity {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "VirtualMachine")][Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$VMObject,
        [Parameter(Mandatory = $true, ParameterSetName = "VirtualMachineScaleSet")][Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$VMssObject,
        [Parameter(Mandatory = $true, ParameterSetName = "VirtualMachineScaleSet")][switch]$isScaleset,
        [Parameter(Mandatory = $true)][string]$UserAssignedManagedIdentyId
    )
    if ($isScaleset) {
        $userAssignedIdentitiesList = $VMssObject.Identity.UserAssignedIdentities
    } else {
        $userAssignedIdentitiesList = $VMObject.Identity.UserAssignedIdentities
    }

    foreach ($userAssignDict in $userAssignedIdentitiesList) {
        if ($userAssignDict.Keys -eq $UserAssignedManagedIdentyId) {
            return $True
        }
    }

    return $False
}

function Assign-VmssManagedIdentity {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)][Microsoft.Azure.Commands.Compute.Automation.Models.PSVirtualMachineScaleSet]$VMssObject,
        [Parameter(mandatory = $true)][string]$UserAssignedManagedIdentityResourceGroup,
        [Parameter(mandatory = $true)][string]$UserAssignedManagedIdentityName
    )

    #Vmss have been noted to have non-standard resourceIDs - bug
    if ($VMssObject.Id -match "/subscriptions/([^/]+)/") {
        $vmssSubscriptionId = $matches[1]
    } else {
        $message = $VMssObject.Name + ": Invalid Azure Resource Id"
        throw $message
    }

    try {
        $userAssignedIdentityObject = Get-AzUserAssignedIdentity -ResourceGroupName $UserAssignedManagedIdentityResourceGroup -Name $UserAssignedManagedIdentityName
        if (!$userAssignedIdentityObject) {
            throw
        }
    } catch {
        $message = "Failed to lookup managed identity $UserAssignedManagedIdentityName"
        $OnboardingStatus.Failed += $message
        throw $_
    }

    try {
        $statusResult = Get-AzVmss -ResourceGroupName $VMssObject.ResourceGroupName -Name $VMssObject.Name
    } catch {
        $message = $VMssObject.Name + " : Failed to lookup VMss in " + $VMssObject.ResourceGroupName
        $OnboardingStatus.Failed += $message
        throw $_
    }
    if ($statusResult -and ($statusResult.Identity.Type -eq "UserAssigned") -and (Util-Assign-ManagedIdentity -isScaleset -VMssObject $statusResult -UserAssignedManagedIdentyId $userAssignedIdentityObject.Id)) {
        $message = $VMssObject.Name + ": Already assigned with user managed identity : $UserAssignedManagedIdentityName"
        Write-Verbose($message)
    } else {
        try {
            $updateResult = Update-AzVMss -ResourceGroupName $VMssObject.ResourceGroupName `
                                        -VMScaleSetName $VMssObject.Name `
                                        -VirtualMachineScaleSet $VMssObject `
                                        -IdentityType "UserAssigned" `
                                        -IdentityID $userAssignedIdentityObject.Id
        } catch {
            $message = "Exception : " + $VMssObject.Name + ": Failed to assign user managed identity : $UserAssignedManagedIdentityName"
            Write-Output ($message)
            $OnboardingStatus.Failed += $message
            throw $_
        }
        if ($updateResult -and $updateResult.IsSuccessStatusCode) {
            $message = $VMssObject.Name + ": Successfully assigned user managed identity : $UserAssignedManagedIdentityName"
            Write-Output($message)
        }
        else {
            $updateCode = $updateResult.StatusCode
            $errorMessage = $updateResult.ReasonPhrase
            $message = $VMssObject.Name + ": Failed to assign managed identity : " + $UserAssignedManagedIdentityName + ". StatusCode = $updateCode. ErrorMessage = $errorMessage."
            Write-Output($message)
            $OnboardingStatus.Failed += $message
        }
    }

    ##Assign roles to the provided managed identity.
    $targetScope = "/subscriptions/" + $vmssSubscriptionId + "/resourceGroups/" + $VMssObject.ResourceGroupName
    $roleDefinitionList = @("Virtual Machine Contributor", "Azure Connected Machine Resource Administrator", "Log Analytics Contributor")
    foreach ($role in $roleDefinitionList) {
        $roleAssignmentFound = Get-AzRoleAssignment -ObjectId $userAssignedIdentityObject.principalId -RoleDefinitionName $role -Scope $targetScope
        if (!$roleAssignmentFound) {
            Write-Verbose("Scope $targetScope : assigning role $role")
            try {
                $result = New-AzRoleAssignment -ObjectId $userAssignedIdentityObject.principalId -RoleDefinitionName $role -Scope $targetScope
                Write-Output ("Scope $targetScope : role assignment for $UserAssignedManagedIdentityName with $role succeeded")
            }
            catch {
                $message = "Scope $targetScope : role assignment with $role failed"
                throw $message
            }
        } else {
            Write-Verbose("Scope $targetScope : role $role already set")
        }
    }

    ##Assign Managed identity to Azure Monitoring Agent
    $amaPublicSettings.authentication.managedIdentity.'identifier-value' = $userAssignedIdentityObject.Id
}

function Assign-VmManagedIdentity {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)][Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine]$VMObject,
        [Parameter(mandatory = $true)][string]$UserAssignedManagedIdentityResourceGroup,
        [Parameter(mandatory = $true)][string]$UserAssignedManagedIdentityName
    )

    if ($VMObject.Id -match "/subscriptions/([^/]+)/") {
        $vmSubscriptionId = $matches[1]
    } else {
        $message = $VMObject.Name + ": Invalid Azure Resource Id"
        throw $message
    }

    try {
        $userAssignedIdentityObject = Get-AzUserAssignedIdentity -ResourceGroupName $UserAssignedManagedIdentityResourceGroup -Name $UserAssignedManagedIdentityName
        if (!$userAssignedIdentityObject) {
            throw
        }
    } catch {
        $message = "Failed to lookup managed identity $UserAssignedManagedIdentityName"
        $OnboardingStatus.Failed += $message
        throw $_
    }

    try {
        $statusResult = Get-AzVM -ResourceGroupName $VMObject.ResourceGroupName -Name $VMObject.Name
    } catch {
        $message = $VMObject.Name + " : Failed to lookup VM in " + $VMObject.ResourceGroupName
        $OnboardingStatus.Failed += $message
        throw $_
    }
    if ($statusResult -and ($statusResult.Identity.Type -eq "UserAssigned") -and (Util-Assign-ManagedIdentity -VMObject $statusResult -UserAssignedManagedIdentyId $userAssignedIdentityObject.Id)) {
        $message = $VMObject.Name + " : Already assigned with managed identity : " + $UserAssignedManagedIdentityName
        Write-Output($message)
    } else {
        try {
            $updateResult = Update-AzVM -ResourceGroupName $VMObject.ResourceGroupName `
                                        -VM $VMObject `
                                        -IdentityType "UserAssigned" `
                                        -IdentityID $userAssignedIdentityObject.Id
        } catch {
            $message = $VMObject.Name + ": Failed to assign user managed identity = " + $UserAssignedManagedIdentityName
            $OnboardingStatus.Failed += $message
            throw $_
        }
        if ($updateResult -and $updateResult.IsSuccessStatusCode) {
            $message = $VMObject.Name + ": Successfully assigned managed identity : " + $UserAssignedManagedIdentityName
            Write-Output($message)
        }
        else {
            $statusCode = $updateResult.StatusCode
            $ErrorMessage = $updateResult.ReasonPhrase
            $message = $VMObject.Name + ": Failed to assign managed identity : " + $UserAssignedManagedIdentityName + ". StatusCode = $statusCode. ErrorMessage = $ErrorMessage."
            $OnboardingStatus.Failed += $message
            throw $message
        }
    }

    ##Assign roles to the provided managed identity.
    $targetScope = "/subscriptions/" + $vmSubscriptionId + "/resourceGroups/" + $VM.ResourceGroupName
    $roleDefinitionList = @("Virtual Machine Contributor", "Azure Connected Machine Resource Administrator", "Log Analytics Contributor")
    foreach ($role in $roleDefinitionList) {
        $roleAssignmentFound = Get-AzRoleAssignment -ObjectId $userAssignedIdentityObject.principalId -RoleDefinitionName $role -Scope $targetScope
        if (!$roleAssignmentFound) {
            Write-Verbose ("Scope $targetScope : assigning role $role")
            try {
                $result = New-AzRoleAssignment -ObjectId $userAssignedIdentityObject.principalId -RoleDefinitionName $role -Scope $targetScope
                Write-Output ("Scope $targetScope : role assignment for $UserAssignedManagedIdentityName with $role succeeded")
            }
            catch {
                $message = "Scope $targetScope : role assignment with $role failed"
                $OnboardingStatus.Failed += $message
                throw $_
            }
        } else {
            Write-Verbose ("Scope $targetScope : role $role found")
        }
    }

    ##Assign Managed identity to Azure Monitoring Agent
    $amaPublicSettings.authentication.managedIdentity.'identifier-value' = $userAssignedIdentityObject.Id
}

function Display-Exception {
    try {
        try { "ExceptionClass = $($_.Exception.GetType().Name)" | Write-Output } catch { }
        if ($OnboardingStatus.Failed.Length -ne 0) {
            try { "ExceptionMessage:`r`n$($OnboardingStatus.Failed[-1])`r`n" | Write-Output } catch { }
        }
        try { "ExceptionDetailedMessage:`r`n$($_.Exception.Message)`r`n" | Write-Output } catch { }
        try { "StackTrace:`r`n$($_.Exception.StackTrace)`r`n" | Write-Output } catch { }
        try { "ScriptStackTrace:`r`n$($_.ScriptStackTrace)`r`n" | Write-Output } catch { }
        try { "Exception.HResult = 0x{0,0:x8}" -f $_.Exception.HResult | Write-Output } catch { }
    }
    catch {
        #silently ignore
    }
}

#
# Main Script
#

#
# First make sure authenticed and Select the subscription supplied
#
$account = Get-AzureRmContext
if ($null -eq $account.Account) {
    Write-Output("Account Context not found, please login")
    Login-AzureRmAccount -subscriptionid $SubscriptionId
}
else {
    if ($account.Subscription.Id -eq $SubscriptionId) {
        Write-Verbose("Subscription: $SubscriptionId is already selected.")
        $account
    }
    else {
        Write-Output("Current Subscription:")

        $account
        Write-Output("Changing to subscription: $SubscriptionId")
        Select-AzureRmSubscription -SubscriptionId $SubscriptionId
    }
}

$VMs = @()
$ScaleSets = @()
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

$mmaPublicSettings = @{"workspaceId" = $WorkspaceId; "stopOnMultipleConnections" = "true"}
$mmaProtectedSettings = @{"workspaceKey" = $WorkspaceKey}
$daPublicSettings = @{}

if ($PolicyAssignmentName) {
    Write-Output("Getting list of VM's from PolicyAssignmentName: " + $PolicyAssignmentName)
    $complianceResults = Get-AzureRmPolicyState -PolicyAssignmentName $PolicyAssignmentName

    foreach ($result in $complianceResults) {
        Write-Verbose($result.ResourceId)
        Write-Verbose($result.ResourceType)
        if ($result.SubscriptionId -ne $SubscriptionId) {
            Write-Output("VM is not in same subscription, this scenario is not currently supported. Skipping this VM.")
        }

        $vmName = $result.ResourceId.split('/')[8]
        $vmResourceGroup = $result.ResourceId.split('/')[4]

        # Skip if ResourceGroup or Name provided, but does not match
        if ($ResourceGroup -and $ResourceGroup -ne $vmResourceGroup) { continue }
        if ($Name -and $Name -ne $vmName) { continue }

        $vm = Get-AzureRmVM -Name $vmName -ResourceGroupName $vmResourceGroup
        $vmStatus = Get-AzureRmVM -Status -Name $vmName -ResourceGroupName $vmResourceGroup

        # fix to have same property as VM that is retrieved without Name
        $vm | Add-Member -NotePropertyName PowerState -NotePropertyValue $vmStatus.Statuses[1].DisplayStatus

        $VMs = @($VMs) + $vm
    }
}

if (! $PolicyAssignmentName) {
    Write-Output("Getting list of VM's or VM ScaleSets matching criteria specified")
    if (!$ResourceGroup -and !$Name) {
        # If ResourceGroup value is not passed - get all VMs under given SubscriptionId
        $VMs = Get-AzureRmVM -Status
        $ScaleSets = Get-AzureRmVmss
        $VMs = @($VMs) + $ScaleSets
    }
    else {
        # If ResourceGroup value is passed - select all VMs under given ResourceGroupName
        $VMs = Get-AzureRmVM -ResourceGroupName $ResourceGroup -Status
        if ($Name) {
            $VMs = $VMs | Where-Object {$_.Name -like $Name}
        }
        $ScaleSets = Get-AzureRmVmss -ResourceGroupName $ResourceGroup
        if ($Name) {
            $ScaleSets = $ScaleSets | Where-Object {$_.Name -like $Name}
        }
        $VMs = @($VMs) + $ScaleSets
    }
}

Write-Output("`nVM's or VM ScaleSets matching criteria:`n")
$VMS | ForEach-Object { Write-Output ($_.Name + " " + $_.PowerState) }

# Validate customer wants to continue
$monitoringAgent = if ($DcrResourceId) {"AzureMonitoringAgent"} else {"LogAnalyticsAgent"}
$infoMessage = "`For above $($VMS.Count) VM's or VM Scale Sets, this operation will install $monitoringAgent"
if (!$DcrResourceId -or ($DcrResourceId -and $ProcessAndDependencies)) {
    $infoMessage+=" and Dependency Agent extension"
}
Write-Output($infoMessage)
Write-Output("VM's in a non-running state will be skipped.")
if ($Approve -eq $true -or !$PSCmdlet.ShouldProcess("All") -or $PSCmdlet.ShouldContinue("Continue?", "")) {
    Write-Output ""
}
else {
    Write-Output "You selected No - exiting"
    return
}

#
# Loop through each VM/VM Scale set, as appropriate handle installing VM Extensions
#
Foreach ($vm in $VMs) {
    try {
        # set as variabels so easier to use in output strings
        $vmName = $vm.Name
        $vmLocation = $vm.Location
        $vmResourceGroupName = $vm.ResourceGroupName
        $vmId = $vm.Id
        #
        # Find OS Type
        #
        if ($vm.type -eq 'Microsoft.Compute/virtualMachineScaleSets') {
            $isScaleset = $true
            $scalesetVMs = @()
            try {
                $scalesetVMs = Get-AzureRmVMssVM -ResourceGroupName $vmResourceGroupName -VMScaleSetName $vmName
            } catch {
                Write-Output ("Exception : $vmName : Failed to lookup constituent VMs")
                throw $_
            }
            if ($scalesetVMs.length -gt 0) {
                if ($scalesetVMs[0]) {
                    $osType = $scalesetVMs[0].storageprofile.osdisk.ostype
                }
            }
        }
        else {
            $isScaleset = $false
            $osType = $vm.StorageProfile.OsDisk.OsType
        }

        #
        # Map to correct extension for OS type
        #
        if ($DcrResourceId) {
            $maExt = $amaExtensionMap.($osType.ToString())
            $maExtVersion = $amaExtensionVersionMap.($osType.ToString())
            $maExtensionPublisher = $amaExtensionPublisher
            $maExtensionName = $amaExtensionName
            $maPublicSettings = $amaPublicSettings
            $maProtectedSettings = $amaProtectedSettings
        } else {
            $maExt = $mmaExtensionMap.($osType.ToString())
            $maExtVersion = $mmaExtensionVersionMap.($osType.ToString())
            $maExtensionPublisher = $mmaExtensionPublisher
            $maExtensionName = $mmaExtensionName
            $maPublicSettings = $mmaPublicSettings
            $maProtectedSettings = $mmaProtectedSettings
        }

        if (! $maExt) {
            Write-Warning("$vmName : has an unsupported OS: $osType")
            continue
        }

        $daExt = $daExtensionMap.($osType.ToString())
        if ($DcrResourceId -and $ProcessAndDependencies) {
            $daPublicSettings = @{"enableAMA" = "true"}
            $daExtVersion = $daExtensionVersionMap.($osType.ToString())
        }

        Write-Verbose("Deployment settings: ")
        Write-Verbose("ResourceGroup: $vmResourceGroupName")
        Write-Verbose("VM: $vmName")
        Write-Verbose("Location: $vmLocation")
        Write-Verbose("OS Type: $ext")
        Write-Verbose("Dependency Agent: $daExt, HandlerVersion: $daExtVersion")
        Write-Verbose("Monitoring Agent: $mmaExt, HandlerVersion: $maExtVersion")

        if ($DcrResourceId) {
            if ($isScaleset) {
                Assign-VmssManagedIdentity -VMssObject $vm `
                    -UserAssignedManagedIdentityResourceGroup $UserAssignedManagedIdentityResourceGroup `
                    -UserAssignedManagedIdentityName $UserAssignedManagedIdentityName
            } else {
                Assign-VmManagedIdentity -VMObject $vm `
                    -UserAssignedManagedIdentityResourceGroup $UserAssignedManagedIdentityResourceGroup `
                    -UserAssignedManagedIdentityName $UserAssignedManagedIdentityName
            }
        }

        if ($isScaleset) {
            Install-VMssExtension `
                -VMScaleSetName $vmName `
                -VMScaleSetResourceGroupName $vmResourceGroupName `
                -ExtensionType $maExt `
                -ExtensionName $maExtensionName `
                -ExtensionPublisher $maExtensionPublisher `
                -ExtensionVersion $maExtVersion `
                -PublicSettings $maPublicSettings `
                -ProtectedSettings $maProtectedSettings `
                -ReInstall $ReInstall `

            if (!$DcrResourceId -or ($DcrResourceId -and $ProcessAndDependencies)) {
                Install-VMssExtension `
                    -VMScaleSetName $vmName `
                    -VMScaleSetResourceGroupName $vmResourceGroupName `
                    -ExtensionType $daExt `
                    -ExtensionName $daExt `
                    -ExtensionPublisher $daExtensionPublisher `
                    -ExtensionVersion $daextVersion `
                    -PublicSettings $daPublicSettings `
                    -ReInstall $ReInstall `
            }

            $scalesetObject = Get-AzureRMVMSS -VMScaleSetName $vmName -ResourceGroupName $vmResourceGroupName
            if ($scalesetObject.UpgradePolicy.mode -eq 'Manual') {
                if ($TriggerVmssManualVMUpdate -eq $true) {

                    Write-Output("$vmName : Upgrading scale set instances since the upgrade policy is set to Manual")
                    $scaleSetInstances = @{}
                    $scaleSetInstances = Get-AzureRMVMSSvm -ResourceGroupName $vmResourceGroupName -VMScaleSetName $vmName -InstanceView
                    $i = 0
                    $instanceCount = $scaleSetInstances.Length
                    Foreach ($scaleSetInstance in $scaleSetInstances) {
                        $i++
                        Write-Output("$vmName : Updating instance " + $scaleSetInstance.Name + " $i of $instanceCount")
                        Update-AzureRmVmssInstance -ResourceGroupName $vmResourceGroupName -VMScaleSetName $vmName -InstanceId $scaleSetInstance.InstanceId
                    }
                    Write-Output("$vmName All scale set instances upgraded")
                }
                else {
                    $message = "$vmName : has UpgradePolicy of Manual. Please trigger upgrade of VM Scale Set or call with -TriggerVmssManualVMUpdate"
                    Write-Warning($message)
                    $OnboardingStatus.VMScaleSetNeedsUpdate += $message
                }
            }
        }
        #
        # Handle VM's
        #
        else {
            if ("VM Running" -ne $vm.PowerState) {
                $message = "$vmName : has a PowerState " + $vm.PowerState + " Skipping"
                Write-Output($message)
                $OnboardingStatus.NotRunning += $message
                continue
            }

            Install-VMExtension `
                -VMName $vmName `
                -VMLocation $vmLocation `
                -VMResourceGroupName $vmResourceGroupName `
                -ExtensionType $maExt `
                -ExtensionName $maExt `
                -ExtensionPublisher $maExtensionPublisher `
                -ExtensionVersion $maExtVersion `
                -PublicSettings $maPublicSettings `
                -ProtectedSettings $maProtectedSettings `
                -ReInstall $ReInstall `
                -OnboardingStatus $OnboardingStatus

            if (!$DcrResourceId -or ($DcrResourceId -and $ProcessAndDependencies)) {
                Install-VMExtension `
                    -VMName $vmName `
                    -VMLocation $vmLocation `
                    -VMResourceGroupName $vmResourceGroupName `
                    -ExtensionType $daExt `
                    -ExtensionName $daExt `
                    -ExtensionPublisher $daExtensionPublisher `
                    -ExtensionVersion $daextVersion `
                    -PublicSettings $daPublicSettings `
                    -ReInstall $ReInstall `
                    -OnboardingStatus $OnboardingStatus
            }
        }
        Install-DCRAssociation `
            -TargetResourceId $vmId `
            -TargetName $vmName `
            -DcrResourceId $DcrResourceId `
        #reached this point - indicates all previous deployments succeeded
        $message = "$vmName : Successfully onboarded VMInsights"
        Write-Output ($message)
        $OnboardingStatus.Succeeded += $message
    }
    catch {
        Display-Exception $_
    }
}


Write-Output("`nSummary:")
Write-Output("`nSucceeded: (" + $OnboardingStatus.Succeeded.Count + ")")
$OnboardingStatus.Succeeded | ForEach-Object { Write-Output ($_) }
Write-Output("`nNot running - start VM to configure: (" + $OnboardingStatus.NotRunning.Count + ")")
$OnboardingStatus.NotRunning  | ForEach-Object { Write-Output ($_) }
Write-Output("`nVM Scale Set needs update: (" + $OnboardingStatus.VMScaleSetNeedsUpdate.Count + ")")
$OnboardingStatus.VMScaleSetNeedsUpdate  | ForEach-Object { Write-Output ($_) }
Write-Output("`nFailed: (" + $OnboardingStatus.Failed.Count + ")")
$OnboardingStatus.Failed | ForEach-Object { Write-Output ($_) }
