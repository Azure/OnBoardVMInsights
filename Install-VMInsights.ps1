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
This script installs VM extensions for Log Analytics/Azure Monitoring Agent(AMA) and Dependency Agent as needed for VM Insights. If the customer
onboarded AMA a Data Collection Rule(DCR) and User Assigned Identity (UAMI) is also associated with the VM's and VM Scal Sets.

.DESCRIPTION
This script installs or re-configures following on VM's and VM Scale Sets:
- Log Analytics VM Extension configured to supplied Log Analytics Workspace
- Azure Monitor Agent and assigns Data Collection Rule and User Assigned Identity
- Dependency Agent VM Extension

Can be applied to:
- Subscription
- Resource Group in a Subscription
- Specific VM/VM Scale Set
- Compliance results of a policy for a VM or VM Extension

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

.PARAMETER Whatif
<Optional> See what would happen in terms of installs.
If extension is already installed will show what workspace is currently configured, and status of the VM extension

.PARAMETER Confirm
<Optional> Confirm every action

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

.EXAMPLE
.\Install-VMInsights.ps1 -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup>  -DcrResourceId <DataCollectionRuleResourceId> -UserAssignedManagedIdentityName <UserAssignedIdentityName> -ProcessAndDependencies -UserAssignedManagedIdentityResourceGroup <UserAssignedIdentityResourceGroup>

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

#
# FUNCTIONS
#
function Set-FailureMessage {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(mandatory = $true)][string]$Message
    )
    $OnboardingStatus.Failed += $Message
}

function Remove-VMExtension {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)][Object]$VMObject,
        [Parameter(mandatory = $true)][string]$ExtensionType,
        [Parameter(mandatory = $true)][string]$ExtensionName
    )

    if (!$VMObject) {
        return
    }

    $vmResourceGroupName = $VMObject.ResourceGroupName
    $vmName = $VMObject.VMName

    try {
        $extension = Get-AzVMExtension -VMName $vmName -VMResourceGroup $vmResourceGroupName -ExtensionType $ExtensionType
    } catch {
        Set-FailureMessage "$vmName : Failed to lookup extension $ExtensionType"
        throw $_
    }

    if (!$extension) {
        $message = $vmName + " : " +  $ExtensionName + " with name : " + $ExtensionName + " does not exist"
        Write-Verbose ($message)
        return
    }

    try {
        $removeResult = Remove-AzVMExtension -ResourceGroupName $vmResourceGroupName -VMName $vmName -Name $ExtensionName -Force
    } catch {
        Set-FailureMessage "$vmName : Failed to remove extension : $ExtensionType"
        throw $_
    }

    if (-not $removeResult) {
        Set-FailureMessage "$vmName : Failed to remove $ExtensionType."
        throw
    } elseif (!$removeResult.IsSuccessStatusCode) {
        $statusCode = $removeResult.StatusCode
        $ErrorMessage = $removeResult.ReasonPhrase
        Set-FailureMessage "$vmName : Failed to remove $ExtensionType. StatusCode = $statusCode. ErrorMessage = $ErrorMessage."
        throw
    } else {
        $message = "$vmName : Successfully removed $ExtensionType"
        Write-Verbose($message)
    }
}

function New-DCRAssociation {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)][Object]$VMObject,
        [Parameter(mandatory = $true)][string]$DcrResourceId
    )

    if (!$VMObject -or !$DcrResourceId) {
        return
    }

    $vmName = $VMObject.Name
    $vmId = $VMObject.Id

    try {
        $dcrAssociationList = Get-AzDataCollectionRuleAssociation -TargetResourceId $vmId
    } catch {
        Set-FailureMessage "Exception : $vmName : Failed to lookup the Data Collection Rule : $DcrResourceId"
        throw $_
    }

    # A VM may have zero or more Data Collection Rule Associations
    foreach ($dcrAssociation in $dcrAssociationList) {
        if ($dcrAssociation.DataCollectionRuleId -eq $DcrResourceId) {
            $message = "$TargetName : Data Collection Rule already associated."
            Write-Output($message)
            return
        }
    }

    #The Customer is responsible to uninstall the DCR Association themselves
    if ($PSCmdlet.ShouldProcess($TargetName, "Install Data Collection Rule Association")) {
        $dcrassociationName = "VM-Insights-$TargetName-Association"
        Write-Verbose("$TargetName : Deploying Data Collection Rule Association with name $dcrassociationName")
        try {
            $dcrassociation = New-AzDataCollectionRuleAssociation -TargetResourceId $TargetResourceId -AssociationName $dcrassociationName -RuleId $DcrResourceId
            if (!$dcrassociation -or $dcrassociation -is [ErrorResponseCommonV2Exception]) {
                #Tmp fix task:- 21191002
                throw
            }
        } catch {
            Set-FailureMessage "$TargetName : Failed to create Data Collection Rule Association for $TargetResourceId"
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
        [Parameter(Mandatory = $true)][Object]$VMObject,
        [Parameter(mandatory = $true)][string]$ExtensionType,
        [Parameter(mandatory = $true)][string]$ExtensionName,
        [Parameter(mandatory = $true)][string]$ExtensionPublisher,
        [Parameter(mandatory = $true)][string]$ExtensionVersion,
        [Parameter(mandatory = $false)][hashtable]$PublicSettings,
        [Parameter(mandatory = $false)][hashtable]$ProtectedSettings,
        [Parameter(mandatory = $false)][boolean]$ReInstall,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmName = $VMObject.Name
    $vmLocation = $VMObject.Location
    $vmResourceGroupName = $VMObject.ResourceGroupName

    # Use supplied name unless already deployed, use same name
    $extensionName = $ExtensionName

    try {
        $extension = Get-AzVMExtension -VMName $vmName -VMResourceGroup $vmResourceGroupName -ExtensionType $ExtensionType
        $extensionName = $extension.Name
    }
    catch {
        Set-FailureMessage "$vmName : Failed to lookup $ExtensionType"
        throw $_
    }

    if ($extension) {
        $extensionName = $extension.Name
        $message = "$vmName : $ExtensionType extension with name " + $extension.Name + " already installed. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings
        Write-Output ($message)
        if ($extension.Settings) {
            if ($mmaExtensionMap.Values -contains $ExtensionType) {
                if ($extension.Settings.ToString().Contains($PublicSettings.workspaceId)) {
                    $message = "$vmName : Extension $ExtensionType already configured for this workspace. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings
                    Write-Output($message)
                    return
                } else {
                    if ($ReInstall -ne $true) {
                        $message = "$vmName : Extension $ExtensionType present, run with -ReInstall again to move to new workspace. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings
                        Write-Output ($message)
                        return
                    }
                }
            }

            if ($amaExtensionMap.Values -contains $ExtensionType) {
                if ($extension.Settings.ToString().Contains($PublicSettings.authentication.managedIdentity.'identifier-value')) {
                    $message = "$vmName : Extension $ExtensionType already configured with this user assigned managed identity. Provisioning State: " + $extension.ProvisioningState + "`n" + $extension.Settings
                    Write-Output($message)
                    return
                }
            }

            if ($daExtensionMap.Values -contains $ExtensionType) {
                if ($extension.Settings.ToString().Contains($PublicSettings.enableAMA)) {
                    $message = "$vmName : Extension $ExtensionType already configured with AMA enabled. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings
                    Write-Output($message)
                    return
                }
            }
        }
    }

    if ($PSCmdlet.ShouldProcess($VMName, "install extension $ExtensionType")) {

        $parameters = @{
            ResourceGroupName  = $vmResourceGroupName
            VMName             = $vmName
            Location           = $vmLocation
            Publisher          = $ExtensionPublisher
            ExtensionType      = $ExtensionType
            ExtensionName      = $extensionName
            TypeHandlerVersion = $ExtensionVersion
        }

        if ($PublicSettings) {
            $parameters.Add("Settings", $PublicSettings)
        }

        if ($ProtectedSettin) {
            $parameters.Add("ProtectedSettings", $ProtectedSettings)
        }

        if ($ExtensionType -eq "OmsAgentForLinux") {
            Write-Output("$vmName : ExtensionType: $ExtensionType does not support updating workspace. Uninstalling and Re-Installing")
            Remove-VMExtension -VMObject $VMObject `
                               -ExtensionType $ExtensionType `
                               -ExtensionName $ExtensionName
        }

        Write-Verbose("$vmName : Deploying/Updating $ExtensionType with name $extensionName")
        try {
            $result = Set-AzVMExtension @parameters
            if ((-not $result) -or !$result.IsSuccessStatusCode) {
                throw
            }
            else {
                Write-Output("$vmName : Successfully deployed/updated $ExtensionType")
            }
        } catch {
            Set-FailureMessage "$vmName : Failed to deploy/update $ExtensionType"
            throw $_
        }
    }
}

function Install-VMssExtension {
    <#
	.SYNOPSIS
	Install VMss Extension, handling if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)][Object]$VMssObject,
        [Parameter(Mandatory = $True)][string]$ExtensionType,
        [Parameter(Mandatory = $True)][string]$ExtensionName,
        [Parameter(Mandatory = $True)][string]$ExtensionPublisher,
        [Parameter(Mandatory = $True)][string]$ExtensionVersion,
        [Parameter(mandatory = $false)][hashtable]$PublicSettings,
        [Parameter(mandatory = $false)][hashtable]$ProtectedSettings,
        [Parameter(mandatory = $false)][boolean]$ReInstall = $false
    )

    $vmScaleSetName = $VMssObject.Name
    $vmScaleSetResourceGroupName = $VMssObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $ExtensionName

    try {
        $extension = Get-AzVMssExtension -VMss $VMssObject -ExtensionType $ExtensionType
    } catch {
        Set-FailureMessage "$vmScaleSetName : Failed to lookup $ExtensionType"
        throw $_
    }

    if ($extension) {
        Write-Verbose("$vmScaleSetName : $ExtensionType extension with name " + $extension.Name + " already installed. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings)
        $extensionName = $extension.Name
    }

    if ($PSCmdlet.ShouldProcess($vmScaleSetName, "install extension $ExtensionType")) {

        $parameters = @{
            VirtualMachineScaleSet  = $VMssObject
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

        Write-Verbose("$vmScaleSetName : Adding $ExtensionType with name $extensionName")
        $scalesetObject = Add-AzureRmVmssExtension @parameters

        Write-Verbose("$vmScaleSetName : Updating scale set with $ExtensionType extension")
        try {
            $result = Update-AzureRmVmss -VMScaleSetName $vmScaleSetName -ResourceGroupName $vmScaleSetResourceGroupName -VirtualMachineScaleSet $scalesetObject
        } catch {
            Set-FailureMessage "$vmScaleSetName : failed updating scale set with $ExtensionType extension"
            throw $_
        }
        if (!$result -or $result.ProvisioningState -ne "Succeeded") {
            Set-FailureMessage "$vmScaleSetName : failed updating scale set with $ExtensionType extension"
            throw
        } else {
            $message = "$vmScaleSetName : Successfully updated scale set with $ExtensionType extension"
            Write-Output($message)
            $OnboardingStatus.Succeeded += $message
        }
    }
}

function Assign-ManagedIdentityUtil {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)][Object]$VMObject,
        [Parameter(Mandatory = $true)][string]$UserAssignedManagedIdentyId
    )

    if (!$VMObject -or !$UserAssignedManagedIdentyId) {
        return
    }

    $userAssignedIdentitiesList = $VMObject.Identity.UserAssignedIdentities

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
        [Parameter(Mandatory = $true)][Object]$VMssObject,
        [Parameter(mandatory = $true)][string]$UserAssignedManagedIdentityResourceGroup,
        [Parameter(mandatory = $true)][string]$UserAssignedManagedIdentityName
    )

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
        Set-FailureMessage "Failed to lookup managed identity $UserAssignedManagedIdentityName"
        throw $_
    }

    try {
        $statusResult = Get-AzVmss -ResourceGroupName $VMssObject.ResourceGroupName -Name $VMssObject.Name
    } catch {
        $message = $VMssObject.Name + " : Failed to lookup VMss in " + $VMssObject.ResourceGroupName
        throw $_
    }
    if ($statusResult -and ($statusResult.Identity.Type -eq "UserAssigned") -and (Assign-ManagedIdentityUtil -isScaleset -VMssObject $statusResult -UserAssignedManagedIdentyId $userAssignedIdentityObject.Id)) {
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
            Set-FailureMessage  "Exception : $($VMssObject.Name) : Failed to assign user managed identity : $UserAssignedManagedIdentityName"
            throw $_
        }
        if ($updateResult -and $updateResult.IsSuccessStatusCode) {
            $message = $VMssObject.Name + ": Successfully assigned user managed identity : $UserAssignedManagedIdentityName"
            Write-Output($message)
        }
        else {
            $updateCode = $updateResult.StatusCode
            $errorMessage = $updateResult.ReasonPhrase
            Set-FailureMessage  "$($VMssObject.Name) : Failed to assign managed identity : $UserAssignedManagedIdentityName. StatusCode = $updateCode. ErrorMessage = $errorMessage."
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
        [Parameter(Mandatory = $true)][Object]$VMObject,
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
        Set-FailureMessage "Failed to lookup managed identity $UserAssignedManagedIdentityName"
        throw $_
    }

    try {
        $statusResult = Get-AzVM -ResourceGroupName $VMObject.ResourceGroupName -Name $VMObject.Name
    } catch {
        Set-FailureMessage "$($VMObject.Name) : Failed to lookup VM in $($VMObject.ResourceGroupName)"
        throw $_
    }
    if ($statusResult -and ($statusResult.Identity.Type -eq "UserAssigned") -and (Assign-ManagedIdentityUtil -VMObject $statusResult -UserAssignedManagedIdentyId $userAssignedIdentityObject.Id)) {
        $message = $VMObject.Name + " : Already assigned with managed identity : " + $UserAssignedManagedIdentityName
        Write-Output($message)
    } else {
        try {
            $updateResult = Update-AzVM -ResourceGroupName $VMObject.ResourceGroupName `
                                        -VM $VMObject `
                                        -IdentityType "UserAssigned" `
                                        -IdentityID $userAssignedIdentityObject.Id
        } catch {
            Set-FailureMessage "$($VMObject.Name) : Failed to assign user managed identity = $UserAssignedManagedIdentityName"
            throw $_
        }
        if ($updateResult -and $updateResult.IsSuccessStatusCode) {
            $message = $VMObject.Name + ": Successfully assigned managed identity : " + $UserAssignedManagedIdentityName
            Write-Output($message)
        }
        else {
            $statusCode = $updateResult.StatusCode
            $ErrorMessage = $updateResult.ReasonPhrase
            Set-FailureMessage "$($VMObject.Name) : Failed to assign managed identity : $UserAssignedManagedIdentityName. StatusCode = $statusCode. ErrorMessage = $ErrorMessage."
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
                Set-FailureMessage "Scope $targetScope : role assignment with $role failed"
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
$account =  Get-AzContext
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
                -VMssObject $vm
                -ExtensionType $maExt `
                -ExtensionName $maExtensionName `
                -ExtensionPublisher $maExtensionPublisher `
                -ExtensionVersion $maExtVersion `
                -PublicSettings $maPublicSettings `
                -ProtectedSettings $maProtectedSettings `
                -ReInstall $ReInstall `

            if (!$DcrResourceId -or ($DcrResourceId -and $ProcessAndDependencies)) {
                Install-VMssExtension `
                    -VMssObject $vm
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
                -VMObject $vm
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
                    -VMObject $vm
                    -ExtensionType $daExt `
                    -ExtensionName $daExt `
                    -ExtensionPublisher $daExtensionPublisher `
                    -ExtensionVersion $daextVersion `
                    -PublicSettings $daPublicSettings `
                    -ReInstall $ReInstall `
                    -OnboardingStatus $OnboardingStatus
            }
        }
        New-DCRAssociation `
            -VMObject $vm `
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
