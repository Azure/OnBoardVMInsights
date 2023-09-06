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
(the above command will onboard Assign a UAMI to a VM/VMss for AMA, Onboard AMA, DA and Associate a DCR with the VM/Vmss)

.EXAMPLE
.\Install-VMInsights.ps1 -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup>  -DcrResourceId <DataCollectionRuleResourceId> -UserAssignedManagedIdentityName <UserAssignedIdentityName> -UserAssignedManagedIdentityResourceGroup <UserAssignedIdentityResourceGroup>
(the above command will onboard Assign a UAMI to a VM/VMss for AMA, Onboard AMA and Associate a DCR with the VM/Vmss)

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

# Azure Monitoring Agent Extension constants
Set-Variable -Name amaExtensionMap -Option Constant -Value @{ "Windows" = "AzureMonitorWindowsAgent"; "Linux" = "AzureMonitorLinuxAgent" }
Set-Variable -Name amaExtensionVersionMap -Option Constant -Value @{ "Windows" = "1.16"; "Linux" = "1.16" }
Set-Variable -Name amaExtensionPublisher -Option Constant -Value "Microsoft.Azure.Monitor"
Set-Variable -Name amaExtensionName -Option Constant -Value "AzureMonitoringAgent"

# Dependency Agent Extension constants
Set-Variable -Name daExtensionMap -Option Constant -Value @{"Windows" = "DependencyAgentWindows"; "Linux" = "DependencyAgentLinux" }
Set-Variable -Name daExtensionVersionMap -Option Constant -Value @{ "Windows" = "9.10"; "Linux" = "9.10" }
Set-Variable -Name daExtensionPublisher -Option Constant -Value "Microsoft.Azure.Monitoring.DependencyAgent"
Set-Variable -Name daExtensionName -Option Constant -Value "DA-Extension"
Set-Varaible -Name processAndDependenciesPublicSettings -Option Constant -Value @{"enableAMA" = "true"}
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
        [Parameter(mandatory = $true)][Object]$VMObject,
        [Parameter(mandatory = $true)][string]$ExtensionType,	
	    [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmResourceGroupName = $VMObject.ResourceGroupName
    $vmName = $VMObject.VMName

    try {
        $extensions = Get-AzVMExtension -VMName $vmName -ResourceGroupName $vmResourceGroupName
    } catch {
        $OnboardingStatus.Failed += "$vmName : Failed to lookup for extensions"
        throw $_
    }

    foreach ($extension in $extensions) {
        if ($ExtensionType -eq $extension.VirtualMachineExtensionType) {
            Write-Verbose("$vmName : Extension : $ExtensionType found")
            $extension
            return
        }
    }
    Write-Verbose("$vmName : Extension : $ExtensionType not found")
}

function Get-VMssExtension {
    <#
	.SYNOPSIS
	Return the VMss extension of specified ExtensionType
	#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $True)][Object]$VMssObject,
        [Parameter(mandatory = $true)][string]$ExtensionType
    )

    $vmssName = $VMssObject.Name
    try {
        foreach ($extension in $VMssObject.VirtualMachineProfile.ExtensionProfile.Extensions) {
            if ($ExtensionType -eq $extension.Type) {
                Write-Verbose("$vmssName : Extension: $ExtensionType found")
                $extension
                return
            }
        }
        Write-Verbose("$vmssName : Extension: $ExtensionType not found")
    }
    catch {
        $OnboardingStatus.Failed += "$vmssName : Failed to lookup $ExtensionType"
        throw $_
    }
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
        Write-Verbose "$vmName : Failed to lookup $ExtensionType"
        return
    }

    $extensionName = $extension.Name

    if (!$PSCmdlet.ShouldProcess($vmssName, "Remove OmsAgentForLinux")) {
        return
    }

    try {
        $removeResult = Remove-AzVMExtension -ResourceGroupName $vmResourceGroupName -VMName $vmName -Name $extensionName -Force -ErrorAction "Stop"
    } catch [ParameterBindingException] {

    } 
    catch {
        $OnboardingStatus.Failed += "$vmName : Failed to remove extension : $ExtensionType"
        throw $_
    }

    if ($removeResult.IsSuccessStatusCode) {
        Write-Verbose "$vmName : Successfully removed $ExtensionType"
        return
    }

    $statusCode = $removeResult.StatusCode
    $errorMessage = $removeResult.ReasonPhrase
    $OnboardingStatus.Failed += "$vmName : Failed to remove $ExtensionType. StatusCode = $statusCode. ErrorMessage = $errorMessage."
    throw "$vmName : Failed to remove $ExtensionType. StatusCode = $statusCode. ErrorMessage = $errorMessage."
    
}

function New-DCRAssociation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(mandatory = $true)][Object]$VMObject,
        [Parameter(mandatory = $true)][string]$DcrResourceId,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmName = $VMObject.Name
    $vmId = $VMObject.Id

    try {
        # A VM may have zero or more Data Collection Rule Associations
        $dcrAssociationList = Get-AzDataCollectionRuleAssociation -TargetResourceId $vmId
    } catch {
        $OnboardingStatus.Failed += "$vmName : Failed to lookup the Data Collection Rule : $DcrResourceId"
        throw $_
    }

    # A VM may have zero or more Data Collection Rule Associations
    foreach ($dcrAssociation in $dcrAssociationList) {
        if ($dcrAssociation.DataCollectionRuleId -eq $DcrResourceId) {
            Write-Output "$vmName : Data Collection Rule already associated under $($dcrAssociation.Name)"
            return
        }
    }

    #The Customer is responsible to uninstall the DCR Association themselves
    if (!($PSCmdlet.ShouldProcess($vmName, "Install Data Collection Rule Association. (NOTE : Customer is responsible for uninstalling a data collection rule association)"))) {
        return
    }

    $dcrassociationName = "VM-Insights-$vmName-Association"
    Write-Verbose "$vmName : Deploying Data Collection Rule Association with name $dcrassociationName"
    try {
        $dcrassociation = New-AzDataCollectionRuleAssociation -TargetResourceId $vmId -AssociationName $dcrassociationName -RuleId $DcrResourceId
    } catch {
        $OnboardingStatus.Failed += "$vmName : Failed to create Data Collection Rule Association for $vmId"
        throw $_
    }
    #Tmp fix task:- 21191002
    if (!$dcrassociation -or $dcrassociation -is [ErrorResponseCommonV2Exception]) {
        $OnboardingStatus.Failed += "$vmName : Failed to create Data Collection Rule Association for $vmId"
        throw "$vmName : Failed to create Data Collection Rule Association for $vmId. ErrorMessage = $($dcrassociation.Response)"
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
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus    
    )

    Install-MmaVm -VMObject $VMObject `
                  -OnboardingStatus $OnboardingStatus

    Install-DaVm -VMObject $VMObject `
                 -OnboardingStatus $OnboardingStatus

    #reached this point - indicates all previous deployments succeeded
    $message = "$vmssName : Successfully onboarded VMInsights"
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
        [Parameter(mandatory = $false)][Object]$VMssObject,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus    
    )

    Install-MmaVmss -VMssObject $VMssObject `
                     -OnboardingStatus $OnboardingStatus

    Install-DaVmss -VMssObject $VMssObject `
                 -OnboardingStatus $OnboardingStatus

    #reached this point - indicates all previous deployments succeeded
    $message = "$vmssName : Successfully onboarded VMInsights"
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
        [Parameter(mandatory = $false)][Object]$VMObject,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $amaPublicSettings = @{'authentication' = @{
        'managedIdentity' = @{
        'identifier-name' = 'mi_res_id'
        }
      }
    }
            
    Assign-VmManagedIdentity -VMObject $VMObject `
                             -UserAssignedManagedIdentityObject $UserAssignedManagedIdentityObject `
                             -AmaPublicSettings $amaPublicSettings `
                             -OnboardingStatus $OnboardingStatus
        
    Install-AmaVm -VMObject $VMObject `
                  -AmaPublicSettings $amaPublicSettings `
                  -OnboardingStatus $OnboardingStatus

    if ($ProcessAndDependencies) {
        Install-DaVm -VMObject $VMObject `
                    -IsAmaOnboarded `
                    -OnboardingStatus $OnboardingStatus                
    }

    New-DCRAssociation `
                  -VMObject $VMObject `
                  -DcrResourceId $DcrResourceId `
                  -OnboardingStatus $OnboardingStatus

    #reached this point - indicates all previous deployments succeeded
    $message = "$vmName : Successfully onboarded VMInsights"
    Write-Output $message
    $OnboardingStatus.Succeeded += $message
}

function Onboard-VmiWithAmaOnVmss {
    <#
	.SYNOPSIS
	Onboard VMI with AMA on VMSS
	#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(mandatory = $false)][Object]$VMssObject,
        [Parameter(mandatory = $false)][Switch]$ProcessAndDependencies,
        [Parameter(mandatory = $true)][String]$DcrResourceId,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus,
        [Parameter(mandatory = $true)][hashtable]$UserAssignedManagedIdentityObject
    )

    $amaPublicSettings = @{'authentication' = @{
        'managedIdentity' = @{
        'identifier-name' = 'mi_res_id'
        }
      }
    }
            
    Assign-VmssManagedIdentity -VMssObject $VMObject `
                               -UserAssignedManagedIdentityObject $UserAssignedManagedIdentityObject
                               -AmaPublicSettings $amaPublicSettings
                               -OnboardingStatus $OnboardingStatus
        
    Install-AmaVmss -VMObject $VMObject `
                    -AmaPublicSettings $amaPublicSettings `
                    -OnboardingStatus $OnboardingStatus

    if ($ProcessAndDependencies) {
        Install-DaVmss -VMObject $VMObject `
                       -IsAmaOnboarded `
                       -OnboardingStatus $OnboardingStatus                
    }

    New-DCRAssociation `
                  -VMObject $VMObject `
                  -DcrResourceId $DcrResourceId `
                  -OnboardingStatus $OnboardingStatus

    #reached this point - indicates all previous deployments succeeded
    $message = "$vmssName : Successfully onboarded VMInsights"
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
        Write-Verbose "$vmName : $extensionType extension with name $extensionName already installed. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
        if (!$IsAmaOnboarded) {
            return
        } else {
            if ($extension.PublicSettings -and $extension.PublicSettings.ToString().Contains($processAndDependenciesPublicSettings.ToString())) {
                Write-Output "$vmName : Extension $extensionType already configured with AMA enabled. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
                return
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

    Install-VMExtension @parameters -OnboardingStatus $OnboardingStatus
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
    $vmssLocation = $VMssObject.Location
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $daExtensionName
    
    try {
        $vmssInstances = Get-AzVmssVM -ResourceGroupName $vmssResourceGroupName -VMScaleSetName $vmssName
    } catch {
        Write-Output "Exception : $vmssName : Failed to lookup constituent VMs"
        throw $_
    }
    if ($vmssInstances.length -gt 0) {
        if ($vmssInstances[0]) {
            $osType = $vmssInstances[0].storageprofile.osdisk.ostype
        }
    }

    $extensionType = $daExtensionMap.($osType.ToString())
    $extension = Get-VMssExtension -VMssObject $VMssObject -ExtensionType $extensionType -OnboardingStatus $OnboardingStatus
    
    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "$vmssName : $extensionType extension with name $extensionName already installed. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
        if (!$IsAmaOnboarded) {
            return
        } else {
            if ($extension.PublicSettings -and $extension.PublicSettings.Contains($processAndDependenciesPublicSettings.ToString())) {
                Write-Output "$vmssName : Extension $extensionType already configured with AMA enabled. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
                return
            }
        }
    }
    
    if (!($PSCmdlet.ShouldProcess($vmssName, "install extension $extensionType"))) {
        return
    }

    $parameters = @{
        ResourceGroupName  = $vmssResourceGroupName
        VMName             = $vmssName
        Location           = $vmssLocation
        Publisher          = $daExtensionPublisher
        ExtensionType      = $extensionType
        ExtensionName      = $extensionName
        TypeHandlerVersion = $daExtensionVersionMap.($osType.ToString())
        ForceRerun         = $True
    }

    if ($IsAmaOnboarded) {
        $parameters.Add("Settings", $processAndDependenciesPublicSettings)
    }

    Install-VMssExtension @parameters -OnboardingStatus $OnboardingStatus
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
        [Parameter(mandatory = $true)][String]$AmaPublicSettings,
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
        Write-Verbose "$vmName : $extensionType extension with name $extensionName already installed. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
        if ($extension.PublicSettings) {
            if ($extension.PublicSettings.ToString().Contains($AmaPublicSettings.ToString())) {
                Write-Output "$vmName : Extension $extensionType already configured with this user assigned managed identity. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
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
    }

    $parameters.Add("Settings", $AmaPublicSettings)
    Install-VMExtension @parameters -OnboardingStatus $OnboardingStatus 
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
        [Parameter(mandatory = $false)][Switch]$ReInstall,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmName = $VMObject.Name
    $vmLocation = $VMObject.Location
    $vmResourceGroupName = $VMObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $mmaExtensionName
    $osType = $VMObject.StorageProfile.OsDisk.OsType
    $extensionType = $mmaExtensionMap.($osType.ToString())
    $extension = Get-VMExtension -VMObject $VMObject -ExtensionType $extensionType -OnboardingStatus $OnboardingStatus
    $mmaPublicSettings = @{"workspaceId" = $WorkspaceId; "stopOnMultipleConnections" = "true"}
    $mmaProtectedSettings = @{"workspaceKey" = $WorkspaceKey}

    if ($extension) {
        $extensionName = $extension.Name
        Write-Verbose "$vmName : $extensionType extension with name $extensionName already installed. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
        if ($extension.PublicSettings) {
            if ($extension.PublicSettings.ToString().Contains($MmaPublicSettings.ToString())) {
                Write-Output "$vmName : Extension $extensionType already configured for this workspace. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
                return
            } else {
                if (!$ReInstall) {
                    Write-Output "$vmName : Extension $extensionType present, run with -ReInstall again to move to new workspace. Provisioning State: $($extension.ProvisioningState) `n $($extension.PublicSettings)"
                    return
                }
            }
        }
    }

    if ($extensionType -eq "OmsAgentForLinux") {
        Write-Output "$vmName : ExtensionType: $extensionType does not support updating workspace. An uninstall followed by re-install is required"
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
    }

    $parameters.Add("Settings", $mmaPublicSettings)
    $parameters.Add("ProtectedSettings", $mmaProtectedSettings)
    if ($ExtensionType -eq "OmsAgentForLinux") {
        Remove-VMExtension -VMObject $VMObject `
                            -ExtensionType $extensionType `
                            -OnboardingStatus $OnboardingStatus
    }

    Install-VMExtension @parameters -OnboardingStatus $OnboardingStatus 
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
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmssName = $VMssObject.Name
    $vmssResourceGroupName = $VMssObject.ResourceGroupName
    # Use supplied name unless already deployed, use same name
    $extensionName = $amaExtensionName
    
    try {
        $scalesetVms = Get-AzVmssVM -ResourceGroupName $vmssResourceGroupName -VMScaleSetName $vmssName
    } catch {
        Write-Output "Exception : $vmssName : Failed to lookup constituent VMs"
        throw $_
    }

    if ($scalesetVMs.length -gt 0) {
        if ($scalesetVMs[0]) {
            $osType = $scalesetVMs[0].storageprofile.osdisk.ostype
        }
    }
    
    $extensionType = $amaExtensionMap.($osType.ToString())
    # Use supplied name unless already deployed, use same name
    $extension = Get-VMssExtension -VMss $VMssObject -ExtensionType $extensionType
    $extAutoUpgradeMinorVersion = $true
    
    if ($extension) {
        $extensionName = $extension.Name
        $extAutoUpgradeMinorVersion = $extension.AutoUpgradeMinorVersion
        Write-Verbose "$vmssName : $extensionType extension with name $extensionName already installed. Provisioning State: $($extension.ProvisioningState)  $($extension.Settings)"
    }

    if (!($PSCmdlet.ShouldProcess($vmssName, "install extension $extensionType"))) {
        return
    }

    $parameters = @{
        VirtualMachineScaleSet  = $VMssObject
        Name                    = $extensionName
        Publisher               = $amaExtensionPublisher
        Type                    = $extensionType
        TypeHandlerVersion      = $amaExtensionVersionMap.($osType.ToString())
        AutoUpgradeMinorVersion = $extAutoUpgradeMinorVersion
    }

    $parameters.Add("Settings", $amaPublicSettings)
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
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmssName = $VMssObject.Name
    # Use supplied name unless already deployed, use same name
    $extensionName = $mmaExtensionName
    $osType = $VMssObject.StorageProfile.OsDisk.OsType
    $extensionType = $amaExtensionMap.($osType.ToString())
    # Use supplied name unless already deployed, use same name
    $extension = Get-VMssExtension -VMss $VMssObject -ExtensionType $extensionType
    $extAutoUpgradeMinorVersion = $true
    $mmaPublicSettings = @{"workspaceId" = $WorkspaceId; "stopOnMultipleConnections" = "true"}
    $mmaProtectedSettings = @{"workspaceKey" = $WorkspaceKey}
    
    if ($extension) {
        $extensionName = $extension.Name
        $extAutoUpgradeMinorVersion = $extension.AutoUpgradeMinorVersion
        Write-Verbose "$vmssName : $extensionType extension with name $extensionName already installed. Provisioning State: $($extension.ProvisioningState)  $($extension.Settings)"
    }

    if (!($PSCmdlet.ShouldProcess($vmssName, "install extension $extensionType"))) {
        return
    }

    $parameters = @{
        VirtualMachineScaleSet  = $VMssObject
        Name                    = $extensionName
        Publisher               = $mmaExtensionPublisher
        Type                    = $extensionType
        TypeHandlerVersion      = $mmaExtensionVersionMap.($osType.ToString())
        AutoUpgradeMinorVersion = $extAutoUpgradeMinorVersion
    }

    $parameters.Add("Settings", $mmaPublicSettings)
    $parameters.Add("ProtectedSettings", $mmaProtectedSettings)
    Install-VMssExtension -InstallParameters $parameters -OnboardingStatus $OnboardingStatus
}

function Install-VMExtension {
    <#
	.SYNOPSIS
	Install VM Extension, handling if already installed
	#>
    param
    (
        [Parameter(mandatory = $false)][hashtable]$InstallParameters,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmName = $InstallParameters.VMName
    $extensionType = $InstallParameters.ExtensionType
    $extensionName = $InstallParameters.ExtensionName
    
    Write-Verbose("$vmName : Deploying/Updating $extensionType with name $extensionName")
    try {
        $result = Set-AzVMExtension @InstallParameters
    }
    catch {
        $OnboardingStatus.Failed += "$vmName : Failed to install/update $extensionType"
        throw $_
    }

    if ($result.IsSuccessStatusCode) {
        Write-Output "$vmName : Successfully deployed/updated $extensionType"
        return
    }

    $OnboardingStatus.Failed += "$vmName : Failed to install/update $extensionType"
    throw "$vmName : Failed to deploy/update $extensionType"
}

function Install-VMssExtension {
    <#
	.SYNOPSIS
	Install VMss Extension, handling if already installed
	#>
    param
    (
        [Parameter(mandatory = $false)][hashtable]$InstallParameters,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmssName = $InstallParameters.VirtualMachineScaleSet.Name
    $extensionType = $InstallParameters.Type
    Write-Verbose("$vmssName : Adding $extensionType with name $extensionName")
    try {
        $VMssObject = Add-AzVmssExtension @InstallParameters
    }
    catch {
        $OnboardingStatus.Failed += "$vmssName : Failed to install/update $extensionType"
        throw $_
    }
    
    Write-Verbose("$vmssName : Updating scale set with $extensionType extension")
    
    try {
        $result = Update-AzVmss -VMScaleSetName $vmssName -ResourceGroupName $vmssResourceGroupName -VirtualMachineScaleSet $VMssObject
    } catch {
        $OnboardingStatus.Failed += "$vmssName : failed updating scale set with $extensionType extension"
        throw $_
    }

    if ($result -and $result.ProvisioningState -eq "Succeeded") {
        Write-Output "$vmssName : Successfully updated scale set with $extensionType extension"
    }

    $OnboardingStatus.Failed += "$vmssName : failed updating scale set with $extensionType extension"
    throw "$vmssName : failed updating scale set with $extensionType extension"
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

function Assign-ManagedIdentityRoles {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param {
        [Parameter(Mandatory = $true)][String]$TargetScope
        [Parameter(Mandatory = $true)][IIdentity]$UserAssignedManagedIdentityObject
    }

    $userAssignedManagedIdentityName = $UserAssignedManagedIdentityObject.Name
    $userAssignedManagedIdentityId = $UserAssignedManagedIdentityObject.principalId
    $roleDefinitionList = @("Virtual Machine Contributor", "Azure Connected Machine Resource Administrator", "Log Analytics Contributor") 
    
    if (!($PSCmdlet.ShouldProcess($vmResourceGroupName, "assign roles : $roleDefinitionList to user assigned managed identity : $userAssignedManagedIdentityName"))) {
        return
    }

    foreach ($role in $roleDefinitionList) {
        try {
            $roleAssignmentFound = Get-AzRoleAssignment -ObjectId $userAssignedManagedIdentityId -RoleDefinitionName $role -Scope $TargetScope
        }
        catch {
            throw $_
        }

        if ($roleAssignmentFound) {
            Write-Verbose "Scope $targetScope : role $role already set"
        } else {
            Write-Verbose("Scope $targetScope : assigning role $role")
            try {
                New-AzRoleAssignment  -ObjectId $userAssignedManagedIdentityId -RoleDefinitionName $role -Scope $targetScope
                Write-Output "Scope $targetScope : role assignment for $userAssignedManagedIdentityName with $role succeeded"
            }
            catch {
                throw $_
            }
        }
    }
}

function Assign-VmssManagedIdentity {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)][Object]$VMssObject,
        [Parameter(Mandatory = $true)][IIdentity]$UserAssignedManagedIdentityObject,
        [Parameter(mandatory = $true)][hashtable]$AmaPublicSettings,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmssName = $VMssObject.Name
    $vmssResourceGroup = $VMssObject.ResourceGroupName
    $userAssignedManagedIdentityName = $UserAssignedManagedIdentityObject.Name
    $userAssignedManagedIdentityId = $UserAssignedManagedIdentityObject.Id

    if (Check-UserManagedIdentityAlreadyAssigned -VMObject $VMssObject `
                                                 -UserAssignedManagedIdentyId $userAssignedManagedIdentityId) {
        Write-Verbose "$vmssName : Already assigned with user managed identity : $userAssignedManagedIdentityName"
    } else {
        if (!($PSCmdlet.ShouldProcess($vmssName, "assign managed identity $userAssignedManagedIdentityName"))) {
            return
        }

        try {
            $result = Update-AzVMss -VirtualMachineScaleSet $VMssObject `
                                    -ResourceGroupName $vmssResourceGroup `
                                    -IdentityType "UserAssigned" `
                                    -IdentityID $userAssignedManagedIdentityId
        } catch {
            $OnboardingStatus.Failed += "$vmScaleSetName : Failed to assign user managed identity : $userAssignedManagedIdentityName"
            throw $_
        }

        if ($result -and $result.IsSuccessStatusCode) {
            Write-Output "$vmScaleSetName : Successfully assigned user managed identity : $userAssignedManagedIdentityName"
            return
        }

        $updateCode = $result.StatusCode
        $errorMessage = $result.ReasonPhrase
        $OnboardingStatus.Failed += "$vmScaleSetName : Failed to assign managed identity : $userAssignedManagedIdentityName. StatusCode = $updateCode. ErrorMessage = $errorMessage."
        
    }

    ##Assign Managed identity to Azure Monitoring Agent
    $AmaPublicSettings.authentication.managedIdentity.'identifier-value' = $UserAssignedManagedIdentityObject.Id
}

function Assign-VmManagedIdentity {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
        [Parameter(Mandatory = $true)][Object]$VMObject,
        [Parameter(Mandatory = $true)][IIdentity]$UserAssignedManagedIdentityObject,
        [Parameter(mandatory = $true)][hashtable]$AmaPublicSettings,
        [Parameter(mandatory = $true)][hashtable]$OnboardingStatus
    )

    $vmName = $VMObject.Name
    $vmResourceGroup = $VMObject.ResourceGroupName
    $userAssignedManagedIdentityName = $UserAssignedManagedIdentityObject.Name
    $userAssignedManagedIdentityId = $UserAssignedManagedIdentityObject.Id

    if (Check-UserManagedIdentityAlreadyAssigned -VMObject $VMObject `
                                                 -UserAssignedManagedIdentyId $userAssignedManagedIdentityId) {
        Write-Verbose "$vmName : Already assigned with managed identity : $userAssignedManagedIdentityName"
    } else {
        if (!($PSCmdlet.ShouldProcess($vmName, "assign managed identity $userAssignedManagedIdentityName"))) {
            return
        }

        try {
            $result = Update-AzVM -VM $VMObject `
                                  -ResourceGroupName $vmResourceGroup `
                                  -IdentityType "UserAssigned" `
                                  -IdentityID $userAssignedManagedIdentityId                               
        } catch {
            $OnboardingStatus.Failed += "$vmName : Failed to assign user managed identity = $userAssignedManagedIdentityName"
            throw $_
        }

        if ($result.IsSuccessStatusCode) {
            Write-Output "$vmName : Successfully assigned managed identity : $userAssignedManagedIdentityName"
            return
        }
       
        $statusCode = $result.StatusCode
        $errorMessage = $result.ReasonPhrase
        $OnboardingStatus.Failed += "$vmName : Failed to assign managed identity : $userAssignedManagedIdentityName. StatusCode = $statusCode. ErrorMessage = $errorMessage."
        throw "$vmName : Failed to assign managed identity : $userAssignedManagedIdentityName. StatusCode = $statusCode. ErrorMessage = $errorMessage."
    
    }

    ##Assign Managed identity to Azure Monitoring Agent
    $AmaPublicSettings.authentication.managedIdentity.'identifier-value' = $UserAssignedManagedIdentityObject.Id
}

function Display-Exception {
    try {
        try { "ExceptionClass = $($_.Exception.GetType().Name)" | Write-Output } catch { }
        try { "ExceptionMessage:`r`n$($_.Exception.Message)`r`n" | Write-Output } catch { }
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
    Write-Output "Account Context not found, please login"
    Connect-AzAccount -subscriptionid $SubscriptionId
}
else {
    if ($account.Subscription.Id -eq $SubscriptionId) {
        Write-Verbose("Subscription: $SubscriptionId is already selected.")
        $account
    }
    else {
        Write-Output "Current Subscription:"
        $account
        Write-Output "Changing to subscription: $SubscriptionId"
        Select-AzureSubscription -SubscriptionId $SubscriptionId
    }
}

$Vms = @()
$Vmss = @()
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
    $complianceResults = Get-AzPolicyState -PolicyAssignmentName $PolicyAssignmentName

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

        $vm = Get-AzVM -Name $vmName -ResourceGroupName $vmResourceGroup
        $vmStatus = Get-AzVM -Status -Name $vmName -ResourceGroupName $vmResourceGroup

        # fix to have same property as VM that is retrieved without Name
        $vm | Add-Member -NotePropertyName PowerState -NotePropertyValue $vmStatus.Statuses[1].DisplayStatus

        $VMs = @($VMs) + $vm
    }
} else {
    Write-Output "Getting list of VM's or VM ScaleSets matching criteria specified"
    if (!$ResourceGroup -and $Name) {
        exit
    } elseif (!$ResourceGroup -and !$Name) {
        # If ResourceGroup and Name value is not passed - get all VMs under given SubscriptionId
        $Vms = Get-AzVM -Status
        #skipping VMSS Instances and Virtual Machines not running.
        $Vms = $Vms | Where-Object {$_.PowerState -eq 'VM running' -and !($_.VirtualMachineScaleSet)}
        $Vmss = Get-AzVmss
    } else {
        # If ResourceGroup value is passed - select all VMs under given ResourceGroupName
        $Vms = Get-AzVM -ResourceGroupName $ResourceGroup -Status
        $Vms = $Vms | Where-Object {$_.PowerState -eq 'VM running' -and !($_.VirtualMachineScaleSet)}
        if ($Name) {
            $Vms = $Vms | Where-Object {$_.Name -like $Name}
        }
        $Vmss = Get-AzVmss -ResourceGroupName $ResourceGroup
        if ($Name) {
            $Vmss = $Vmss | Where-Object {$_.Name -like $Name}
        }
    }
}

Write-Output("`nVM's or VM ScaleSets matching criteria:`n")
$Vms | ForEach-Object { Write-Output "$($_.Name) $($_.PowerState)" }
$Vmss | ForEach-Object { Write-Output "$($_.Name) $($_.PowerState)" }

#script blocks
sb_ama_vm = { param($vmObj, $obs); Onboard-VmiWithAmaVm -VMObject $vmObj -OnboardingStatus $obs}
sb_mma_vm = { param($vmObj, $obs); Onboard-VmiWithMmaVm -VMObject $vmObj -OnboardingStatus $obs}
sb_ama_vmss = { param($vmssObj, $obs); Onboard-VmiWithAmaVmss -VMssObject $vmssObj -OnboardingStatus $obs}
sb_mma_vmss =   { param($vmssObj, $obs);  Onboard-VmiWithMmaVmss -VMssObject $vmssObj -OnboardingStatus $obs}

sb_vmss =  sb_mma_vmss
sb_vm = sb_mma_vm

# Validate customer wants to continue
Write-Output "VM's in a non-running state will be skipped."
if ($Approve -or $PSCmdlet.ShouldContinue("Continue?", "")) {
    Write-Output ""
}
else {
    Write-Output "You selected No - exiting"
    return
}

#assign roles to the user managed identity.
if ($DcrResourceId) {
    try {
        if ($ProcessAndDependencies) {
            sb_vm = sb_ama_pd_vm
            sb_vmss = sb_ama_pd_vmss
        } else {
            sb_vm = sb_ama_vm
            sb_vmss = sb_ama_vmss
        }
        
        #readonly object
        $userAssignedIdentityObject = Get-AzUserAssignedIdentity 
                                        -ResourceGroupName $UserAssignedManagedIdentityResourceGroup `
                                        -Name $UserAssignedManagedIdentityName
        if (!$userAssignedIdentityObject) {
            Write-Output "Failed to lookup managed identity $($userAssignedIdentityObject.Name)"
            Write-Output "Exiting..."
            exit
        } else {
            if ($VMResourceGroupName) {
                $rg = Get-AzResourceGroup -SubscriptionId $SubscriptionId -Name $VMResourceGroupName
                Assign-ManagedIdentityRoles -TargetScope $rg.ResourceId -UserAssignedIdentityObject $userAssignedIdentityObject
            } else {
                $Rgs = Get-AzResourceGroup -SubscriptionId $SubscriptionId
                ForEach ($rg in $Rgs) {
                    Assign-ManagedIdentityRoles -TargetScope $rg.ResourceId -UserAssignedIdentityObject $userAssignedIdentityObject
                }
            } 
        }
    } catch {
        Display-Exception $_
    }
}

#
# Loop through each VM/VM Scale set, as appropriate handle installing VM Extensions
#
Foreach ($vm in $Vms) {
    &$sb_vm -vmObj $Vm -obs $OnboardingStatus
}

Foreach ($vm in $Vmss) {
    &$sb_vmss -vmssObj $Vmss -obs $OnboardingStatus
}


Write-Output "`nSummary:"
Write-Output "`nSucceeded: (" + $OnboardingStatus.Succeeded.Count + ")"
$OnboardingStatus.Succeeded | ForEach-Object { Write-Output $_ }
Write-Output "`nNot running - start VM to configure: (" + $OnboardingStatus.NotRunning.Count + ")"
$OnboardingStatus.NotRunning  | ForEach-Object { Write-Output $_ }
Write-Output("`nVM Scale Set needs update: (" + $OnboardingStatus.VMScaleSetNeedsUpdate.Count + ")")
$OnboardingStatus.VMScaleSetNeedsUpdate  | ForEach-Object { Write-Output $_ }
Write-Output("`nFailed: (" + $OnboardingStatus.Failed.Count + ")")
$OnboardingStatus.Failed | ForEach-Object { Write-Output $_ }
