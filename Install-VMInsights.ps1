<#
.SYNOPSIS
  Configure VM's and VM Scale Sets for VM Insights:
  - Installs Log Analytics VM Extension configured to supplied Log Analytics Workspace
  - Installs Dependency Agent VM Extension
  - Installs resource for Health (Microsoft.WorkloadMonitor/workloadInsights) for VM's only

  Can be applied to:
  - Subscription
  - Resource Group in a Subscription
  - Specific VM/VM Scale Set

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

.PARAMETER WorkspaceRegion
    Region the Log Analytics Workspace is in
    Suuported values: "East US","eastus","Southeast Asia","southeastasia","West Central US","westcentralus","West Europe","westeurope"
    For Health supported is: "East US","eastus","West Central US","westcentralus"

.PARAMETER ResourceGroup
    <Optional> Resource Group to which the VMs or VM Scale Sets belong to

.PARAMETER Name
    <Optional> To install to a single VM/VM Scale Set

.PARAMETER ReInstall
    <Optional> If VM/VM Scale Set is already configured for a different workspace, set this to change to the new workspace

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
  .\Install-VMInsights.ps1 -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup>
  Install for all VM's in a Resource Group in a subscription

  .\Install-VMInsights.ps1 -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup> -ReInstall
  Specify to ReInstall extensions even if already installed, for example to update workspace

.LINK
    This script is posted to and further documented at the following location:
    http://aka.ms/OnBoardVMInsights
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(mandatory = $true)][string]$WorkspaceId,
    [Parameter(mandatory = $true)][string]$WorkspaceKey,
    [Parameter(mandatory = $true)][string]$SubscriptionId,
    [Parameter(mandatory = $false)][string]$ResourceGroup,
    [Parameter(mandatory = $false)][string]$Name,
    [Parameter(mandatory = $false)][switch]$ReInstall,
    [Parameter(mandatory = $false)][switch]$TriggerVmssManualVMUpdate,
    [Parameter(mandatory = $false)][switch]$Approve,
    [Parameter(mandatory = $true)] `
        [ValidateSet( `
            "East US", "eastus", "Southeast Asia", "southeastasia", "West Central US", "westcentralus", "West Europe", "westeurope")] `
        [string]$WorkspaceRegion
)

# supported regions for Health
$supportedHealthRegions = @("East US", "eastus", "West Central US", "westcentralus")

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

    $vm = Get-AzureRmVM -Name $VMName -ResourceGroupName $vmResourceGroupName -DisplayHint Expand
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

    $extension = Get-VMExtension -VMName $VMName -VMResourceGroup $VMResourceGroupName -ExtensionType $ExtensionType
    if ($extension) {
        $extensionName = $extension.Name

        # of has Settings - it is LogAnalytics extension
        if ($extension.Settings) {
            if ($extension.Settings.ToString().Contains($PublicSettings.workspaceId)) {
                $message = "$VMName : Extension $ExtensionType already configured for this workspace. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings
                $OnboardingStatus.AlreadyOnboarded += $message
                Write-Output($message)
            }
            else {
                if ($ReInstall -ne $true) {
                    $message = "$VMName : Extension $ExtensionType already configured for a different workspace. Run with -ReInstall to move to new workspace. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings
                    Write-Warning($message)
                    $OnboardingStatus.DifferentWorkspace += $message
                }
            }
        }
        else {
            $message = "$VMName : $ExtensionType extension with name " + $extension.Name + " already installed. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings
            Write-Output($message)
        }
    }

    if ($PSCmdlet.ShouldProcess($VMName, "install extension $ExtensionType") -and ($ReInstall -eq $true -or !$extension)) {

        $parameters = @{
            ResourceGroupName  = $VMResourceGroupName
            VMName             = $VMName
            Location           = $VMLocation
            Publisher          = $ExtensionPublisher
            ExtensionType      = $ExtensionType
            ExtensionName      = $extensionName
            TypeHandlerVersion = $ExtensionVersion
        }

        if ($PublicSettings -and $ProtectedSettings) {
            $parameters.Add("Settings", $PublicSettings)
            $parameters.Add("ProtectedSettings", $ProtectedSettings)
        }

        Write-Output("$VMName : Deploying $ExtensionType with name $extensionName")
        $result = Set-AzureRmVMExtension @parameters

        if ($result -and $result.IsSuccessStatusCode) {
            $message = "$VMName : Successfully deployed $ExtensionType"
            Write-Output($message)
            $OnboardingStatus.Succeeded += $message
        }
        else {
            $message = "$VMName : Failed to deploy $ExtensionType"
            Write-Warning($message)
            $OnboardingStatus.Failed += $message
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
            Write-Verbose("$VMScaleSetName : Extension: $ExtensionType found on VMSS")
            $extension
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

    $scalesetObject = Get-AzureRMVMSS -VMScaleSetName $VMScaleSetName -ResourceGroupName $VMScaleSetResourceGroupName

    $extension = Get-VMssExtension -VMss $scalesetObject -ExtensionType $ExtensionType
    if ($extension) {
        Write-Output("$VMScaleSetName : $ExtensionType extension with name " + $extension.Name + " already installed. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings)
        $extensionName = $extension.Name
    }

    if (($ReInstall -eq $true -or !$extension) -and $PSCmdlet.ShouldProcess($VMScaleSetName, "install extension $ExtensionType")) {

        $parameters = @{
            VirtualMachineScaleSet  = $scalesetObject
            Name                    = $extensionName
            Publisher               = $ExtensionPublisher
            Type                    = $ExtensionType
            TypeHandlerVersion      = $ExtensionVersion
            AutoUpgradeMinorVersion = $true
        }

        if ($PublicSettings -and $ProtectedSettings) {
            $parameters.Add("Setting", $PublicSettings)
            $parameters.Add("ProtectedSetting", $ProtectedSettings)
        }

        Write-Verbose("$VMScaleSetName : Adding $ExtensionType with name $extensionName")
        $scalesetObject = Add-AzureRmVmssExtension @parameters

        Write-Output("$VMScaleSetName Updating scale set with $ExtensionType extension")
        $result = Update-AzureRmVmss -VMScaleSetName $VMScaleSetName -ResourceGroupName $VMScaleSetResourceGroupName -VirtualMachineScaleSet $scalesetObject
        if ($result -and $result.ProvisioningState -eq "Succeeded") {
            $message = "$VMScaleSetName : Successfully updated scale set with $ExtensionType extension"
            Write-Output($message)
            $OnboardingStatus.Succeeded += $message
        }
        else {
            $message = "$VMScaleSetName : failed updating scale set with $ExtensionType extension"
            Write-Warning($message)
            $OnboardingStatus.Failed += $message
        }
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
$AlreadyOnboarded = @()
$OnboardingSucceeded = @()
$OnboardingFailed = @()
$OnboardingBlockedNotRunning = @()
$OnboardingBlockedDifferentWorkspace = @()
$VMScaleSetNeedsUpdate = @()
$OnboardingStatus = @{
    AlreadyOnboarded      = $AlreadyOnboarded;
    Succeeded             = $OnboardingSucceeded;
    Failed                = $OnboardingFailed;
    NotRunning            = $OnboardingBlockedNotRunning;
    DifferentWorkspace    = $OnboardingBlockedDifferentWorkspace;
    VMScaleSetNeedsUpdate = $VMScaleSetNeedsUpdate;
}

# Log Analytics Extension constants
$MMAExtensionMap = @{ "Windows" = "MicrosoftMonitoringAgent"; "Linux" = "OmsAgentForLinux" }
$MMAExtensionVersionMap = @{ "Windows" = "1.0"; "Linux" = "1.6" }
$MMAExtensionPublisher = "Microsoft.EnterpriseCloud.Monitoring"
$MMAExtensionName = "MMAExtension"
$PublicSettings = @{"workspaceId" = $WorkspaceId; "stopOnMultipleConnections" = "true"}
$ProtectedSettings = @{"workspaceKey" = $WorkspaceKey}

# Dependency Agent Extension constants
$DAExtensionMap = @{ "Windows" = "DependencyAgentWindows"; "Linux" = "DependencyAgentLinux" }
$DAExtensionVersionMap = @{ "Windows" = "9.5"; "Linux" = "9.5" }
$DAExtensionPublisher = "Microsoft.Azure.Monitoring.DependencyAgent"
$DAExtensionName = "DAExtension"

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
    $VMs = @($VMs) + $ScaleSets
}

Write-Output("`nVM's or VM ScaleSets matching criteria:`n")
$VMS | ForEach-Object { Write-Output ($_.Name + " " + $_.PowerState) }

# Validate customer wants to continue
Write-Output("`nThis operation will install the Log Analytics and Dependency Agent extensions on above $($VMS.Count) VM's or VM Scale Sets.")
Write-Output("VM's in a non-running state will be skipped.")
Write-Output("Extension will not be re-installed if already installed. Use -ReInstall if desired, for example to update workspace ")
if ($Approve -eq $true -or !$PSCmdlet.ShouldProcess("All") -or $PSCmdlet.ShouldContinue("Continue?", "")) {
    Write-Output ""
}
else {
    Write-Output "You selected No - exiting"
    return
}

Write-Output "Register the Resource Provider Microsoft.AlertsManagement for Health feature"
Register-AzureRmResourceProvider -ProviderNamespace Microsoft.AlertsManagement

#
# Loop through each VM/VM Scale set, as appropriate handle installing VM Extensions
#
Foreach ($vm in $VMs) {
    # set as variabels so easier to use in output strings
    $vmName = $vm.Name
    $vmLocation = $vm.Location
    $vmResourceGroupName = $vm.ResourceGroupName

    #
    # Find OS Type
    #
    if ($vm.type -eq 'Microsoft.Compute/virtualMachineScaleSets') {
        $isScaleset = $true

        $scalesetVMs = @()
        $scalesetVMs = Get-AzureRmVMssVM -ResourceGroupName $vmResourceGroupName -VMScaleSetName $vmName
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
    $mmaExt = $MMAExtensionMap.($osType.ToString())
    if (! $mmaExt) {
        Write-Warning("$vmName : has an unsupported OS: $osType")
        continue
    }
    $mmaExtVersion = $MMAExtensionVersionMap.($osType.ToString())
    $daExt = $DAExtensionMap.($osType.ToString())
    $daExtVersion = $DAExtensionVersionMap.($osType.ToString())

    Write-Verbose("Deployment settings: ")
    Write-Verbose("ResourceGroup: $vmResourceGroupName")
    Write-Verbose("VM: $vmName")
    Write-Verbose("Location: $vmLocation")
    Write-Verbose("OS Type: $ext")
    Write-Verbose("Dependency Agent: $daExt, HandlerVersion: $daExtVersion")
    Write-Verbose("Monitoring Agent: $mmaExt, HandlerVersion: $mmaExtVersion")

    if ($isScaleset) {

        Install-VMssExtension `
            -VMScaleSetName $vmName `
            -VMScaleSetResourceGroupName $vmResourceGroupName `
            -ExtensionType $mmaExt `
            -ExtensionName $mmaExtensionName `
            -ExtensionPublisher $MMAExtensionPublisher `
            -ExtensionVersion $mmaExtVersion `
            -PublicSettings $PublicSettings `
            -ProtectedSettings $ProtectedSettings `
            -ReInstall $ReInstall

        Install-VMssExtension `
            -VMScaleSetName $vmName `
            -VMScaleSetResourceGroupName $vmResourceGroupName `
            -ExtensionType $daExt `
            -ExtensionName $daExtensionName `
            -ExtensionPublisher $DAExtensionPublisher `
            -ExtensionVersion $daExtVersion `
            -ReInstall $ReInstall

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
		
        if ($supportedHealthRegions -contains $WorkspaceRegion) {
            $message = "$vmName : Succesfully onboarded to Health"
			Write-Output($message)
			$OnboardingStatus.Succeeded += $message
		}
		else
		{
			$message = "$vmname cannot be onboarded to Health monitoring, workspace associated to this is not in a supported region "
			Write-Warning($message)	
		}
		
        Install-VMExtension `
            -VMName $vmName `
            -VMLocation $vmLocation `
            -VMResourceGroupName $vmResourceGroupName `
            -ExtensionType $mmaExt `
            -ExtensionName $mmaExtensionName `
            -ExtensionPublisher $MMAExtensionPublisher `
            -ExtensionVersion $mmaExtVersion `
            -PublicSettings $PublicSettings `
            -ProtectedSettings $ProtectedSettings `
            -ReInstall $ReInstall `
            -OnboardingStatus $OnboardingStatus

        Install-VMExtension `
            -VMName $vmName `
            -VMLocation $vmLocation `
            -VMResourceGroupName $vmResourceGroupName `
            -ExtensionType $daExt `
            -ExtensionName $daExtensionName `
            -ExtensionPublisher $DAExtensionPublisher `
            -ExtensionVersion $daExtVersion `
            -ReInstall $ReInstall `
            -OnboardingStatus $OnboardingStatus
			
		Write-Output("`n")

    }
}

Write-Output("`nSummary:")
Write-Output("`nAlready Onboarded: (" + $OnboardingStatus.AlreadyOnboarded.Count + ")")
$OnboardingStatus.AlreadyOnboarded  | ForEach-Object { Write-Output ($_) }
Write-Output("`nSucceeded: (" + $OnboardingStatus.Succeeded.Count + ")")
$OnboardingStatus.Succeeded | ForEach-Object { Write-Output ($_) }
Write-Output("`nConnected to different workspace: (" + $OnboardingStatus.DifferentWorkspace.Count + ")")
$OnboardingStatus.DifferentWorkspace | ForEach-Object { Write-Output ($_) }
Write-Output("`nNot running - start VM to configure: (" + $OnboardingStatus.NotRunning.Count + ")")
$OnboardingStatus.NotRunning  | ForEach-Object { Write-Output ($_) }
Write-Output("`nVM Scale Set needs update: (" + $OnboardingStatus.VMScaleSetNeedsUpdate.Count + ")")
$OnboardingStatus.VMScaleSetNeedsUpdate  | ForEach-Object { Write-Output ($_) }
Write-Output("`nFailed: (" + $OnboardingStatus.Failed.Count + ")")
$OnboardingStatus.Failed | ForEach-Object { Write-Output ($_) }
