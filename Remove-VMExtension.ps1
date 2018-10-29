<#PSScriptInfo

.VERSION 1.1

.GUID 5d26f91b-5975-45f5-baa7-384b4276a155

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
This script removes Log Analytics and Dependency Agent VM extensions from VM's and VM Scale Sets

.DESCRIPTION
This script removes Log Analytics and Dependency Agent VM extensions from VM's and VM Scale Sets

Specify what to apply to with following parameters:
-LogAnalyticsAgent and/or -DependencyAgent and/or -TriggerVmssManualVMUpdate

Can be applied to:
- Subscription
- Resource Group in a Subscription
- Specific VM/VM Scale Set
- Compliance results of a policy for a VM or VM Extension

Script will show you list of VM's/VM Scale Sets that will apply to and let you confirm to continue.
Use -Approve switch to run without prompting, if all required parameters are provided.

Use -WhatIf if you would like to see what would happen in terms of installs, what workspace configured to, and status of the extension.

.PARAMETER SubscriptionId
SubscriptionId for the VMs/VM Scale Sets
If using PolicyAssignmentName parameter, subscription that VM's are in

.PARAMETER ResourceGroup
<Optional> Resource Group to which the VMs or VM Scale Sets belong to

.PARAMETER Name
<Optional> To install to a single VM/VM Scale Set

.PARAMETER PolicyAssignmentName
<Optional> Take the input VM's to operate on as the Compliance results from this Assignment
If specified will only take from this source.

.PARAMETER LogAnalyticsAgent
<Optional> Remove the Log Analytics Agent extension

.PARAMETER DependencyAgent
<Optional> Remove the Dependency Agent extension

.PARAMETER ApplyToVM
<Optional> Apply operation to VMs

.PARAMETER ApplyToVMSS
<Optional> Apply operation to VM Scale Sets

.PARAMETER TriggerVmssManualVMUpdate
<Optional> Set this flag to trigger update of VM instances in a scale set whose upgrade policy is set to Manual

.PARAMETER Approve
<Optional> Gives the approval with no confirmation prompt for the listed VM's/VM Scale Sets

.PARAMETER Whatif
<Optional> See what would happen

.PARAMETER Confirm
<Optional> Confirm every action

.EXAMPLE
.\Remove-VMExtension.ps1 -SubscriptionId <sub id> -ApplyToVM -LogAnalyticsAgent -DependencyAgent
Removes both Log Analytics and Dependency Agent extension for all VM's in subscription

.EXAMPLE
.\Remove-VMExtension.ps1 -SubscriptionId <sub id> -PolicyAssignmentName 4a69c0a045e94d88bf72715a -DependencyAgent -LogAnalyticsAgent
Remove both Log Analytics and Dependency Agent extension for VM's not compliant with this policy

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
    [Parameter(mandatory = $false)][switch]$LogAnalyticsAgent,
    [Parameter(mandatory = $false)][switch]$DependencyAgent,
    [Parameter(mandatory = $false)][switch]$ApplyToVM,
    [Parameter(mandatory = $false)][switch]$ApplyToVMSS,
    [Parameter(mandatory = $false)][switch]$TriggerVmssManualVMUpdate,
    [Parameter(mandatory = $false)][switch]$Approve
)

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

function Remove-VMExtension {
    <#
	.SYNOPSIS
	Remove VM Extension
	#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(mandatory = $true)][string]$VMResourceGroupName,
        [Parameter(mandatory = $true)][string]$ExtensionType,
        [Parameter(mandatory = $true)][hashtable]$OperationStatus
    )

    $extension = Get-VMExtension -VMName $VMName -VMResourceGroup $VMResourceGroupName -ExtensionType $ExtensionType
    if ($extension) {

        $message = "$VMName : $ExtensionType extension with name " + $extension.Name + " installed. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings
        Write-Output($message)

        if ($PSCmdlet.ShouldProcess($VMName, "remove extension $ExtensionType")) {

            Write-Output("$VMName : Removing extension $ExtensionType")
            $removeResult = Remove-AzureRmVMExtension -ResourceGroupName $VMResourceGroupName -VMName $VMName -Name $extension.Name -Force
            if ($removeResult -and $removeResult.IsSuccessStatusCode) {
                $message = "$VMName : Successfully removed $ExtensionType"
                $OperationStatus.Succeeded += $message
                Write-Output($message)
            }
            else {
                $message = "$VMName : Failed to remove $ExtensionType"
                Write-Warning($message)
                $OperationStatus.Failed += $message
            }
        }
    }
    else {
        $message = "$VMName : Extension: $ExtensionType not found on VM"
        Write-Output($message)
        $OperationStatus.ExtensionNotFound += $message
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

function Remove-VMssExtension {
    <#
	.SYNOPSIS
	Remove VM Extension based on ExtensionType
	#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $True)][string]$VMScaleSetName,
        [Parameter(Mandatory = $True)][string]$VMScaleSetResourceGroupName,
        [Parameter(Mandatory = $True)][string]$ExtensionType
    )
    $scalesetObject = Get-AzureRMVMSS -VMScaleSetName $VMScaleSetName -ResourceGroupName $VMScaleSetResourceGroupName

    $extension = Get-VMssExtension -VMss $scalesetObject -ExtensionType $ExtensionType
    if ($extension) {
        Write-Output("$VMScaleSetName : $ExtensionType extension with name " + $extension.Name + " installed. Provisioning State: " + $extension.ProvisioningState + " " + $extension.Settings)

        if ($PSCmdlet.ShouldProcess($VMScaleSetName, "install extension $ExtensionType")) {

            Write-Verbose("$VMScaleSetName : Removing $ExtensionType with name $extensionName")
            $result = Remove-AzureRmVmssExtension -VirtualMachineScaleSet $scalesetObject -Name $extension.Name
            if ($result -and $result.ProvisioningState -eq "Succeeded") {
                Write-Output("$VMScaleSetName : Succeeded removing $ExtensionType extension")
            }
            else {
                $message = "$VMScaleSetName : failed removing $ExtensionType extension"
                Write-Warning($message)
                $OperationStatus.Failed += $message
                return
            }

            Write-Output("$VMScaleSetName : Updating scale set")
            $result = Update-AzureRmVmss -VMScaleSetName $VMScaleSetName -ResourceGroupName $VMScaleSetResourceGroupName -VirtualMachineScaleSet $scalesetObject
            if ($result -and $result.ProvisioningState -eq "Succeeded") {
                $message = "$VMScaleSetName : Successfully updated scale set"
                Write-Output($message)
                $OperationStatus.Succeeded += $message
            }
            else {
                $message = "$VMScaleSetName : failed updating scale set"
                Write-Warning($message)
                $OperationStatus.Failed += $message
            }
        }
    }
    else {
        $message = "$VMScaleSetName : Extension: $ExtensionType not found on VMSS"
        Write-Output($message)
        $OperationStatus.ExtensionNotFound += $message
    }
}

#
# Main Script
#

#
# Validate an operation is supplied
#
if (-not ($LogAnalyticsAgent -or $DependencyAgent -or $TriggerVmssManualVMUpdate)) {
    Write-Output "`nPlease provide parameter for extension to remove. Either -LogAnalyticsAgent and/or -DependencyAgent"
    return
}

if (-not ($ApplyToVM -or $ApplyToVMSS -or $PolicyAssignmentName)) {
    Write-Output "`nPlease provide parameter for what to apply to. Either -ApplyToVM and/or -ApplyToVMSS or -PolicyAssignmentName"
    return
}

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
$ExtensionNotFound = @()
$OnboardingSucceeded = @()
$OnboardingFailed = @()
$OnboardingBlockedNotRunning = @()
$VMScaleSetNeedsUpdate = @()
$VMScaleSetInstancesUpdated = @()
$OperationStatus = @{
    ExtensionNotFound      = $ExtensionNotFound;
    Succeeded             = $OnboardingSucceeded;
    Failed                = $OnboardingFailed;
    NotRunning            = $OnboardingBlockedNotRunning;
    VMScaleSetNeedsUpdate = $VMScaleSetNeedsUpdate;
    VMScaleSetInstancesUpdated = $VMScaleSetInstancesUpdated;
}

# Log Analytics Extension constants
$MMAExtensionMap = @{ "Windows" = "MicrosoftMonitoringAgent"; "Linux" = "OmsAgentForLinux" }

# Dependency Agent Extension constants
$DAExtensionMap = @{ "Windows" = "DependencyAgentWindows"; "Linux" = "DependencyAgentLinux" }

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
        if ($ApplyToVM) {
            $VMs = Get-AzureRmVM -Status
        }
        if ($ApplyToVMSS) {
            $ScaleSets = Get-AzureRmVmss
        }
        $VMs = @($VMs) + $ScaleSets
    }
    else {
        # If ResourceGroup value is passed - select all VMs under given ResourceGroupName
        if ($ApplyToVM) {
            $VMs = Get-AzureRmVM -ResourceGroupName $ResourceGroup -Status
            if ($Name) {
                $VMs = $VMs | Where-Object {$_.Name -like $Name}
            }
        }
        if ($ApplyToVMSS) {
            $ScaleSets = Get-AzureRmVmss -ResourceGroupName $ResourceGroup
            if ($Name) {
                $ScaleSets = $ScaleSets | Where-Object {$_.Name -like $Name}
            }
        }

        $VMs = @($VMs) + $ScaleSets
    }
}

Write-Output("`nVM's or VM ScaleSets matching criteria:`n")
$VMS | ForEach-Object { Write-Output ($_.Name + " " + $_.PowerState) }

# Validate customer wants to continue
Write-Output("`nThis operation will remove the extensions as per arguments on above $($VMS.Count) VM's or VM Scale Sets.")
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
    $daExt = $DAExtensionMap.($osType.ToString())

    Write-Verbose("Settings: ")
    Write-Verbose("ResourceGroup: $vmResourceGroupName")
    Write-Verbose("VM: $vmName")
    Write-Verbose("Location: $vmLocation")
    Write-Verbose("OS Type: $ext")
    Write-Verbose("Dependency Agent: $daExt, HandlerVersion: $daExtVersion")
    Write-Verbose("Monitoring Agent: $mmaExt, HandlerVersion: $mmaExtVersion")

    if ($isScaleset) {

        if ($LogAnalyticsAgent) {
        Remove-VMssExtension `
            -VMScaleSetName $vmName `
            -VMScaleSetResourceGroupName $vmResourceGroupName `
            -ExtensionType $mmaExt
        }
        if ($DependencyAgent) {
        Remove-VMssExtension `
            -VMScaleSetName $vmName `
            -VMScaleSetResourceGroupName $vmResourceGroupName `
            -ExtensionType $daExt
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
                $message = "$vmName All scale set instances upgraded"
                Write-Output($message)
                $OperationStatus.VMScaleSetInstancesUpdated += $message
            }
            else {
                $message = "$vmName : has UpgradePolicy of Manual. Please trigger upgrade of VM Scale Set or call with -TriggerVmssManualVMUpdate"
                Write-Warning($message)
                $OperationStatus.VMScaleSetNeedsUpdate += $message
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
            $OperationStatus.NotRunning += $message
            continue
        }

        if ($LogAnalyticsAgent) {
            Remove-VMExtension `
                -VMName $vmName `
                -VMResourceGroupName $vmResourceGroupName `
                -ExtensionType $mmaExt `
                -OperationStatus $OperationStatus
        }

        if ($DependencyAgent) {
            Remove-VMExtension `
                -VMName $vmName `
                -VMResourceGroupName $vmResourceGroupName `
                -ExtensionType $daExt `
                -OperationStatus $OperationStatus
        }


        # Write-Output("`n")

    }
}

Write-Output("`nSummary:")
Write-Output("`nExtension not enabled: (" + $OperationStatus.ExtensionNotFound.Count + ")")
$OperationStatus.ExtensionNotFound  | ForEach-Object { Write-Output ($_) }
Write-Output("`nSucceeded: (" + $OperationStatus.Succeeded.Count + ")")
$OperationStatus.Succeeded | ForEach-Object { Write-Output ($_) }
Write-Output("`nNot running - start VM to configure: (" + $OperationStatus.NotRunning.Count + ")")
$OperationStatus.NotRunning  | ForEach-Object { Write-Output ($_) }
Write-Output("`nVM Scale Set needs update: (" + $OperationStatus.VMScaleSetNeedsUpdate.Count + ")")
$OperationStatus.VMScaleSetNeedsUpdate  | ForEach-Object { Write-Output ($_) }
Write-Output("`nVM Scale Set instances updated: (" + $OperationStatus.VMScaleSetInstancesUpdated.Count + ")")
$OperationStatus.VMScaleSetInstancesUpdated  | ForEach-Object { Write-Output ($_) }
Write-Output("`nFailed: (" + $OperationStatus.Failed.Count + ")")
$OperationStatus.Failed | ForEach-Object { Write-Output ($_) }
