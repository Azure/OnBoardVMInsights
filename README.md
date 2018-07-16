# On-Boarding for VM Insights
This document gives steps on how to On-Board to VM Insights using scripts and ARM templates.

We can organize steps as follows:
- [Log Analytics Workspace setup](#Log-Analytics-Workspace-setup)
- [Per VM, VM Scale Set setup](#Per-VM,-VM-Scale-Set-setup)

For details on VM Insights, included supported VM operating systems and regions, see < TODO: Add Link >
## Log Analytics Workspace setup
If you have already configured a single VM for VM Insights through UI experience, then these steps will already have been taken care of for you and you can move on to enabling for more VM's.

Summary of steps:
- Create a Log Analytics workspace in a supported region 
- Install the ServiceMap and InfrastructureInsights Solutions
- Configure the workspace to collect performance counters

#### Create a Log Analytics workspace in a supported region
< TODO: Add link to detailed documentation on regions supported and steps to create a workspace >

#### Install the ServiceMap and InfrastructureInsights Solutions
We have provided an ARM template [InstallSolutionsForVMInsights.json](.\InstallSolutionsForVMInsights.json) that will deploy the ServiceMap and InfrastructureInsights solutions to your Log Analytics workspace.

You can find information on how to deploy ARM templates [here](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-template-deploy)
Example of deploying with PowerShell:
```powershell
New-AzureRmResourceGroupDeployment -Name DeploySolutions -TemplateFile InstallSolutionsForVMInsights.json -ResourceGroupName <workspace resource group name> -WorkspaceName <workspace name> -WorkspaceLocation <workspace location- example: eastus>
```

You can also deploy directly from Azure Portal using this [link](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fdougbrad%2Fmaster%2FOnBoardVMInsights%2FInstallSolutionsForVMInsights.json)
#### Configure the workspace to collect performance counters

TODO: Update with script to enable performance counter collection

## Per VM, VM Scale Set setup

On each VM or VM Scale Set the following is needed
- Log Analytics VM Extension pointing to a supported workspace
- Dependency Agent VM Extension

For the current iteration, we are providing a script [Install-VMInsights.ps1](Install-VMInsights.ps1) to accomplish this.

This script will iterate through VM's and VM Scale sets in a Subcription, or further scoped by ResourceGroup or Name.
For each VM or VM ScaleSet it will check the currently installed VM extensions and install if needed.

You can run Get-Help to get details and an example of usage:

```powershell
Get-Help .\EnableVMsForVMInsights.ps1 -Detailed

SYNOPSIS
    Configure VM's and VM Scale Sets for VM Insights:
    - Installs Log Analytics VM Extension configured to supplied Log Analytics Workspace
    - Installs Dependency Agent VM Extension

    Can be applied to:
    - Subscription
    - Resource Group in a Subscription
    - Specific VM/VM Scale Set

    Script will show you list of VM's/VM Scale Sets that will apply to and let you confirm to continue.
    Use -Approve switch to run without prompting, if all required parameters are provided.

    If the extensions is already installed will not install again.
    Use -ReInstall switch if you need to for example update the workspace.

    Use -WhatIf if you would like to see what would happen in terms of installs, what workspace configured to, and status of the
    extension.

SYNTAX
    D:\GitHub\OnBoardVMInsights\EnableVMsForVMInsights.ps1 [-WorkspaceId] <String> [-WorkspaceKey] <String> [-SubscriptionId]
    <String> [[-ResourceGroup] <String>] [[-Name] <String>] [-ReInstall] [-TriggerVmssManualVMUpdate] [-Approve] [-WhatIf]
    [-Confirm] [<CommonParameters>]

PARAMETERS
    -WorkspaceId <String>
        Log Analytics WorkspaceID (GUID) for the data to be sent to

    -WorkspaceKey <String>
        Log Analytics Workspace primary or secondary key

    -SubscriptionId <String>
        SubscriptionId for the VMs/VM Scale Sets

    -ResourceGroup <String>
        <Optional> Resource Group to which the VMs or VM Scale Sets belong to

    -Name <String>
        <Optional> To install to a single VM/VM Scale Set

    -ReInstall [<SwitchParameter>]
        <Optional> If VM/VM Scale Set is already configured for a different workspace, set this to change to the
        new workspace

    -TriggerVmssManualVMUpdate [<SwitchParameter>]
        <Optional> Set this flag to trigger update of VM instances in a scale set whose upgrade policy is set to
        Manual

    -Approve [<SwitchParameter>]
        <Optional> Gives the approval for the installation to start with no confirmation prompt for the listed VM's/VM Scale Sets

    -WhatIf [<SwitchParameter>]
        <Optional> See what would happen in terms of installs.
        If extension is already installed will show what workspace is currently configured, and status of the VM
        extension

    -Confirm [<SwitchParameter>]
        <Optional> Confirm every action

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).

    -------------------------- EXAMPLE 1 --------------------------

    .\Install-VMInsights.ps1 -WorkspaceId <WorkspaceId>-WorkspaceKey <WorkspaceKey> -SubscriptionId
    <SubscriptionId> -ResourceGroup <ResourceGroup>        
```

Example of running:

```powershell
$WorkspaceId = "<GUID>"
$WorkspaceKey = "<Key>"
$SubscriptionId = "<GUID>"
.\Install-VMInsights.ps1 -WorkspaceId $WorkspaceId -WorkspaceKey $WorkspaceKey -SubscriptionId $SubscriptionId -ResourceGroup db-ws

Getting list of VM's or VM ScaleSets matching criteria specified

VM's or VM ScaleSets matching criteria:

db-ws-1 VM running
db-ws2012 VM running

This operation will install the Log Analytics and Dependency Agent extensions on above 2 VM's or VM Scale Sets.
VM's in a non-running state will be skipped.
Extension will not be re-installed if already installed. Use /ReInstall if desired, for example to update workspace

Confirm
Continue?
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): y

db-ws-1 : Deploying DependencyAgentWindows with name DAExtension
db-ws-1 : Successfully deployed DependencyAgentWindows
db-ws-1 : Deploying MicrosoftMonitoringAgent with name MMAExtension
db-ws-1 : Successfully deployed MicrosoftMonitoringAgent
db-ws2012 : Deploying DependencyAgentWindows with name DAExtension
db-ws2012 : Successfully deployed DependencyAgentWindows
db-ws2012 : Deploying MicrosoftMonitoringAgent with name MMAExtension
db-ws2012 : Successfully deployed MicrosoftMonitoringAgent

Summary:

Already Onboarded: (0)

Succeeded: (4)
db-ws-1 : Successfully deployed DependencyAgentWindows
db-ws-1 : Successfully deployed MicrosoftMonitoringAgent
db-ws2012 : Successfully deployed DependencyAgentWindows
db-ws2012 : Successfully deployed MicrosoftMonitoringAgent

Connected to different workspace: (0)

Not running - start VM to configure: (0)

Failed: (0)

