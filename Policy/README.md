# Configure VM's for VM Insights with Policy - Private Preview
For any questions, to give feedback:
* email: AzMonOnboardAtScale@microsoft.com

This readme gives steps on how to On-Board VM's to VM Insights using Policy.

Workspace configuration should still be done using steps [here](..\readme.md)

For more information on Policy, see [Azure Policy Introduction](https://docs.microsoft.com/en-us/azure/azure-policy/azure-policy-introduction)

Note:
- Support for deployIfNotExists policies which this uses is not yet enabled for all tenants, email us and we can have your tenant white-listed
- Currently Policy only supports configuring new VM's, support for existing VM's (Remediation feature) is coming mid September


We can organize steps as follows:
- [Add the Policies amd Initiative to your Subscription](#add-the-policies-and-initiative-to-your-subscription)
- [Assign the Policy](#assign-the-policy)

## Add the Policies and Initiative to your Subscription

To allow a preview of using policy, we have provided a script [Add-VMInsightsPolicy.ps1](Add-VMInsightsPolicy.ps1) which adds the Policies and an Initiative to your subscription.

To quickly download the powershell to your local filesystem, run following:
```powershell
$client = new-object System.Net.WebClient
$client.DownloadFile(“https://raw.githubusercontent.com/dougbrad/OnBoardVMInsights/Policy/Policy/Add-VMInsightsPolicy.ps1”,“Add-VMInsightsPolicy.ps1”) 
``` 

You can run it as follows:
```powershell
.\Add-VMInsightsPolicy.ps1
```
The script also has these optional parameters:
```powershell
    -UseLocalPolicies [<SwitchParameter>]
        <Optional> Load the policies from local folder instead of
        https://raw.githubusercontent.com/dougbrad/OnBoardVMInsights/Policy/Policy/

    -SubscriptionId <String>
        <Optional> SubscriptionId to add the Policies/Initiatives to

    -Approve [<SwitchParameter>]
        <Optional> Gives the approval to add the Policies/Initiatives without any prompt
```

Note: If you plan to apply policies to multiple subscriptions, the definitions must be stored in the management group that contains the subscriptions you will assign the policy to.
Currently Add-VMInsightsPolicy.ps1 does not support adding to a management group, this will be added in the future. 

## Assign the Policy
After you run Add-VMInsightsPolicy.ps1 the following Initiave and Policies will be added 

Enable VM Insights for VMs - Preview
- Deploy Log Analytics Agent for Windows VMs - Preview
- Deploy Log Analytics Agent for Linux VMs - Preview
- Deploy Dependency Agent for Windows VMs - Preview
- Deploy Dependency Agent for Linux VMs - Preview

Initiative Parameter:
- Log Analytice Workspace (ResourceId if doing assignment from PowerShell/CLI)

A stand-alone optional policy will also be added:
- VM is configured for mismatched Log Analytics Workspace - Preview
This can be used to identify VM's that are already configured with Log Analytics VM extension, however that are configured for a different workspace than intended.
This takes a parameter of the Workspace Id

You can create a Policy Assignment either through Policy UI or PowerShell/CLI - see [Quick Start - Assign a Policy - Portal](https://docs.microsoft.com/en-us/azure/azure-policy/assign-policy-definition)

## Up-coming Additions
Up-coming is following Policies
- VM's not in OS scope of Log Analytics deployment policy
- VM's not in OS scope of Dependency Agent deployment policy
- VM's with Log Analytics extension in failed state
- VM's with Dependency Agent extension in failed state

We'll also provide a script that takes output of "VMs is configured for mismatched Log Analytics Workspace" and allows to update VM to use a different workspace.

## Feedback Requested

### Data sovereignty
When you assign the Initiative you provide a Subscription, and optional Resource Groups along with the Log Analytics workspace.
If your VM's that are located across different Azure regions are organized by Subscription and/or Resource Group, you can create multiple assignments to associate the VM's with workspaces in required regions for your organizations compliance.

Does this meet needs? Or is more control such as a parameter on the Initiative for the VM Locations required? (we want the minimum set of parameters to keep things simple for the most common case)

### VM Scale Sets
We want to discuss needs of users of VM Scale Sets, is there a need for us to supply policies?
VM Scale Sets default to have an UpgradePolicy of Manual - which means if there is a change like apply a VM extension, you have to 'Upgrade' each VM to get the change
When creating new VMSS - since our policy runs after creation - means customer must do this step themselves.

Looking for feedback from users of VM Scale Sets

### Source for the Policies
Policy supports Built-In policies and Custom Policies, and we need feedback on delivery of VM Insights policies.
- With Built-In policies they are somewhat discoverable from Policy UI, and when the Policy is updated by Microsoft, your automatically get the update
- With Custom policies, customer creates them themselves, such as by running Add-VMInsightsPolicy.ps1. Customer can sign up to see changes through GitHub notifications, and can decide to apply themselves.

Let know any feedback around this.