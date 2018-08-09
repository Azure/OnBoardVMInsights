# Configure VM's for VM Insights with Policy - Private Preview
For any questions, to give feedback:
* email: vminsights@microsoft.com

This readme gives steps on how to On-Board VM's to VM Insights using Policy

For more information on Policy, see [Azure Policy Introduction](https://docs.microsoft.com/en-us/azure/azure-policy/azure-policy-introduction)

Note:
- Currently Policy only supports configuring new VM's, support for existing VM's (Remediation feature) is coming mid September
- Also note - not sure if support for new VM's yet supported for non-Microsoft tenants, that is to be enabled soon, or we can have your tenant white-listed if you'd like to try this out now.

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
- Deploy Dependency Agent VM extension for Windows VMs - Preview
- Deploy Dependency Agent VM extension for Linux VMs - Preview
- Deploy Log Analytics VM extension for Windows VMs - Preview
- Deploy Log Analytics VM extension for Linux VMs - Preview

Initiative Parameter:
- Log Analytice Workspace (ResourceId if doing assignment from PowerShell/CLI)

You can create a Policy Assignment either through Policy UI or PowerShell/CLI - see [Quick Start - Assign a Policy - Portal](https://docs.microsoft.com/en-us/azure/azure-policy/assign-policy-definition)

## Up-coming Additions
Up-coming is following Initiative and Policies

VM Insights - VM Applicability - Preview
- VMs is configured for mismatched Log Analytics Workspace - Preview
- VMs with un-supported Log Analytics Operating System - Preview
- VMs with un-supported Dependency Agent Operating System - Preview

Iniative Parameter:
- Log Analytics WorkspaceId

We'll also provide a script that takes output of "VMs is configured for mismatched Log Analytics Workspace" and allows to update VM to use a different workspace.

## Feedback Requested

### Data sovereignty
We are assessing what is needed for Data sovereignty.
One proposal is to have a parameter 
- VMLocations (List of Locations/Regions the Policy will apply to – default to all locations )

Let know feedback if we should include this, or you believe is a rare case customer can handle through their own customization, or any other suggestion

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