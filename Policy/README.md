# Onboard VMs to VM Insights using Azure Policies - Private Preview

This readme gives steps on how to On-Board VM's to VM Insights using Policy. 

## Overview

Azure Policy makes it simple and manageable to govern your resources at scale.

We are introducing an initiative (a bundle of policies) that will enable VM Insights on Virtual machines in the assigned scope. A scope in this contect could be management group, subscription or resource group.

The policies under this initiative will do the following for new Windows or Linux VM (greenfield)
- Deploy
  - Log Analytics Agent
  - Dependency Agent
   
- Audit
  - Check for the OS in scope (listed here)

We are offering this as custom initiative and to activate it for your tenant the process requires: 
- Configure Log Analytics workspace using steps [here](https://github.com/dougbrad/OnBoardVMInsights/blob/master/README.md)
- Import the initiative defintion to your tenant (at management group or subscription level)
- Assign the policy to the desired scope
- Review the compliance results

For more information on Policy, see [Azure Policy Introduction](https://docs.microsoft.com/en-us/azure/azure-policy/azure-policy-introduction)

## Private Preview Notes

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

    -ManagementGroupId <String>
        <Optional> Management Group Id to add the Policies/Initiatives to

    -Approve [<SwitchParameter>]
        <Optional> Gives the approval to add the Policies/Initiatives without any prompt
```

Note: If you plan to assign the initiative/policy to multiple subscriptions, the definitions must be stored in the management group that contains the subscriptions you will assign the policy to, use the -ManagementGroupId parameter.

## Assign the Policy
After you run Add-VMInsightsPolicy.ps1 the following Initiave and Policies will be added 

Enable VM Insights for VMs - Preview
- Deploy Log Analytics Agent for Windows VMs - Preview
- Deploy Log Analytics Agent for Linux VMs - Preview
- Deploy Dependency Agent for Windows VMs - Preview
- Deploy Dependency Agent for Linux VMs - Preview
- VMs not in OS scope of Log Analytics deployment policy - Preview
- VMs not in OS scope of Dependency Agent deployment policy - Preview

Initiative Parameter:
- Log Analytice Workspace (ResourceId if doing assignment from PowerShell/CLI)

For VM's that are found as not-compliant from the audit policies "VMs not in OS scope..."
The criteria of the deployment policy only includes VM's that are deployed from well-known Azure VM images.
Check documentation if the VM OS is supported or not, if it is and it is a well known VM that should be included, give us this feedback. If not then you'll need to duplicate the deployment policy, and update to make the image in scope.

A stand-alone optional policy will also be added:
- VM is configured for mismatched Log Analytics Workspace - Preview

This can be used to identify VM's that are already configured with Log Analytics VM extension, however that are configured for a different workspace than intended.
This takes a parameter of the Workspace Id

You can create a Policy Assignment either through Policy UI or PowerShell/CLI - see [Quick Start - Assign a Policy - Portal](https://docs.microsoft.com/en-us/azure/azure-policy/assign-policy-definition)

## Up-coming Additions
Up-coming is following Policies
- VM's with Log Analytics extension in failed state
- VM's with Dependency Agent extension in failed state

We'll also provide a script that takes output of "VMs is configured for mismatched Log Analytics Workspace" and allows to update VM to use a different workspace.

## Feedback Requested

### Data sovereignty
When you assign the Initiative you provide a Subscription, and optional Resource Groups along with the Log Analytics workspace.
If your VM's that are located across different Azure regions are organized by Subscription and/or Resource Group, you can create multiple assignments to associate the VM's with workspaces in required regions for your organizations compliance.

Does this meet needs? Or is more control such as a parameter on the Initiative for the VM Locations required? (we want the minimum set of parameters to keep things simple for the most common case)

### VM Scale Sets
VM Scale Sets default to have an UpgradePolicy of Manual - which means if there is a change like apply a VM extension, you have to 'Upgrade' each VM to get the change
When creating new VMSS - since our policy runs after creation - means customer must do this step themselves.

Looking for feedback from users of VM Scale Sets - how can we improve this?

Should the policies for VM Scale sets be in same initiative or the VM policies, or is the owner of the Scale Set different, so should be a different initiative?

### Source for the Policies
Policy supports Built-In policies and Custom Policies, and we need feedback on delivery of VM Insights policies.
- With Built-In policies they are somewhat discoverable from Policy UI, and when the Policy is updated by Microsoft, your automatically get the update
- With Custom policies, customer creates them themselves, such as by running Add-VMInsightsPolicy.ps1. Customer can sign up to see changes through GitHub notifications, and can decide to apply themselves.

Let know any feedback around this.

For any questions, to give feedback:
* email: AzMonOnboardAtScale@microsoft.com

