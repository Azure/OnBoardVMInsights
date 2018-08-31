# Onboard VMs to VM Insights using Azure Policies - Private Preview

This readme gives steps on how to onboard VM's to VM Insights using Azure Policy. 

## Overview

Azure Policy makes it simple and manageable to govern your resources at scale.

We are introducing an initiative (a bundle of policies) that will enable VM Insights on Virtual Machines in the assigned scope. A scope in this context could be a Management Group, Subscription or Resource Group.

The policies under this initiative will do the following for new Windows or Linux VM (i.e. greenfield).
- Deploy
  - Log Analytics Agent
  - Dependency Agent
   
- Audit
  - Check for the OS in scope (listed here)

We are offering this as a custom initiative. To activate it for your tenant, the process requires: 
- Configure a Log Analytics Workspace using the steps listed [here](https://github.com/dougbrad/OnBoardVMInsights/blob/master/README.md)
- Import the initiative defintion to your tenant (at the Management Group or Subscription level)
- Assign the policy to the desired scope
- Review the compliance results

For more information on Azure Policy, see [Azure Policy Introduction](https://docs.microsoft.com/en-us/azure/azure-policy/azure-policy-introduction)

## Private Preview Notes

We depend on new and in development Policy features. To access these features, you must use [this URL](https://ms.portal.azure.com/?microsoft_azure_policy_remediation=true#blade/Microsoft_Azure_Policy/PolicyMenuBlade/Remediation) to access the Azure Policy UI in Azure Portal.

The remediation UI (for existing resources) is still in development, and it is expected to be feature complete by the middle of September. It can be used for basic operations including triggering remediation.

Let know us know any feedback and bugs observed regardless.

Known issues:
- You cannot trigger remediation from the Compliance view, you must use the remediation view.

## Steps To Use
We can organize the steps as follows:
- [Add the Policies and Initiative to your Subscription](#add-the-policies-and-initiative-to-your-subscription)
- [Assign the Policy](#assign-the-policy)

## Add the Policies and Initiative to your Subscription

To allow a preview of using the policies, we have provided a script [Add-VMInsightsPolicy.ps1](Add-VMInsightsPolicy.ps1) which adds the Policies and an Initiative to your subscription.

To quickly download the PowerShell script to your local system, run following:
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
        <Optional> Load the policies from a local folder instead of
        https://raw.githubusercontent.com/dougbrad/OnBoardVMInsights/Policy/Policy/

    -SubscriptionID <String>
        <Optional> SubscriptionID to add the Policies/Initiatives to

    -ManagementGroupID <String>
        <Optional> Management Group ID to add the Policies/Initiatives to

    -Approve [<SwitchParameter>]
        <Optional> Gives the approval to add the Policies/Initiatives without any prompt
```

Note: If you plan to assign the Initiative/Policy to multiple Subscriptions, the definitions must be stored in the Management Group that contains the Subscriptions you will assign the policy to. Therefore you must use the -ManagementGroupID parameter.

## Assign the Policy
After you run [Add-VMInsightsPolicy.ps1](Add-VMInsightsPolicy.ps1) script, the following Initiave and Policies will be added.

Enable VM Insights for VMs - Preview
- Deploy Log Analytics Agent for Windows VMs - Preview
- Deploy Log Analytics Agent for Linux VMs - Preview
- Deploy Dependency Agent for Windows VMs - Preview
- Deploy Dependency Agent for Linux VMs - Preview
- VMs not in OS scope of Log Analytics Agent deployment policy - Preview
- VMs not in OS scope of Dependency Agent deployment policy - Preview

Initiative Parameter:
- Log Analytice Workspace (The ResourceID if applying an assignment using PowerShell/CLI)

For VM's that are found as not-compliant from the audit policies "VMs not in OS scope..." the criteria of the deployment policy only includes VM's that are deployed from well-known Azure VM Images.
Check the documentation if the VM OS is supported or not, if it is and it is a well-known Azure VM Image that should be included, give us this feedback. If not, then you will need to duplicate the deployment policy, and update/modify it to make the image in scope.

A standalone optional policy will also be added:
- VM is configured for mismatched Log Analytics Workspace - Preview

This can be used to identify VM's that are already configured with the [Log Analytics VM Extension](https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/oms-windows), but that are configured for a different Workspace than intended (as indicated by the policy assignment).
This takes a parameter for the WorkspaceID.

During the Private Preview, you can only create the assignment through the Policy UI using this [this URL](https://ms.portal.azure.com/?microsoft_azure_policy_remediation=true#blade/Microsoft_Azure_Policy/PolicyMenuBlade/Remediation). For documentation on this, see [Quick Start - Assign a Policy - Portal](https://docs.microsoft.com/en-us/azure/azure-policy/assign-policy-definition)

## Known Issues / Up-coming Additions

Known Issues:
- The Policy "VM is configured for mismatched Log Analytics Workspace - Preview" gives Compliance results that include VM's that don't have the Log Analytics VM Extension installed.

Up-Coming Additions:
- We'll provide a script that takes the output of the "VMs is configured for mismatched Log Analytics Workspace" policy, and allows the ability to update the VM to use a different Workspace.

## Feedback Requested

### Data Sovereignty
When you assign the Initiative you provide a Subscription, and optional Resource Groups along with the Log Analytics Workspace.
If your VM's are located across different Azure regions, or are organized by Subscription and/or Resource Group, you can create multiple assignments to associate the VM's with Workspaces in the required regions for your organization's compliance.

Q: Does this meet your needs? Or is more control, such as a parameter, on the Initiative for the VM Locations required? (We want to use the minimal set of parameters to keep things simple for the most common usecases).

### VM Scale Sets
VM Scale Sets default to have an UpgradePolicy of Manual - which means if there is a change, like appling a VM extension, you have to 'Upgrade' each VM to get the change. 
When creating new VMSS - since our policy runs after creation - means customer must do this step themselves.

We are looking for feedback from users of VM Scale Sets - how can we improve this?

Q: Should the Policies for VM Scale Sets be in same Initiative as the VM Policies, or is the owner of the Scale Set different, so it should be separated into a different Initiative?

### Source for the Policies
Policy supports Built-In policies and Custom policies, and we need feedback on the delivery of the VM Insights policies.
- With Built-In policies they are somewhat discoverable from the Policy UI, and when the Policy is updated by Microsoft, you will automatically receive the update
- With Custom policies, customers create these themselves, such as by running the Add-VMInsightsPolicy.ps1 script. Customer can choose to sign up to see changes that are published through GitHub notifications, and can then decide to apply these updates themselves or not.

Let us know any feedback around this.

For any questions, to give feedback please email: AzMonOnboardAtScale@microsoft.com
