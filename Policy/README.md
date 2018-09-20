# Enable Azure Monitor for VMs using Azure Policy (Preview)

This readme gives steps on how to onboard VM's to VM Insights using Azure Policy. 

## Overview

Azure Policy makes it simple and manageable to govern your resources at scale.

We are providing an initiative (a bundle of policies) that will enable VM Insights on Virtual Machines in the assigned scope. A scope in this context could be a Management Group, Subscription or Resource Group.

The policies under this initiative will do the following for new Windows or Linux VM (i.e. greenfield), and allow you to use the Policy Remediation feature to trigger for existing VM's.
- Deploy
  - Log Analytics Agent
  - Dependency Agent
   
- Audit
  - Check for the OS in scope (listed here)

This is available as both:
- Built-In initiative, you can assign from [Azure Policy service](https://ms.portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyMenuBlade/Definitions) in Azure Portal
- Custom initiative from git-hub, in case you need to customize, for example to target additional OS images or target based on tags.

A high level of the steps to use are:
- Configure a Log Analytics Workspace using the steps listed [here](https://github.com/dougbrad/OnBoardVMInsights/blob/master/README.md)
- Assign the initiative to the desired scope
- Review the compliance results

For more information on Azure Policy, see [Azure Policy Introduction](https://docs.microsoft.com/en-us/azure/azure-policy/azure-policy-introduction)

## Assign the Built-In Initiative
For documentation on assigning policies, see [Quick Start - Assign a Policy - Portal](https://docs.microsoft.com/en-us/azure/azure-policy/assign-policy-definition)

The Initiative to assign is: "[Preview]: Enable Azure Monitor for VMs"

For example:
- Go to 'Definitions', in the search filter, enter this name.
- Click the Initiative
- Click 'Assign'
- Configure the 'Scope'
- Configure the parameter 'Log Analytics workspace' using the UI to pick the workspace (this is the Resource Id fo the workspace, if assigning from command line / powershell)

If you would like to audit to find VM's using Log Analytics agent configured for a mismatched workspace, assign this policy:
- [Preview]: Audit Log Analytics Workspace for VM - Report Mismatch
This takes a parameter of the Workspace Id (GUID).


This can be used to identify VM's that are already configured with the [Log Analytics VM Extension](https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/oms-windows), but that are configured for a different Workspace than intended (as indicated by the policy assignment).
This takes a parameter for the WorkspaceID.

## Review the compliance results

The Initiative "[Preview]: Enable Azure Monitor for VMs" contains following policies:
- [Preview]: Deploy Log Analytics Agent for Windows VMs
- [Preview]: Deploy Log Analytics Agent for Linux VMs
- [Preview]: Deploy Dependency Agent for Windows VMs
- [Preview]: Deploy Dependency Agent for Linux VMs
- [Preview]: Audit Log Analytics Agent Deployment – VM Image (OS) unlisted
- [Preview]: Audit Dependency Agent Deployment – VM Image (OS) unlisted

For VM's that are found as not-compliant from the audit policies "Audit ... Agent Deployment - VM Image (OS) unlisted" the criteria of the deployment policy only includes VM's that are deployed from well-known Azure VM Images.
Check the documentation if the VM OS is supported or not, if it is and it is a well-known Azure VM Image that should be included, give us this feedback. If not, then you will need to duplicate the deployment policy or import from github [Using as Custom Policies], and update/modify it to make the image in scope.

For Policy "[Preview]: Audit Log Analytics Workspace for VM - Report Mismatch" the non-compliant resources can be used as an input to the Install-VMInsights.ps1 script through the -PolicyAssignmentName in order to move a VM from the mistmatched workspace to the expected one.

## Using as Custom Policies

If you need to Customize the Policies, for example add additional OS images supported, or new criterias such as by 'tags', then you can modify the policy we publish to Github and import to your subscription.

The Initiative and Policies are here: (to be moved to Azure Policy Samples Github)
https://github.com/dougbrad/OnBoardVMInsights/tree/master/Policy

You can branch off of these, and make any changes you need.

We have provided a script [Add-VMInsightsPolicy.ps1](Add-VMInsightsPolicy.ps1) which adds the Policies and an Initiative to your subscription or management group.

To quickly download the PowerShell script to your local system, run following:
```powershell
$client = new-object System.Net.WebClient
$client.DownloadFile(“https://raw.githubusercontent.com/dougbrad/OnBoardVMInsights/master/Policy/Add-VMInsightsPolicy.ps1”,“Add-VMInsightsPolicy.ps1”)
``` 

You can run it as follows:
```powershell
.\Add-VMInsightsPolicy.ps1
```
The script also has these optional parameters:
```powershell
    -UseLocalPolicies [<SwitchParameter>]
        <Optional> Load the policies from a local folder instead of
        https://github.com/dougbrad/OnBoardVMInsights/tree/master/Policy

    -SubscriptionId <String>
        <Optional> SubscriptionId to add the Policies/Initiatives to

    -ManagementGroupId <String>
        <Optional> Management Group Id to add the Policies/Initiatives to

    -Approve [<SwitchParameter>]
        <Optional> Gives the approval to add the Policies/Initiatives without any prompt
```

Note: If you plan to assign the Initiative/Policy to multiple Subscriptions, the definitions must be stored in the Management Group that contains the Subscriptions you will assign the policy to. Therefore you must use the -ManagementGroupID parameter.


For any questions, to give feedback please email: AzMonOnboardAtScale@microsoft.com
