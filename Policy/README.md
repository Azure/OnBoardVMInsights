# Configure VM's for VM Insights with Policy - Private Preview
For any questions, to give feedback:
* email: vminsights@microsoft.com

This readme gives steps on how to On-Board VM's to VM Insights using Policy
For more information on Policy, see [Azure Policy Introduction](https://docs.microsoft.com/en-us/azure/azure-policy/azure-policy-introduction)

Note:
- Currently Policy only supports configuring new VM's, support for existing VM's (Remediation feature) is coming mid September
- Also note - not sure if support for new VM's yet supported for non-Microsoft tenants, that is to be enabled soon.

To allow a preview of using policy, we have provided a script [Add-VMInsightsPolicy.ps1](Add-VMInsightsPolicy.ps1) which adds the Policies and an Initiative to your subscription.

To quickly download the powershell to your local filesystem, run following:
```powershell
$client = new-object System.Net.WebClient
$client.DownloadFile(“https://raw.githubusercontent.com/dougbrad/OnBoardVMInsights/Policy/Policy/Add-VMInsightsPolicy.ps1”,“Enable-VMInsightsPerfCounters.ps1”) 
``` 

You can run it as follows:
```powershell
.\Add-VMInsightsPolicy.ps1
```
There is one optional parameter which can be used to load the polices from the local folder you run script from instead of our github:
```powershell
-UseLocalPolicies
```

Once this is added to your subscription, you can create a Policy Assignment - see [Quick Start - Assign a Policy - Portal](https://docs.microsoft.com/en-us/azure/azure-policy/assign-policy-definition)