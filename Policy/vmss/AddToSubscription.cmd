REM Temporary script to allow importing the vsmm policies to subscription using armclient (not PowerShell support for this format)

REM update to your subscription
set subscriptionId=60b79d74-f4e4-4867-b631-58a10650b71f

REM also update AzureMonitor_VMSS.json where subscription is hard-coded

# each policy in the initiative
armclient PUT "/subscriptions/%subscriptionId%/providers/Microsoft.Authorization/policyDefinitions/LogAnalyticsExtension_Windows_VMSS_Deploy?api-version=2018-05-01" @LogAnalyticsExtension_Windows_VMSS_Deploy.json
armclient PUT "/subscriptions/%subscriptionId%/providers/Microsoft.Authorization/policyDefinitions/LogAnalyticsExtension_Linux_VMSS_Deploy?api-version=2018-05-01" @LogAnalyticsExtension_Linux_VMSS_Deploy.json
armclient PUT "/subscriptions/%subscriptionId%/providers/Microsoft.Authorization/policyDefinitions/DependencyAgentExtension_Windows_VMSS_Deploy?api-version=2018-05-01" @DependencyAgentExtension_Windows_VMSS_Deploy.json
armclient PUT "/subscriptions/%subscriptionId%/providers/Microsoft.Authorization/policyDefinitions/DependencyAgentExtension_Linux_VMSS_Deploy?api-version=2018-05-01" @DependencyAgentExtension_Linux_VMSS_Deploy.json
armclient PUT "/subscriptions/%subscriptionId%/providers/Microsoft.Authorization/policyDefinitions/LogAnalytics_OSImage_VMSS_Audit?api-version=2018-05-01" @LogAnalytics_OSImage_VMSS_Audit.json
armclient PUT "/subscriptions/%subscriptionId%/providers/Microsoft.Authorization/policyDefinitions/DependencyAgent_OSImage_VMSS_Audit?api-version=2018-05-01" @DependencyAgent_OSImage_VMSS_Audit.json

# the Initiative
armclient PUT "/subscriptions/%subscriptionId%/providers/Microsoft.Authorization/policySetDefinitions/AzureMonitor_VMSS?api-version=2018-05-01" @AzureMonitor_VMSS.json

# stand-alone mismatch policy
armclient PUT "/subscriptions/%subscriptionId%/providers/Microsoft.Authorization/policyDefinitions/LogAnalytics_WorkspaceMismatch_VMSS_Audit?api-version=2018-05-01" @LogAnalytics_WorkspaceMismatch_VMSS_Audit.json