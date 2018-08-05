[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(mandatory = $true)][string]$WorkspaceName,
    [Parameter(mandatory = $true)][string]$WorkspaceResourceGroupName,
    [Parameter(mandatory = $true)][string]$WorkspaceSubscriptionId,
    [Parameter(mandatory = $true)][int]$Interval
)

# Ensure authentication and select the subscription
$account = Get-AzureRmContext
if ($null -eq $account.Account) {
    Write-Output("Account Context not found, please login")
    Login-AzureRmAccount -subscriptionid $WorkspaceSubscriptionId
}
else {
    if ($account.Subscription.Id -eq $WorkspaceSubscriptionId) {
        Write-Verbose("Subscription: $WorkspaceSubscriptionId is already selected.")
        $account
    }
    else {
        Write-Output("Current Subscription:")
        $account
        Write-Output("Changing to subscription: $WorkspaceSubscriptionId")
        Select-AzureRmSubscription -SubscriptionId $WorkspaceSubscriptionId
    }
}

# Get all counters
$windowsCounters = Get-AzureRmOperationalInsightsDataSource -WorkspaceName $WorkspaceName -ResourceGroupName $WorkspaceResourceGroupName -Kind WindowsPerformanceCounter
$linuxCounters = Get-AzureRmOperationalInsightsDataSource -WorkspaceName $WorkspaceName -ResourceGroupName $WorkspaceResourceGroupName -Kind LinuxPerformanceObject
$counters = $windowsCounters + $linuxCounters

# Update each counter
foreach ($counter in $counters) {
	$existingInterval = $counter.Properties.intervalSeconds
	if ($existingInterval -eq $Interval) {
		Write-Output "Counter $($counter.Name) is already configured with interval of $Interval seconds"
	}
	else {
		$counter.Properties.intervalSeconds = $Interval
		Set-AzureRmOperationalInsightsDataSource -DataSource $counter
		Write-Output "Counter $($counter.Name) interval changed from $existingInterval to $Interval seconds"
	}
}