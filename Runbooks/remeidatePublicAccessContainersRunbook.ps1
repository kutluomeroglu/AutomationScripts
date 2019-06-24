[OutputType("PSAzureOperationResponse")]
param
(
    [Parameter (Mandatory=$false)]
    [object] $WebhookData
)
$ErrorActionPreference = "stop"

Import-Module Az.Accounts -Force
Import-Module Az.Storage -Force

if ($WebhookData)
{
    # Get the data object from WebhookData
    $WebhookBody = (ConvertFrom-Json -InputObject $WebhookData.RequestBody)

    # Get the info needed to identify the VM (depends on the payload schema)
    $schemaId = $WebhookBody.schemaId
    Write-Verbose "schemaId: $schemaId" -Verbose
    if ($schemaId -eq "azureMonitorCommonAlertSchema") {
        # This is the common Metric Alert schema (released March 2019)
        $Essentials = [object] ($WebhookBody.data).essentials
        # Get the first target only as this script doesn't handle multiple
        $alertTargetIdArray = (($Essentials.alertTargetIds)[0]).Split("/")
        $SubId = ($alertTargetIdArray)[2]
        $ResourceGroupName = ($alertTargetIdArray)[4]
        $ResourceType = ($alertTargetIdArray)[6] + "/" + ($alertTargetIdArray)[7]
        $ResourceName = ($alertTargetIdArray)[-1]
        #region Mycode
        $index = $alertTargetIdArray.IndexOf('storageaccounts')
        $stAccountNameIndex = $index + 1
        $stAccountName =  $alertTargetIdArray[$stAccountNameIndex]
        Write-Verbose "Storage account name is: $stAccountName" -Verbose
        #endregion
        $status = $Essentials.monitorCondition
    }
    else {
        # Schema not supported
        Write-Error "The alert data schema - $schemaId - is not supported. Alert must be in common alert schema."
    }

    Write-Verbose "status: $status" -Verbose
    if (($status -eq "Activated") -or ($status -eq "Fired"))
    {
        Write-Verbose "resourceType: $ResourceType" -Verbose
        Write-Verbose "resourceName: $ResourceName" -Verbose
        Write-Verbose "resourceGroupName: $ResourceGroupName" -Verbose
        Write-Verbose "subscriptionId: $SubId" -Verbose

        # Determine code path depending on the resourceType
        if ($ResourceType -eq "microsoft.storage/storageaccounts")
        {
            # This is a storage account
            Write-Verbose "It is the expected resource type!" -Verbose
            
            # Authenticate to Azure with service principal and certificate and set subscription
            Write-Verbose "Authenticating to Azure with service principal and certificate" -Verbose

            <#This code section uses the run as acconection
            Write-Verbose "Authenticating to Azure with service principal and certificate" -Verbose
            $ConnectionAssetName = "AzureRunAsConnection"
            Write-Verbose "Get connection asset: $ConnectionAssetName" -Verbose
            $Conn = Get-AutomationConnection -Name $ConnectionAssetName
            if ($Conn -eq $null)
            {
                throw "Could not retrieve connection asset: $ConnectionAssetName. Check that this asset exists in the Automation account."
            }
            Write-Verbose "Authenticating to Azure with service principal." -Verbose
            Connect-AzAccount -ServicePrincipal -Tenant $Conn.TenantID -ApplicationId $Conn.ApplicationID -CertificateThumbprint $Conn.CertificateThumbprint | Write-Verbose
            #>
            
            <#This section uses service principal authentication#>

            Write-Host "Getting credential information from automation account"
            $cred = Get-AutomationPSCredential -Name 'RemediationSP'
            $tenantId = Get-AutomationVariable -Name 'TenantId'
            Write-Host "Start login with SPN"
            Connect-AzAccount -Credential $cred -ServicePrincipal -TenantId $tenantId
            

            #region Mycode
            $storageAccountContext = (Get-AzStorageAccount -Name $stAccountName -ResourceGroupName $ResourceGroupName).Context
            $containerPermission = (Get-AzStorageContainer -Context $storageAccountContext -Name $ResourceName).PublicAccess

            Write-Verbose "Getting Azure token"
            $azContext = Get-AzContext
            $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
            $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
            $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'='Bearer ' + $token.AccessToken
            }
            Write-Verbose "Got Token"

            if ( $containerPermission -ne "Off" ) {
                Write-Verbose "Storage account permissions is set to: $containerPermission, setting the permission to Off"
                Set-AzStorageContainerAcl -Context $storageAccountContext -Name $ResourceName -Permission Off
                Write-Verbose "Container permission set to off"
            }
            else {
                Write-Verbose "Storage account permission is Off."
            }

            Write-Verbose "Getting alert id"
            $alertId = ($Essentials.alertId.Split('/'))[-1]
            Write-Verbose "Changing alert state to closed"
            $uri = "https://management.azure.com/subscriptions/$SubId/providers/Microsoft.AlertsManagement/alerts/$alertId/changestate?api-version=2018-05-05&newState=Closed"
            Invoke-WebRequest -Headers $authHeader -Uri $uri -Method Post -UseBasicParsing
            Write-Verbose "Alert was closed"
            #endregion

            # [OutputType(PSAzureOperationResponse")]
        }
        else {
            # ResourceType not supported
            Write-Error "$ResourceType is not a supported resource type for this runbook."
        }
    }
    else {
        # The alert status was not 'Activated' or 'Fired' so no action taken
        Write-Verbose ("No action taken. Alert status: " + $status) -Verbose
    }
}
else {
    # Error
    Write-Error "This runbook is meant to be started from an Azure alert webhook only."
}