#Creating logging directory and file for debugging purposes. If logging file already exists, it will empty it accordignly for a new run.
$Path = 'C:\X\Sentia\'
$LogFile = "DeployLogging.log"
$LogPath = $Path + '\' + $Logfile
If (!([System.IO.Directory]::Exists($Path)) -or (![System.IO.File]::Exists($Path + '\' + $LogFile))) {

      New-Item -ItemType Directory -Path (($Path).Split('\')[0] + '\' + ($Path).Split('\')[1]) -Name Sentia -ErrorAction SilentlyContinue | Out-Null;
      New-Item -ItemType File -Path $Path -Name $LogFile -ErrorAction SilentlyContinue | Out-Null}
 
Else {[System.IO.File]::WriteAllText($LogPath, $null)}

Write-Output "$(Get-TimeStamp): Logfile succesfully created" | Out-File $LogPath -Append

# We want to abort further processing upon an error, and debug it accordingly.
$ErrorActionPreference = "Stop"

#Creating timestamp function for further processing during debugging. Variables aren't dynamic unless assigned, and will report a static timestamp, hence the function.
function Get-TimeStamp {
    
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    
}

Function Deploy-AzureVM {
    [cmdletbinding()]

    Param 
    (
        #Restricting location following new GDPR
        [Parameter(Mandatory=$True, Position="0", HelpMessage="Location where the resources will be deployed.")]
        [ValidateSet("West Europe", "Alternative_Location")]
        [string]$Location,

        [Parameter(Mandatory=$True, HelpMessage="Specify the username of the Azure account deploying the resource group upon.")]
        [string]$AzureUserName,

        [Parameter(Mandatory=$True, HelpMessage="Specify the local path to the local password file. It should contain a secure string, not plain text.")]
        [String]$AzurePasswordFilePath,

        [Parameter(Mandatory=$True, HelpMessage="Specify the local path to the local admin password file for the VM. It should contain plain text.")]
        [String]$LocalAdminPasswordPath,

        [Parameter(Mandatory=$True, HelpMessage="Specify a vaultname to store the local admin password into.")]
        [string]$VaultName,

        [Parameter(Mandatory=$True, HelpMessage="Specify the name of the secret that will be created.")]
        [string]$SecretName,

        [Parameter(Mandatory=$True, HelpMessage="Specify the name of the resourcegroup where to deploy the resources to. It will create the resourcegroup if not present already.")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$True, HelpMessage="Specify the deployment mode. Default value is 'incremental'.")]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$DeploymentMode,

        [Parameter(Mandatory=$True, HelpMessage="Name of the deployment.")]
        [string]$DeploymentName,

        [Parameter(Mandatory=$True, HelpMessage="Subscription ID to deploy the resources.")]
        [string]$SubscriptionID,

        [Parameter(Mandatory=$True, HelpMessage="Tenant ID to connect to.")]
        [string]$TenantID,

        [Parameter(Mandatory=$True, HelpMessage="Local path to the JSON template file.")]
        [string]$JSONTemplateFilePath,

        [Parameter(Mandatory=$True, HelpMessage="Local path to the JSON parameter file.")]
        [string]$JSONParameterFilePath,

        [Parameter(Mandatory=$True, HelpMessage="Tag which will be attached to the resourcegroup.")]
        [Hashtable]$ResourceGroupTag,

        [Parameter(HelpMessage="Specify the restriction policy name")]
        [string]$PolicyName,

        [Parameter(HelpMessage="Specify the displayname of the new policy.")]
        [string]$PolicyDisplayName,

        [Parameter(HelpMessage="Specify the restriction policy description.")]
        [string]$PolicyDescription,

        [Parameter(HelpMessage="Specify the local path to the policy JSON template file.")]
        [string]$PolicyTemplateFilePath,

        [Parameter(HelpMessage="Specify the local path to the policy JSON template parameter file.")]
        [string]$PolicyParameterFilePath,

        [Parameter(HelpMessage="Specify the path to the parameter definition JSON file.")]
        [string]$PolicyParameterDefinitionFilePath

    )

    # Declaring  the deploymentmode if the value is empty. This is to not delete existing resources.
    If ($DeploymentMode -eq $null) {

        $DeploymentMode = "Incremental"
    }

    # Creating the credentials object. Trapping the error, adding to the logging if applicable.
    Try 
    {
        $Password = Get-Content -Path $($AzurePasswordFilePath) | ConvertTo-SecureString 
        $Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($AzureUserName, $Password)
    }

    Catch 
    {
        $ErrorMessage = $_.Exception.Message
        Write-Output "$(Get-TimeStamp): $ErrorMessage" | Out-File $LogPath -Append
        $ErrorMessage = $null
    }

    # Attempting to log into our Azure accont. Storing it into a variable to prevent unwanted output. Variable will be emptied for security reasons.
    Try
    {
        $result = Connect-AzureRmAccount -Credential $Cred -Subscription $SubscriptionID -TenantId $TenantID
    }

    Catch 
    {
        $ErrorMessage = $_.Exception.Message
        Write-Output "$(Get-TimeStamp): $ErrorMessage" | Out-File $LogPath -Append
        $ErrorMessage = $null
    }

    Finally 
    {
        $result = $null
    }

    #Creating a resource group. Location in West Europe due to GDPR.
    $ResourceGroupExists = Get-AzureRmResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue

    If (!($ResourceGroupExists)) {

        Try 
        {
            New-AzureRmResourceGroup -Name $ResourceGroupName  `
                                     -Location $Location `
                                     -Tag $ResourceGroupTag `
                                     -Verbose -Force
        }

        Catch 
        {
            $ErrorMessage = $_.Exception.Message
            Write-Output "$(Get-TimeStamp): $ErrorMessage" | Out-File $LogPath -Append
            $ErrorMessage = $null
        }
    }
        
    # Assign the Resource Group to a variable for further processing.
    $ResourceGroup = Get-AzureRmResourceGroup -Name $ResourceGroupName

    # Processing empty or missing entrys regarding the policy.
    [int]$IsNull = '0'
    If ($PolicyName -eq $null) {$IsNull ++}
    If ($PolicyDescription -eq $null) {$IsNull ++}
    If ($PolicyTemplateFilePath -eq $null) {$IsNull ++}
    If ($PolicyParameterFilePath -eq $null) {$IsNull ++}
    If ($PolicyParameterDefinitionFilePath -eq $null) {$IsNull ++}
#   $IsNull = "5" #TO-DO!!!! <--- I Disabled the policy by defining '5' as $IsNull var for the azure key-vault to be added into the RG. Even after adding the keyvault provider in the policy, it doesn't seem to work...
    If ($IsNull -eq "0") {
        
        Try 
        {
            #Registering resource provider for the policy
            Register-AzureRmResourceProvider -ProviderNamespace 'Microsoft.PolicyInsights'

            # Creating policy definition to restrict allowed resource types.
            $Definition = New-AzureRmPolicyDefinition -Name $($PolicyName) `
                                                      -DisplayName $($PolicyDisplayname) `
                                                      -Description $($PolicyDescription) `
                                                      -Policy $($PolicyTemplateFilePath)`
                                                      -Parameter $($PolicyParameterFilePath) `
        }

        Catch
        {
            $ErrorMessage = $_.Exception.Message
            Write-Output "$(Get-TimeStamp): $ErrorMessage" | Out-File $LogPath -Append
            $ErrorMessage = $null
        }

        Try
        {
            # Assigning policy to our new resourcegroup. 
            New-AzureRmPolicyAssignment -Name $PolicyName -Scope $ResourceGroup.ResourceId -PolicyDefinition $Definition -PolicyParameter $PolicyParameterDefinitionFilePath
        }

        Catch
        {
            $ErrorMessage = $_.Exception.Message
            Write-Output "$(Get-TimeStamp): $ErrorMessage" | Out-File $LogPath -Append
            $ErrorMessage = $null
        }
    }

    ElseIf (($IsNull -gt '0') -and ($IsNull -ne "5")) {
        
        Write-Output "$(Get-TimeStamp): Detected missing entries. Please check for missing information. Aborting script" | Out-File -FilePath $LogPath -Append; break
    }

    ElseIf ($IsNull -eq "5") {
        
        Write-Output "$(Get-TimeStamp): Detected no entrys for policy definition. Continuing without policy definition." | Out-File -FilePath $LogPath -Append
    }

    # Checking if the vault already exists, if not, we will create one. Otherwise the key will be stored in the existing vault anyway.
    $VaultExists = Get-AzureRmKeyVault -VaultName $VaultName

    If (!($VaultExists)) {
        
        Try
        {
            New-AzureRmKeyVault -Name $VaultName.ToString() -ResourceGroupName $ResourceGroupName -Location $Location -EnabledForTemplateDeployment:$True
            Write-Output "$(Get-TimeStamp): Created vault $($VaultName). This vault is enabled for template-deployment." | Out-File -FilePath $LogPath -Append
        }

        Catch 
        {
            $ErrorMessage = $_.Exception.Message
            Write-Output "$(Get-TimeStamp): $ErrorMessage" | Out-File $LogPath -Append
            $ErrorMessage = $null    
        }

    }

    # Adding the secret to our Key Vault.
    Try 
    {
        $securepwd = ConvertTo-SecureString (Get-Content -Path C:\x\AdminPasswordVM.txt) –AsPlainText –Force 
        $setSecret = Set-AzureKeyVaultSecret -VaultName "$($VaultName)" -Name "$($SecretName)" -SecretValue $securepwd
        $KeyVaultID = (Get-AzureRmKeyVault).ResourceID
    }

    Catch 
    {
        $ErrorMessage = $_.Exception.Message
        Write-Output "$(Get-TimeStamp): $ErrorMessage" | Out-File $LogPath -Append
        $ErrorMessage = $null    
    }

    # Updating JSON file with new key information.
    If ($KeyVaultID) {
        
        Try 
        {
            (Get-Content -Path $JSONParameterFilePath).Replace("FutureKeyID","$($KeyVaultID)") | Set-Content $JSONParameterFilePath
            (Get-Content -Path $JSONParameterFilePath).Replace("Future_SecretName","$($setSecret.Name)") | Set-Content $JSONParameterFilePath
        }

        Catch 
        {
            $ErrorMessage = $_.Exception.Message
            Write-Output "$(Get-TimeStamp): $ErrorMessage" | Out-File $LogPath -Append
            $ErrorMessage = $null    
        }
    }

    Else {
        Write-Output "$(Get-TimeStamp): Unable to retrieve critical information from vault. Abotring operation, Please check manually." | Out-File $LogPath -Append ; break
    }

    # Attempting to deploy our resources into our resourcegroup. For debugging purposes the debug level is at maxium. This is not always recommended in production.
    Try
    {
        New-AzureRmResourceGroupDeployment -Name $($DeploymentName) `
                                           -ResourceGroupName $($ResourceGroupName) `
                                           -Mode $($DeploymentMode) `
                                           -TemplateFile $($JSONTemplateFilePath) `
                                           -TemplateParameterFile $($JSONParameterFilePath) `
                                           -Force -Verbose -DeploymentDebugLogLevel All
    }

    Catch 
    {
        $ErrorMessage = $_.Exception.Message
        Write-Output "$(Get-TimeStamp): $ErrorMessage" | Out-File $LogPath -Append
        $ErrorMessage = $null
    }

} #EOF

$Params = @{

location = "West Europe"
AzureUsername = "ken@basdezeeuwsentia.onmicrosoft.com"
AzurePasswordFilePath = "C:\x\PasswordEncrypted.txt"
LocalAdminPasswordPath = "C:\X\AdminPasswordVM.txt"
VaultName = "KensjeroSecretVault"
SecretName = "LocalAdminPassword"
ResourceGroupName = "Sentia_Deployment_Policy"
DeploymentMode = "Incremental"
DeploymentName = "Sentia_Deployment_Policy"
SubscriptionID = '874c624a-899b-45be-99a9-ba8822674908'
TenantID = "ba52ae1a-5fa4-4cc3-b587-801ec3430c47"
JSONTemplateFilePath = "C:\x\Sentia\Single-SubNet\azuredeploy.json"
JSONParameterFilePath = "C:\x\Sentia\Single-SubNet\azuredeploy.parameters.json"
ResourceGroupTag = @{Environment='Test'; Company='Sentia'}
PolicyName = "TypeRestriction"
PolicyDisplayName = "TypeRestriction"
PolicyDescription = "Restricting resource types to allow networking, storage and computing."
PolicyTemplateFilePath = "C:\X\TypeRestrictionPolicy.json"
PolicyParameterFilePath =  "C:\X\TypeRestrictionPolicy.parameters.json"
PolicyParameterDefinitionFilePath = "C:\X\AllowedResourceTypes.json"
            }

Try 
{
    Deploy-AzureVM @Params
}

Catch
{
    $ErrorMessage = $_.Exception.Message
    Write-Output "$(Get-TimeStamp): $ErrorMessage" | Out-File $LogPath -Append
    $ErrorMessage = $null
}

