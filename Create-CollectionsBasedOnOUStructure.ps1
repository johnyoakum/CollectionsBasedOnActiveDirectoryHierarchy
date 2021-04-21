<#
    .SYPOPSIS
        This script/function will create a folder structure and collections based on your Active Directory Structure
    .DESCRIPTION
        Use this script/function to create folders and collections based on your Active Directory Environment. It uses Active Directory domain membership to create the collections and populate
        based on those directory values. This script will log all actions to a log file in your Admin Console Logs or if you have the MEMCM Client installed to the CCM Log folder. I added the ability to add a prefix to each Collection if you'd like.
        Depending on how big and complicated your Active Directory environment is will depend on how long this script takes to run.
        The purposes of this script:
        1. Create SCCM device collections based on Active Directory Organzational Unit and Hierchary
        2. Define the Refresh Schedule of collection to 7 days
        3. Create Query Rule for collection membership
        4. Move created collection to custom folder
        5. Updates collection membership at once.
    .PARAMETER RootFolderName Required
        This is the root folder to use where the folders and collections will begin being created from for mimicing Active Directory
    .PARAMETER SearchBase Required
        This is the distinguished name of the OU or container you wish to start creating the directory structure and collections from
        Example:  "OU=Computers,OU=SomeOU2,OU=SomeOU1,DC=viamonstra,DC=com"
    .PARAMETER SubStringValue Required
        This is the number of characters to exclude from the CanonicalName where to begin the mimicing
        Example: "viamonstra.com/SomeOU1/SomeOU2/Computers", I would enter 15 if I was starting at SomeOU1, 24 if I wanted to start at SomeOU2, etc...
    .PARAMETER Prefix
        This is the prefix you would like to prepend to the Collection Name when it is created.
    .EXAMPLE
        Create-CollectionsBasedOnOUStructure.ps1 -RootFolderName {FolderName} -SearchBase "OU=Computers,OU=SomeOU2,OU=SomeOU1,DC=viamonstra,DC=com" -SubstringValue 15 -Prefix "VIA_"
    .Notes
        FileName:    Create-CollectionsBasedOnOUStructure.PS1
        Author:      John Yoakum with credit to Benoit Lecours from www.SystemCenterDudes.com for getting me started
        Created:     2021-04-20
        Updated:     2021-04-20

        Version 1.0
            - Initial release
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true, HelpMessage="Enter the root folder name to store the hierchary in.", ValueFromPipeline=$true)]
    [string]$RootFolderName,
    [parameter(Mandatory=$true, HelpMessage="Enter the distinguished name of where you'd like to start seaching in Active Directoty.", ValueFromPipeline=$true)]
    [ValidatePattern("^(?:(?:CN|OU|DC)\=\w+,)*(?:OU|DC)\=\w+$")]
    [string]$SearchBase,
    [Parameter(Mandatory=$true, HelpMessage="Enter the number of characters to eliminate from the start of the Search Base (normally your DC=String")]
    [int]$SubstringValue,
    [Parameter(Mandatory=$False,HelpMessage="Enter the Collection Name prefix if you would like to add any characters to the beginning of the collection name.", ValueFromPipeline=$true)]
    [string]$Prefix
)

#region Declarations
# Import PS modules
Import-Module ActiveDirectory
Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"

# Get the Site Code
$Site = (Get-PSDRive -PSProvider CMSite).Name

# Defining refresh interval for collection - 7 days
$Schedule = New-CMSchedule –RecurInterval Days –RecurCount 7

# Set the Initial Target Location
$TargetFolder = "${Site}:\DeviceCollection\$RootFolderName"

# Declare the Array for the Custom Object
$ADOUsFiltered = @()

# Stores the name of this powershell script
$ScriptName = $MyInvocation.MyCommand.Name

# Strips off the trailing '.ps1' value from the script name.
$ScriptName = $ScriptName -replace '.ps1', ''

# Set the filename of the logfile
[string]$FileName = "$ScriptName-$(get-date -format yyyyMMdd).log"
#endregion

#region Functions
function Get-CMLogDirectory {
    [CmdletBinding()]param()

    try {
        $LogDir = (Get-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCM\Logging\@Global\ -Name LogDirectory -ErrorAction Stop).LogDirectory
    }
    catch {
        $LogDir = "$($ENV:SMS_ADMIN_UI_PATH)\..\..\AdminUILog"
    }
    Write-Verbose "CCM Log Directory = $LogDir"
    return $LogDir
}

function Write-CMLogEntry {
    param (
        [parameter(Mandatory = $true, HelpMessage = 'Value added to the log file.')]
        [ValidateNotNullOrEmpty()]
        [string]$Value,
        [parameter(Mandatory = $true, HelpMessage = 'Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('1', '2', '3')]
        [string]$Severity
    )
    # Determine log file location
    $LogFilePath = Join-Path -Path Get-CMLogDirectory -ChildPath $FileName
		
    # Construct time stamp for log entry
    $Time = -join @((Get-Date -Format 'HH:mm:ss.fff'), '+', (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
		
    # Construct date for log entry
    $Date = (Get-Date -Format 'MM-dd-yyyy')
		
    # Construct context for log entry
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
		
    # Construct final log entry
    $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""CollectionsBasedOnOUStructure"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
		
    # Add value to log file
    try {
        Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Continue
    }
    catch {
        Write-Warning -Message "Unable to append log entry to $Filename. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    }
}
#endregion

#region MainBody
# Change to the Site Drive
Set-Location ${Site}:
Write-CMLogEntry -Value "Set the location to the Site drive (${Site}:)" -Severity 1

# Create the Root Folder
Write-CMLogEntry -Value "Creating the Root Folder to store the collections in." -Severity 1
New-Item -Name $RootFolderName -Path "${Site}:\DeviceCollection" | Out-Null

# Get a list of all the OUs that you want to create collections for
Write-CMLogEntry -Value "Getting all the OUs from the Search Base for processing" -Severity 1
$ADOUs = Get-ADOrganizationalUnit -SearchBase "$SearchBase" -Filter * -Properties Canonicalname |Select-Object DistinguishedName,CanonicalName
Write-CMLogEntry -Value "Got a total of $ADOUs.Length OUs from Active Directory" -Severity 1

# Process each OU and create the folder structure and collection
Write-CMLogEntry -Value "Beginning to process the OUs and Collections" -Severity 1
Write-CMLogEntry -Value "Creating a Custom Object with the information needed to create the folders and collections" -Severity 1
foreach ($OU in $ADOUs)
{
    $ADOUsFiltered += New-Object PSObject -prop @{
    DistinguishedName = $OU.DistinguishedName
    FolderName = $($OU.CanonicalName.Substring($SubstringValue)).Replace('/','\')
    CanonicalName=$OU.CanonicalName
    }
}

# Sort the objects by the folder name
$ADOUsSorted = $ADOUsFiltered | Sort-Object -Property FolderName

# Create the folder structure and Collections
ForEach ($OU in $ADOUsSorted ) {
    
# Check to see if the folder already exists and then create if not
If (!(Test-Path -Path "$TargetFolder\$($OU.FolderName)")){
    Try {
        New-Item -Path "$TargetFolder\$($OU.FolderName)" -ItemType Directory -Force | Out-Null
        Write-CMLogEntry -Value "Created the folder for $($OU.FolderName)" -Severity 1
    }
    Catch {
        Write-CMLogEntry -Value "Could not create the folder for $($OU.FolderName)" -Severity 3
    }
}
else {
    Write-CMLogEntry -Value "$($OU.FolderName) already exists, continuing..." -Severity 1
}

# Get the final OU name to use as the collection name
$CollectionBaseName = $OU.FolderName.Split('\')[-1]

# Set the collection name to include the prefix assigned
$CollectionFinalName = "$Prefix$CollectionBaseName"

# Test to make sure that the collection exists
If (!(Get-CMDeviceCollection -Name $CollectionFinalName)){
    Write-CMLogEntry -Value "$CollectionFinalName does not exist, creating it now" -Severity 1
            
    # Try to create the collection, this will fail if there is already a collection with that name
    Try
    {
        New-CMDeviceCollection -LimitingCollectionName 'All Systems' -Name $CollectionFinalName -RefreshSchedule $Schedule | Out-Null
        Write-CMLogEntry -Value "Created Collection with the name $CollectionFinalName." -Severity 1
    }
    Catch
    {
        Write-CMLogEntry -Value "Error creating collection called $CollectionFinalName. Please research..." -Severity 3
    }

    # Add the Membership Rule
    Add-CMDeviceCollectionQueryMembershipRule -CollectionName $CollectionFinalName -QueryExpression "select *  from  SMS_R_System where SMS_R_System.SystemOUName = '$($OU.CanonicalName)'" -RuleName "OU Membership" | Out-Null
    Write-CMLogEntry -Value "Added the membership rule select *  from  SMS_R_System where SMS_R_System.SystemOUName = '$($OU.CanonicalName)' to $CollectionFinalName" -Severity 1

    # Getting collection ID
    $ColID = (Get-CMDeviceCollection -Name $CollectionFinalName).collectionid

    # Set the new folder as the target
    $FinalDestination = "$TargetFolder\$($OU.FolderName)"

    # Moving collection to folder
    Write-CMLogEntry -Value "Attempting to move collection to corresponding folder" -Severity 1
    Try
    {
        Move-CMObject -FolderPath $FinalDestination -ObjectId "$ColID"
        Write-CMLogEntry -Value "Moved $CollectionFinalName to $FinalDestination" -Severity 1
    }
    Catch
    {
        Write-CMLogEntry -Value "There was an error moving the: $CollectionnFinalName collection." -Severity 3
    }

    # Updating collection membership
    Invoke-CMDeviceCollectionUpdate -Name $CollectionFinalName
    Write-CMLogEntry -Value "Updated the collection with members." -Severity 1
    }

}

Write-CMLogEntry -Value "************** Script Completed... Thank you and have a wonderful day **************" -Severity 1
#endregion