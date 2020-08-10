<#
.SYNOPSIS
    Get all device models present in ConfigMgr and create a devicecollection with a queryfilter.
.DESCRIPTION
    This script will get all device models present in ConfigMgr and create collections of them. If they already exist collections from before it moves the collection to the specified folder structure. Made with Scheduled Task in mind. It requires Hardware Inventory to be enabled and that the devices have reported a full hardware inventory report at least once.
.PARAMETER SiteServer
    Site server name with SMS Provider installed.
.PARAMETER DeviceCollectionFolder
    Name of the folder the collections will be created in. Default: Make and Model
.PARAMETER RefreshDays
    Number of days between refresh of the collections. Default: 7
.EXAMPLE
    # Get all device models and create collections on a Primary Site server called 'CM01':
    .\New-CMMakeModel-DeviceCollection.ps1 -SiteServer CM01
.EXAMPLE
    # Defaults with no params. Beforehand check value for default Siteserver!
    .\New-CMMakeModel-DeviceCollection.ps1
    
.NOTES
    FileName:    New-CMMakeModel-DeviceCollection.ps1
    Author:      Gerhard Eriksson
    Created:     2020-08-10
    Updated:     2020-08-10
    Version history:
    1.0.0 - (2020-08-10) Script created

#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [parameter(Mandatory=$false, HelpMessage="Site server where the SMS Provider is installed")][string]$SiteServer="Siteserver.sccm.com",
    [parameter(Mandatory=$false, HelpMessage="Name of the folder the collections will be created in. Default: Make and Model")][string]$DeviceCollectionFolder="Make and Model",
    [parameter(Mandatory=$false, HelpMessage="Number of days between refresh of the collections. Default: 7")][int]$RefreshDays=7
)
Begin {
    #Load Configuration Manager PowerShell Module
    Import-module ($Env:SMS_ADMIN_UI_PATH.Substring(0,$Env:SMS_ADMIN_UI_PATH.Length-5)+ '\ConfigurationManager.psd1')
    
    #Get SiteCode
        $SiteCode = Get-PSDrive -PSProvider CMSite | where Root -EQ $SiteServer
    try{
        if(-NOT(Test-Connection -ComputerName $SiteCode.root)){
            throw "Can't connect or find: $($SiteCode.root)"
        }
    }
    catch {
        $_.Exception.Message
        break
    }
    Write-Verbose "Successfully connected to $($SiteCode.root)"
    Set-location "$($SiteCode.Name):"
    #Error Handling and output
    $ErrorActionPreference= 'SilentlyContinue'

    #Create Default Folder 
    $CollectionFolder = @{Name = $DeviceCollectionFolder; ObjectType =5000; ParentContainerNodeId =0}
    Set-WmiInstance -Namespace "root\sms\site_$($SiteCode.Name)" -Class "SMS_ObjectContainerNode" -Arguments $CollectionFolder -ComputerName $SiteCode.Root
    $FolderPath =($SiteCode.Name +":\DeviceCollection\" + $CollectionFolder.Name)

    # ArrayList to store the models in
    $ModelsArrayList = New-Object -TypeName System.Collections.ArrayList

    try {
    # Enumerate through all models
    $ComputerSystems = Get-WmiObject -Namespace "root\SMS\site_$($SiteCode.Name)" -Class SMS_G_System_COMPUTER_SYSTEM -ComputerName $SiteCode.Root | Select-Object -Property Model, Manufacturer
    
    # Add model to ArrayList if not present
    if ($ComputerSystems -ne $null) {
        foreach ($ComputerSystem in $ComputerSystems) {
            if ($ComputerSystem.Model -notin $ModelsArrayList.Model) {
                $PSObject = [PSCustomObject]@{
                    Manufacturer = $ComputerSystem.Manufacturer
                    Model = $ComputerSystem.Model
                }
                $ModelsArrayList.Add($PSObject) | Out-Null
                Write-host "Added new hardware: $PSObject"
            }
        }
    }
    Write-host "Found $($ModelsArrayList.Count) different computers found in database ."
    Set-location $SiteCode":\DeviceCollection\"$DeviceCollectionFolder
    }
    Catch {
        $_.Exception.Message
        break
    }
}

Process {
    try {
        #Refresh Schedule
        $Schedule = New-CMSchedule –RecurInterval Days –RecurCount $RefreshDays
    
        #Create Default limiting collections
        $LimitingCollection = "All Systems"

        #Create Collection
        $ModelsArrayList |Sort-Object Manufacturer,Model | ForEach-Object {
            if(Get-CMDeviceCollection -Name "$($_.Manufacturer) | $($_.Model)") {
                Write-Verbose "Found existing $($_.Manufacturer) | $($_.Model), moving it to $FolderPath"
                Move-CMObject -FolderPath $FolderPath -InputObject $(Get-CMDeviceCollection -Name "$($_.Manufacturer) | $($_.Model)")
            }
            else {
                Write-Verbose "Creating collection $($_.Manufacturer) | $($_.Model) and moving it to $FolderPath"
                New-CMDeviceCollection -Name "$($_.Manufacturer) | $($_.Model)" -Comment "All devices with model $($_.Model) from $($_.Manufacturer)" -LimitingCollectionName $LimitingCollection -RefreshSchedule $Schedule -RefreshType 2 |Out-Null
                Add-CMDeviceCollectionQueryMembershipRule -CollectionName "$($_.Manufacturer) | $($_.Model)" -QueryExpression "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Model = `"$($_.Model)`" and SMS_G_System_COMPUTER_SYSTEM.Manufacturer = `"$($_.Manufacturer)`"" -RuleName "$($_.Manufacturer) $($_.Model)"
                Move-CMObject -FolderPath $FolderPath -InputObject $(Get-CMDeviceCollection -Name "$($_.Manufacturer) | $($_.Model)")
            }
        }
        Remove-Variable $SiteCode
    }
    catch {
        $_.Exception.Message
    }
}