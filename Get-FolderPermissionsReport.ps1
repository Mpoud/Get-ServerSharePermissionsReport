<#
.SYNOPSIS
    This script is designed to pull the NTFS Access Control List (ACL) permissions of Windows folders (including subfolders).
.DESCRIPTION
    This script attempts to gather NTFS ACL permissions on Windows folders. Rights are required on the systems to access the respective NTFS permissions, likely local administrative rights. This script cannot access permissions on things like printers, Linux based appliances and servers, and will get rejected on Windows' hosts where you do not have local rights.
.PARAMETER Folder
    Specify the folder to start the search.
.PARAMETER Depth
    Specify the depth of the folders to search, or use 0 to disable recursive search. (default: 999)
.PARAMETER ReportStyle
    Specify if the final HTML report should have a nested table style (default) or a flat table sytle.
.PARAMETER HTMLFile
    Specify the HTML report file name (default: NTFS_ACL_Report.html).
.PARAMETER XMLFile
    Specify the XML file name if you would like to save the XML output for later use.
.EXAMPLE
    Get-FolderPermissionsReport.ps1 -Folder c:\shares\data
    This command attempts to pull all folders in 'c:\shares\data' and retrieves all rights below.
.EXAMPLE
    Get-FolderPermissionsReport.ps1 -Folder c:\shares\data -ReportStyle FlatTable -HTMLFile SqlServerSharePermissions.html -XMLFile NTFS_XML_Output.xml
    This command attempts to pull all folders in 'c:\shares\data' and retrieves all rights below. It uses the flat table format and writes the XML to 'NTFS_XML_Ouput.xml' and final HTML report to a file named SqlServerOfficeSharePermissions.html.
.NOTES
    Version 1.0 - Last Modified 13-06-2019
    This script is a modified version of the original script Get-ServerSharePermissionsReport that was written by Vincent Drake and modified by Sam Pursglove.
    I, Michiel van Pouderoijen, wrote this script to use the same output format and create a NTFS report of the files in a share
    
#>

param 
(
    [Parameter(Position=0,
               Mandatory=$true,
               ValueFromPipeline=$false,
               HelpMessage='Enter the folder to start the search.')]
    [string]$Folder,

    [Parameter(Position=0,
               Mandatory=$false,
               ValueFromPipeline=$false,
               HelpMessage='Enter the folderdepth to search for.')]
    [int]$FolderDepth = 999,
    
    [Parameter(Mandatory=$false,
               ValueFromPipeline=$false,
               HelpMessage='Select the final report formatting style.')]
    [ValidateSet('NestedTable','FlatTable')]$ReportStyle = 'NestedTable',
    
    [Parameter(Mandatory=$false,
               ValueFromPipeline=$false,
               HelpMessage='Set the HTML final report name.')]
    [string]$HTMLFile = "NTFS_ACL_Report.html",

    [Parameter(Mandatory=$false,
               ValueFromPipeline=$false,
               HelpMessage='Saves the XML file to use for other purposes')]
    [string]$XMLFile
)

$xslTransforms = @{
    NestedTable = @"
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
  <html>
  <body>
  <h2>File System Security Report</h2>
  <table border="1" style="border-collapse:collapse" width='100%'>
    <tr bgcolor="#9acd32">
      <th>Path</th>
      <th>Owner</th>
      <th>Group</th>
      <th>Access</th>
    </tr>
    <xsl:for-each select="Objects/Object">
    <tr>
      <td><xsl:value-of select="Property[@Name='Path']"/></td>
      <td><xsl:value-of select="Property[@Name='Owner']"/></td>
      <td><xsl:value-of select="Property[@Name='Group']"/></td>
      <td><table border='1' style='border-collapse:collapse' width='100%'>
        <tr bgcolor="#8abd32">
          <th>Id</th>
          <th>Access</th>
          <th>Rights</th>
        </tr>
        <xsl:for-each
select="Property[@Name='Access']/Property[@Type='System.Management.Automation.PSCustomObject']">
        <tr>
          <td><xsl:value-of select="Property[@Name='IdentityReference']"/></td>
          <td><xsl:value-of select="Property[@Name='AccessControlType']"/></td>
          <td><xsl:value-of select="Property[@Name='FileSystemRights']"/></td>
        </tr>
        </xsl:for-each>
      </table></td>
    </tr>
    </xsl:for-each>
  </table>
  </body>
  </html>
</xsl:template>
</xsl:stylesheet>
"@
    FlatTable = @"
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
  <html>
  <body>
  <h2>File System Security Report</h2>
  <table border="1" style="border-collapse:collapse" width='100%'>
    <tr bgcolor="#9acd32">
      <th>Path</th>
      <th>Owner</th>
      <th>Group</th>      
      <th>Id</th>
      <th>Access</th>
      <th>Rights</th>
    </tr>
    <xsl:for-each select="Objects/*/Property[@Name='Access']/Property[@Type='System.Management.Automation.PSCustomObject']">
    <tr>      
      <td><xsl:value-of select="../../Property[@Name='Path']"/></td>
      <td><xsl:value-of select="../../Property[@Name='Owner']"/></td>
      <td><xsl:value-of select="../../Property[@Name='Group']"/></td>
      <td><xsl:value-of select="Property[@Name='IdentityReference']"/></td>
      <td><xsl:value-of select="Property[@Name='AccessControlType']"/></td>
      <td><xsl:value-of select="Property[@Name='FileSystemRights']"/></td>      
    </tr>
    </xsl:for-each> 
  </table>
  </body>
  </html>
</xsl:template>
</xsl:stylesheet>
"@
}

function Get-ACLData {
    Param(
        [parameter(mandatory=$true,ValueFromPipeline=$true)]
        [String]
        $path
    )
    begin{
        $accessMask = [ordered]@{
            [int32]'0x80000000' = 'GenericRead'
            [int32]'0x40000000' = 'GenericWrite'
            [int32]'0x20000000' = 'GenericExecute'
            [int32]'0x10000000' = 'GenericAll'
            [int32]'0x02000000' = 'MaximumAllowed'
            [int32]'0x01000000' = 'AccessSystemSecurity'
            [int32]'0x00100000' = 'Synchronize'
            [int32]'0x00080000' = 'WriteOwner'
            [int32]'0x00040000' = 'WriteDAC'
            [int32]'0x00020000' = 'ReadControl'
            [int32]'0x00010000' = 'Delete'
            [int32]'0x00000100' = 'WriteAttributes'
            [int32]'0x00000080' = 'ReadAttributes'
            [int32]'0x00000040' = 'DeleteChild'
            [int32]'0x00000020' = 'Execute/Traverse'
            [int32]'0x00000010' = 'WriteExtendedAttributes'
            [int32]'0x00000008' = 'ReadExtendedAttributes'
            [int32]'0x00000004' = 'AppendData/AddSubdirectory'
            [int32]'0x00000002' = 'WriteData/AddFile'
            [int32]'0x00000001' = 'ReadData/ListDirectory'
        }

        $Selections = @{
            FileSecurity = @(
                @{label='Path';Expression={$_.Path -replace 'Microsoft.PowerShell.Core\\FileSystem::',''}},
                'Owner',
                'Group',
                'Sddl',
                @{label='Access';Expression={$_.Access | Select-Object $Selections.FileSystemAccessRule}}
            )
            FileSystemAccessRule = @(
                'IdentityReference',
                @{
                    Label='FileSystemRights'
                    Expression={
                        $accessObj = $_
                        if ($accessObj.FileSystemRights -match "[-0-9]+") {                            
                            ($accessMask.Keys | Where-Object {$accessObj.FileSystemRights.Value__ -band $_ } | ForEach-Object { $accessMask.($_) } ) -join ', '
                        } else {
                            $_.FileSystemRights
                        }
                    }
                },
                'AccessControlType'
            )
        }
        $Selections.DirectorySecurity = $Selections.FileSecurity
    }    
    process {        
        try {
            Get-ACL -Path $path -ErrorAction Stop | ForEach-Object { $_ | Select-Object -Property $Selections.($_.GetType().name) }
            Write-Host "Exporting NTFS ACL --> $path"
        } catch {
            if ($_ | Select-String "access is denied" -Quiet) {
                Write-Host "Continuing ----------> $path access is denied"
            } elseif ($_ | Select-String "does not exist" -Quiet) {
                Write-Host "Continuing ----------> $path does not exist"
            }
        } 
    }
    end {}
}

function Get-SubFolders {
    Param ( 
        [Parameter (ValueFromPipeline=$true)] $Path 
    )
    begin{} 
    process{ 
        try {
             Get-ChildItem -Path $Path -Recurse -Attributes d -Depth $FolderDepth |
             Select-Object @( 
                 'Name', 
                 @{  Label="Folder" 
                     expression={ 
                         "$($_.Fullname)" 
                     } 
                 }
             ) 
        } catch { 
            Write-Host "Continuing ----------> Failed to get the folder $($Path)" 
        }
    } 
    end {} 
}

function Generate-Report {
    Param(        
        [XML]$XMLSource,
        [String]$HTMLOutput,
        [ValidateSet('NestedTable','FlatTable')] $ReportStyle = 'NestedTable'
    )
    $xslt = new-object System.Xml.Xsl.XslCompiledTransform    
    $xmlReader = [System.Xml.XmlReader]::Create((new-object System.IO.StringReader -ArgumentList $xslTransforms.$ReportStyle))
    $xslt.Load($xmlReader)
    $xmlSourceNavigator = $XMLSource.CreateNavigator()
    $htmlOutputWriter = [System.Xml.XmlWriter]::Create($HTMLOutput)

    $xslt.Transform($xmlSourceNavigator, $htmlOutputWriter)
}

# Stop if output file already exists
$htmlFilePath = Resolve-Path (New-Item $HTMLFile -ItemType file -ErrorAction Stop)

# Request folders from Startfolder
$CompleteFolderList = $Folder | Get-SubFolders

# Request shares and ACL data
$dataset = $CompleteFolderList.Folder | Get-ACLData

# Convert dataset to XML
[XML]$xmlDataset = $dataset | ConvertTo-XML -depth 2

# Save XML file if requested
if ($XMLFile){
    $ScriptPath = Split-Path -parent $MyInvocation.MyCommand.Definition
    $xmloutputfile = $ScriptPath + "\" + $XMLFile
    $xmlDataset.Save($xmloutputfile)
}

# Generate HTML by XML dataset
Generate-Report -XMLSource $xmlDataset -HTMLOutput $htmlFilePath -ReportStyle $ReportStyle