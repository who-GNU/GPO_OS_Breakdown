#Requires -Modules ActiveDirectory, GroupPolicy

<#
.SYNOPSIS
    Analyzes GPOs linked to a specific OU and its sub-OUs for computer objects and Windows versions
.DESCRIPTION
    This script checks a specific OU and all its sub-OUs, finds GPOs linked to them,
    identifies computer objects in those locations, and analyzes Windows versions
.PARAMETER TargetOU
    The Distinguished Name of the target OU to analyze
.NOTES
    Requires Active Directory and Group Policy PowerShell modules
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetOU
)

# Import required modules
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

# Initialize collections to store results
$Results = @()
$OUAnalysis = @()

Write-Host "Starting OU-focused GPO and Computer Analysis..." -ForegroundColor Green
Write-Host "Target OU: $TargetOU" -ForegroundColor Cyan
Write-Host "=" * 50

try {
    # Step 1: Validate and get the target OU and all its sub-OUs
    Write-Host "Step 1: Retrieving target OU and all sub-OUs..." -ForegroundColor Yellow
    
    # Verify the target OU exists
    try {
        $BaseOU = Get-ADOrganizationalUnit -Identity $TargetOU
        Write-Host "Base OU found: $($BaseOU.Name)" -ForegroundColor Green
    } catch {
        throw "Target OU '$TargetOU' not found or inaccessible: $($_.Exception.Message)"
    }
    
    # Get all OUs under the target OU (including the target OU itself)
    $AllOUs = @($BaseOU) + @(Get-ADOrganizationalUnit -Filter * -SearchBase $TargetOU -SearchScope Subtree)
    Write-Host "Found $($AllOUs.Count) OUs to analyze (including base OU)" -ForegroundColor Cyan
    
    foreach ($OU in $AllOUs) {
        Write-Host "Processing OU: $($OU.Name)" -ForegroundColor White
        Write-Host "  DN: $($OU.DistinguishedName)" -ForegroundColor Gray
        
        # Step 2: Find GPOs linked to this OU
        Write-Host "  - Finding linked GPOs..." -ForegroundColor Gray
        
        try {
            # Get GPO links for this specific OU
            $GPOLinks = Get-GPInheritance -Target $OU.DistinguishedName
            
            if ($GPOLinks.GpoLinks) {
                Write-Host "    Found $($GPOLinks.GpoLinks.Count) linked GPOs" -ForegroundColor Cyan
                
                # Step 3: Get computer objects in this OU (not recursive - just this OU level)
                Write-Host "  - Searching for computer objects in this OU..." -ForegroundColor Gray
                
                $Computers = Get-ADComputer -Filter * -SearchBase $OU.DistinguishedName -SearchScope OneLevel -Properties Name, OperatingSystem, OperatingSystemVersion, LastLogonDate
                Write-Host "    Found $($Computers.Count) computer objects in this OU" -ForegroundColor Cyan
                
                if ($Computers.Count -gt 0) {
                    # Step 4: Analyze Windows versions for computers in this OU
                    $WindowsVersions = @{}
                    $ComputerDetails = @()
                    
                    foreach ($Computer in $Computers) {
                        $OS = $Computer.OperatingSystem
                        $OSVersion = $Computer.OperatingSystemVersion
                        
                        # Create a standardized OS identifier
                        $OSIdentifier = if ($OS) { $OS } else { "Unknown" }
                        
                        # Count versions
                        if ($WindowsVersions.ContainsKey($OSIdentifier)) {
                            $WindowsVersions[$OSIdentifier]++
                        } else {
                            $WindowsVersions[$OSIdentifier] = 1
                        }
                        
                        # Store detailed computer info
                        $ComputerDetails += [PSCustomObject]@{
                            ComputerName = $Computer.Name
                            OperatingSystem = $OS
                            OperatingSystemVersion = $OSVersion
                            LastLogon = $Computer.LastLogonDate
                        }
                    }
                    
                    # Determine if all computers have the same Windows version
                    $UniqueVersions = $WindowsVersions.Keys.Count
                    $AllSameVersion = $UniqueVersions -eq 1
                    $MostCommonVersion = if ($WindowsVersions.Count -gt 0) { 
                        ($WindowsVersions.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Name 
                    } else { "N/A" }
                    
                    # Get GPO details for this OU
                    $LinkedGPOs = @()
                    foreach ($GPOLink in $GPOLinks.GpoLinks) {
                        $LinkedGPOs += [PSCustomObject]@{
                            GPOName = $GPOLink.DisplayName
                            GPOId = $GPOLink.GpoId
                            Enabled = $GPOLink.Enabled
                            Enforced = $GPOLink.Enforced
                            Order = $GPOLink.Order
                        }
                    }
                    
                    # Store results for this OU
                    $OUResult = [PSCustomObject]@{
                        OUName = $OU.Name
                        OUDistinguishedName = $OU.DistinguishedName
                        LinkedGPOs = $LinkedGPOs
                        GPOCount = $GPOLinks.GpoLinks.Count
                        ComputerCount = $Computers.Count
                        AllSameVersion = $AllSameVersion
                        UniqueVersionCount = $UniqueVersions
                        MostCommonVersion = $MostCommonVersion
                        VersionBreakdown = $WindowsVersions
                        ComputerDetails = $ComputerDetails
                        AnalysisDate = Get-Date
                    }
                    
                    $Results += $OUResult
                    
                    # Display summary for this OU
                    Write-Host "    Analysis Summary:" -ForegroundColor Yellow
                    Write-Host "      - All same version: $AllSameVersion" -ForegroundColor $(if ($AllSameVersion) { "Green" } else { "Red" })
                    Write-Host "      - Most common version: $MostCommonVersion" -ForegroundColor Cyan
                    Write-Host "      - Unique versions: $UniqueVersions" -ForegroundColor White
                    Write-Host "      - Linked GPOs: $($GPOLinks.GpoLinks.Count)" -ForegroundColor White
                    
                    if ($UniqueVersions -gt 1) {
                        Write-Host "      - Version breakdown:" -ForegroundColor White
                        foreach ($Version in $WindowsVersions.GetEnumerator()) {
                            Write-Host "        * $($Version.Key): $($Version.Value) computers" -ForegroundColor Gray
                        }
                    }
                    
                    # Show linked GPOs
                    if ($LinkedGPOs.Count -gt 0) {
                        Write-Host "      - Linked GPOs:" -ForegroundColor White
                        foreach ($LinkedGPO in $LinkedGPOs) {
                            $status = if ($LinkedGPO.Enabled) { "Enabled" } else { "Disabled" }
                            $enforced = if ($LinkedGPO.Enforced) { " (Enforced)" } else { "" }
                            Write-Host "        * $($LinkedGPO.GPOName) - $status$enforced" -ForegroundColor Gray
                        }
                    }
                } else {
                    Write-Host "    No computers found in this OU" -ForegroundColor Yellow
                }
                
            } else {
                Write-Host "    No GPOs linked to this OU" -ForegroundColor Yellow
            }
            
        } catch {
            Write-Warning "Failed to process OU '$($OU.DistinguishedName)': $($_.Exception.Message)"
        }
        
        Write-Host "" # Add spacing between OUs
    }
    
    # Summary Report
    Write-Host "=" * 50
    Write-Host "OU ANALYSIS COMPLETE - SUMMARY REPORT" -ForegroundColor Green
    Write-Host "=" * 50
    
    $TotalOUsAnalyzed = $Results.Count
    $OUsWithComputers = ($Results | Where-Object { $_.ComputerCount -gt 0 }).Count
    $OUsWithSameVersion = ($Results | Where-Object { $_.AllSameVersion -and $_.ComputerCount -gt 0 }).Count
    $OUsWithMixedVersions = ($Results | Where-Object { -not $_.AllSameVersion -and $_.ComputerCount -gt 0 }).Count
    $TotalComputers = ($Results | Measure-Object -Property ComputerCount -Sum).Sum
    $TotalGPOLinks = ($Results | Measure-Object -Property GPOCount -Sum).Sum
    
    Write-Host "Target OU: $TargetOU" -ForegroundColor White
    Write-Host "Total OUs Analyzed: $($AllOUs.Count)" -ForegroundColor White
    Write-Host "OUs with Computers: $OUsWithComputers" -ForegroundColor White
    Write-Host "Total Computers Found: $TotalComputers" -ForegroundColor White
    Write-Host "Total GPO Links: $TotalGPOLinks" -ForegroundColor White
    Write-Host "OUs with Uniform Windows Versions: $OUsWithSameVersion" -ForegroundColor Green
    Write-Host "OUs with Mixed Windows Versions: $OUsWithMixedVersions" -ForegroundColor $(if ($OUsWithMixedVersions -gt 0) { "Red" } else { "Green" })
    
    # Show overall Windows version distribution
    if ($TotalComputers -gt 0) {
        Write-Host "`nOverall Windows Version Distribution:" -ForegroundColor Yellow
        $AllVersions = @{}
        foreach ($Result in $Results) {
            foreach ($Version in $Result.VersionBreakdown.GetEnumerator()) {
                if ($AllVersions.ContainsKey($Version.Key)) {
                    $AllVersions[$Version.Key] += $Version.Value
                } else {
                    $AllVersions[$Version.Key] = $Version.Value
                }
            }
        }
        
        foreach ($Version in $AllVersions.GetEnumerator() | Sort-Object Value -Descending) {
            $Percentage = [math]::Round(($Version.Value / $TotalComputers) * 100, 1)
            Write-Host "  $($Version.Key): $($Version.Value) computers ($Percentage%)" -ForegroundColor Cyan
        }
    }
    
    # Store results in global variable for further processing
    $Global:OUAnalysisResults = $Results
    
    Write-Host "`nResults stored in `$Global:OUAnalysisResults variable" -ForegroundColor Yellow
    Write-Host "Ready for additional steps..." -ForegroundColor Green

} catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Write-Error "Stack Trace: $($_.ScriptStackTrace)"
}

# Usage example (commented out)
<#
# Example usage:
# .\Script.ps1 -TargetOU "OU=Workstations,DC=contoso,DC=com"
#>
