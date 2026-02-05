#Requires -RunAsAdministrator
<#
.SYNOPSIS
    README Parser and Analyzer
.DESCRIPTION
    Finds and parses the competition README file, then displays and exports the results.
    Run this first to understand what the competition requires.
#>

# Import the parser module
. "$PSScriptRoot\ReadmeParser.ps1"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CyberPatriot README Analyzer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Allow user to specify README path
$readmePath = $null
if ($args.Count -gt 0) {
    $readmePath = $args[0]
    if (-not (Test-Path $readmePath)) {
        Write-Host "ERROR: Specified file not found: $readmePath" -ForegroundColor Red
        exit 1
    }
}

# Parse the README
Write-Host "Parsing competition README..." -ForegroundColor Cyan
$readmeData = Parse-CompetitionReadme -ReadmePath $readmePath

if (-not $readmeData) {
    Write-Host ""
    Write-Host "ERROR: Could not parse README file!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\AnalyzeReadme.ps1                    # Auto-find README" -ForegroundColor Gray
    Write-Host "  .\AnalyzeReadme.ps1 C:\Path\README.txt # Specify path" -ForegroundColor Gray
    Write-Host ""
    exit 1
}

# Display the parsed data
Show-ReadmeData -ReadmeData $readmeData

# Export to JSON for use by other scripts
$exportPath = "$PSScriptRoot\ReadmeData.json"
$exported = Export-ReadmeData -ReadmeData $readmeData -OutputPath $exportPath

if ($exported) {
    Write-Host "✓ README data has been analyzed and saved" -ForegroundColor Green
    Write-Host "  Other scripts will now use this data to avoid false positives" -ForegroundColor Gray
    Write-Host ""
    Write-Host "IMPORTANT NOTES:" -ForegroundColor Yellow
    Write-Host "  • Users listed above are AUTHORIZED and won't be flagged" -ForegroundColor Gray
    Write-Host "  • Software listed above is ALLOWED and won't be flagged" -ForegroundColor Gray
    Write-Host "  • Services listed above are REQUIRED and won't be disabled" -ForegroundColor Gray
    Write-Host "  • Re-run this script if the README changes" -ForegroundColor Gray
} else {
    Write-Host "✗ Failed to export README data" -ForegroundColor Red
}

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
