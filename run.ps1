# Brando's Toolkit - Quick Launcher
# This wrapper downloads and executes make.ps1 without parameter issues

# Download the main script
$scriptContent = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/brand-o/tools/main/make.ps1' -UseBasicParsing

# Remove the param block to allow execution via iex
# Find the end of the param block (after the closing parenthesis)
$paramStart = $scriptContent.IndexOf('[CmdletBinding()]')
if ($paramStart -gt 0) {
    $paramEnd = $scriptContent.IndexOf(')', $paramStart)
    # Find the next line after param block ends
    $nextLine = $scriptContent.IndexOf("`n", $paramEnd) + 1
    # Remove everything from [CmdletBinding()] to end of param block
    $scriptContent = $scriptContent.Substring(0, $paramStart) + $scriptContent.Substring($nextLine)
}

# Execute the modified script
Invoke-Expression $scriptContent
