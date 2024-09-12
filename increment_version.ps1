# Path to the version header file
$versionFile = "version.h"

# Read the file content
$content = Get-Content $versionFile -Raw

# Define the regular expression pattern to match the build number
$pattern = '#define VER_BUILD (\d+)'

# Use [regex]::Replace to find and increment the build number
$content = [regex]::Replace($content, $pattern, {
    param($matches)
    "#define VER_BUILD " + ([int]$matches.Groups[1].Value + 1)
})

# Write the updated content back to the file without adding a new line
$outFile = $versionFile
$content | Out-File -FilePath $outFile -NoNewline
