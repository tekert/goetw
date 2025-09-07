# This script automatically discovers all ETW kernel trace classes from the root\wmi
# namespace and generates a complete MOF definition file, similar to the provided
# WindowsKernelTrace.mof example.

# Set strict error handling
$ErrorActionPreference = 'Stop'

# Stage 1: Generates a simple, unformatted MOF representation for a single class.
function Get-MofRepresentationRaw {
    param(
        [string]$ClassName,
        [string]$Namespace = 'root\wmi'
    )

    $class = Get-CimClass -Namespace $Namespace -ClassName $ClassName -ErrorAction Stop
    $outputLines = [System.Collections.Generic.List[string]]::new()

    # --- Class Header ---
    $classQualifiers = ($class.CimClassQualifiers | ForEach-Object {
            $qualifierString = $_.Name
            # Fix: Check for null instead of just truthy values
            if ($null -ne $_.Value) {
                if ($_.Name -eq "EventType") {
                    $qualifierString += if ($_.Value -is [array]) { "{" + ($_.Value -join ", ") + "}" } else { "(" + $_.Value + ")" }
                }
                elseif ($_.Name -eq "EventVersion") {
                    $qualifierString += "(" + $_.Value + ")"
                }
                elseif ($_.Name -eq "dynamic") {
                    if ($_.Value -is [bool] -and $_.Value) { $qualifierString += ":ToInstance" }
                }
                elseif ($_.Value -is [string]) {
                    $qualifierString += '("' + $_.Value + '")'
                }
                else {
                    $qualifierString += '(' + $_.Value + ')'
                }
            }
            $qualifierString
        }) -join ", "

    $classHeader = if ($classQualifiers) { "[${classQualifiers}] " } else { "" }
    $classHeader += "class " + $ClassName
    if ($class.CimSuperClassName) {
        $classHeader += " : " + $class.CimSuperClassName
    }
    $classHeader += " {"
    $outputLines.Add($classHeader)

    # --- Properties ---
    $propertiesToInclude = $class.CimClassProperties | Where-Object {
        $_.Qualifiers['WmiDataId'] -or $ClassName -eq 'MSNT_SystemTrace'
    }
    $sortedProperties = $propertiesToInclude | Sort-Object { if ($_.Qualifiers['WmiDataId']) { [int]$_.Qualifiers['WmiDataId'].Value } else { 0 } }

    foreach ($property in $sortedProperties) {
        $qualifierObjects = [System.Collections.Generic.List[object]]::new()
        $property.Qualifiers.ForEach({ $qualifierObjects.Add($_) })

        if ($property.Name -eq 'Flags' -and $property.CimType -eq 'UInt32' -and !$property.Qualifiers['format']) {
            $qualifierObjects.Add([pscustomobject]@{ Name = 'format'; Value = 'x' })
        }

        # Corrected sort order logic
        $sortOrder = @{ 'WmiDataId' = 0; 'read' = 2 }
        $sortedQualifiers = $qualifierObjects | Sort-Object -Property @{Expression = { if ($sortOrder.ContainsKey($_.Name)) { $sortOrder[$_.Name] } else { 1 } } }, Name

        $hasWmiDataId = $null -ne $property.Qualifiers['WmiDataId']
        $propertyQualifiersList = ($sortedQualifiers | ForEach-Object {
                if (($hasWmiDataId -and ($_.Name -in @('Values', 'ValueMap', 'DefineValues'))) -or $_.Name -eq 'EmbeddedObject') { return }
                if ($_.Value -is [bool] -and $_.Value -eq $false) { return }

                $qualifierString = $_.Name
                if ($_.Value -and ($_.Value -isnot [bool])) {
                    if ($_.Value -is [array]) {
                        $qualifierString += '{"' + ($_.Value -join '", "') + '"}'
                    }
                    elseif ($_.Value -is [string]) {
                        $qualifierString += '("' + $_.Value + '")'
                    }
                    else {
                        $qualifierString += '(' + $_.Value + ')'
                    }
                }
                $qualifierString
            })

        $dataType = $property.CimType.ToString().Replace("Array", "")
        $qualifiersString = "[ " + ($propertyQualifiersList -join ", ") + " ]"
        $outputLines.Add("  " + $qualifiersString + " " + $dataType.ToLower() + " " + $property.Name + ";")
    }

    $outputLines.Add("};")
    return $outputLines -join "`n"
}

# Stage 2: Formats a raw MOF string with wrapping and indentation rules. (Asked IA for this)
function Format-MofContent {
    param([string]$MofContent)

    $lineLengthLimit = 90
    $formattedLines = [System.Collections.Generic.List[string]]::new()
    $blocks = $MofContent -split '(?=^\[.*\]\s*(?:abstract\s+)?class|^class)'

    foreach ($block in $blocks) {
        if ($block.Trim().Length -eq 0) { continue }
        $lines = $block.Trim() -split "`n"
        $header = $lines[0]
        $properties = $lines[1..($lines.Count - 2)]
        $footer = $lines[-1]

        # --- 1. Format Class Header ---
        # Only break if the line actually exceeds the limit
        if ($header.Length -gt $lineLengthLimit) {
            # Find the last comma before the limit
            $pos = $header.LastIndexOf(',', $lineLengthLimit)
            if ($pos -gt 0) {
                # Break at that comma and continue with remaining line
                $firstPart = $header.Substring(0, $pos + 1)
                $secondPart = $header.Substring($pos + 1).TrimStart()
                $header = $firstPart + "`n" + (" " * 9) + $secondPart
            }
        }

        # --- 2. Handle empty classes ---
        if ($properties.Count -eq 0) {
            $header = $header -replace ' {$', '{}'
            $formattedLines.Add($header)
            $formattedLines.Add("")
            continue
        }
        $formattedLines.Add($header)

        # --- 3. Format Properties ---
        foreach ($prop in $properties) {
            # Special case: MSNT_SystemTrace.Flags
            if ($header.Contains("class MSNT_SystemTrace") -and $prop.Contains("] uint32 Flags;")) {
                $prop -match '(\s*)\[ (.*) \] (.*)' | Out-Null
                $indent, $qualifiersStr, $rest = $Matches[1], $Matches[2], $Matches[3]

                $newProp = "$indent[`n"

                # Extract and format each qualifier type
                if ($qualifiersStr -match 'DefineValues({.*?})') {
                    $items = $Matches[1] -replace '[{}"]' -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                    $newProp += "$indent    DefineValues{`"" + ($items -join "`",`n$indent                 `"") + "`"},`n"
                }

                if ($qualifiersStr -match 'format\("(.*?)"\)') {
                    $newProp += "$indent    format(`"$($Matches[1])`"),`n"
                }

                if ($qualifiersStr -match 'Values({.*?})') {
                    $items = $Matches[1] -replace '[{}"]' -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                    $newProp += "$indent    Values{`""
                    for ($i = 0; $i -lt $items.Count; $i += 2) {
                        if ($i -gt 0) { $newProp += ",`n$indent           `"" }
                        $newProp += ($items[$i..([Math]::Min($i + 1, $items.Count - 1))] -join "`", `"")
                    }
                    $newProp += "`"},`n"
                }

                if ($qualifiersStr -match 'ValueMap({.*?})') {
                    $items = $Matches[1] -replace '[{}"]' -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                    $newProp += "$indent    ValueMap{`""
                    for ($i = 0; $i -lt $items.Count; $i += 4) {
                        if ($i -gt 0) { $newProp += ",`n$indent             `"" }
                        $newProp += ($items[$i..([Math]::Min($i + 3, $items.Count - 1))] -join "`", `"")
                    }
                    $newProp += "`"}`n"
                }

                $newProp = $newProp.TrimEnd(",`n") + "`n$indent] $rest"
                $formattedLines.Add($newProp)
                continue
            }

            # Regular properties: only wrap if really long
            if ($prop.Length -gt $lineLengthLimit) {
                $prop -match '(\s*)\[(.*)\](.*)' | Out-Null
                $indent, $qualifiers, $rest = $Matches[1], $Matches[2].Trim(), $Matches[3]

                $formattedLines.Add("$indent[`n$indent  " + ($qualifiers -replace ', ', ",`n$indent  ") + "`n$indent]$rest")
            }
            else {
                $formattedLines.Add($prop)
            }
        }

        $formattedLines.Add($footer)
        $formattedLines.Add("")
    }

    return ($formattedLines -join "`n").Trim()
}


# --- Main Script Logic ---

$namespace = 'root\wmi'
$baseClassName = 'MSNT_SystemTrace'
$outputFile = "GeneratedWindowsKernelTrace-Win10.mof"

Write-Host "Discovering kernel trace classes in '$namespace'..."
$allClasses = Get-CimClass -Namespace $namespace
$classHierarchy = @{}
$allClasses | ForEach-Object { $classHierarchy[$_.CimClassName] = $_.CimSuperClassName }

$kernelClasses = [System.Collections.Generic.List[string]]::new()
@('EventTrace', $baseClassName) | ForEach-Object { $kernelClasses.Add($_) }

foreach ($className in $classHierarchy.Keys) {
    $currentClass = $className
    while ($classHierarchy[$currentClass]) {
        if ($classHierarchy[$currentClass] -eq $baseClassName) {
            $kernelClasses.Add($className); break
        }
        $currentClass = $classHierarchy[$currentClass]
    }
}

$classOrder = @{ 'EventTrace' = 1; 'MSNT_SystemTrace' = 2 }
$sortedClassNames = $kernelClasses | Sort-Object -Unique -Property @{Expression = { if ($classOrder.ContainsKey($_)) { $classOrder[$_] } else { 99 } } }, @{Expression = { $_ } }

Write-Host "Found $($sortedClassNames.Count) kernel trace classes."
Write-Host "Generating raw MOF definitions..."
$rawMofDefinitions = @()
foreach ($className in $sortedClassNames) {
    try {
        Write-Progress -Activity "Generating MOF" -Status "Processing $className"
        $mof = Get-MofRepresentationRaw -ClassName $className -Namespace $namespace
        $rawMofDefinitions += $mof
    }
    catch {
        Write-Warning "Could not generate MOF for class '$className': $_"
    }
}

Write-Host "Formatting MOF content..."
$rawContent = $rawMofDefinitions -join "`n`n"
$formattedContent = Format-MofContent -MofContent $rawContent

$header = "// Auto-generated by mofgen.ps1 on $(Get-Date)`r`n"
$header += "// Found $($sortedClassNames.Count) classes derived from $baseClassName`r`n`r`n"
$finalContent = $header + $formattedContent

Set-Content -Path $outputFile -Value $finalContent -Encoding UTF8
Write-Host "Successfully generated '$outputFile'"

# Example Usage:
# .\mofgen.ps1
# Get-MofRepresentationRaw -ClassName "FileIo_V2_MapFile"
# Get-MofRepresentationRaw -ClassName "Process_V4_TypeGroup1"