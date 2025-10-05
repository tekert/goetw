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

# Stage 2: Formats a raw MOF string with wrapping and indentation rules.
# ( AI CODE don't look, just works)
function Format-MofContent {
    param([string]$MofContent)

    $lineLengthLimit = 90
    $formattedLines = [System.Collections.Generic.List[string]]::new()
    $blocks = $MofContent -split '(?=^\[.*\]\s*(?:abstract\s+)?class|^class)'

    foreach ($block in $blocks) {
        if ($block.Trim().Length -eq 0) { continue }

        $allLines = $block.Trim() -split "`n"
        $headerIndex = [array]::FindIndex($allLines, [Predicate[string]] { param($line) $line -match 'class\s' })
        if ($headerIndex -lt 0) { $headerIndex = 0 }

        $header = $allLines[$headerIndex]
        $properties = if ($allLines.Count -gt ($headerIndex + 2)) { $allLines[($headerIndex + 1)..($allLines.Count - 2)] } else { @() }
        $footer = $allLines[-1]

        # --- Unified Formatting for Headers and Properties ---
        $linesToProcess = @($header) + $properties
        $formattedBlock = [System.Collections.Generic.List[string]]::new()

        foreach ($line in $linesToProcess) {
            # Special case for the complex MSNT_SystemTrace.Flags property
            if ($line.Contains("class MSNT_SystemTrace") -or $line.Contains("] uint32 Flags;")) {
                if ($line.Contains("] uint32 Flags;")) {
                    $line -match '(\s*)\[(.*)\](.*)' | Out-Null
                    $indent, $qualifiersStr, $rest = $Matches[1], $Matches[2].Trim(), $Matches[3]
                    $formattedQualifiers = [System.Collections.Generic.List[string]]::new()
                    $qualifiers = $qualifiersStr -split '(?=DefineValues|format|ValueMap|Values)' | ForEach-Object { $_.Trim().TrimEnd(',') }

                    foreach ($q in $qualifiers) {
                        if ($q.StartsWith("DefineValues") -or $q.StartsWith("Values") -or $q.StartsWith("ValueMap")) {
                            $q -match '([a-zA-Z]+)\{(.*)\}' | Out-Null
                            $qName, $qValues = $Matches[1], $Matches[2]
                            $values = $qValues -split ',\s*'
                            $formattedQ = "$indent  $qName{`n"
                            $currentSubLine = "$indent    "
                            foreach ($v in $values) {
                                if (($currentSubLine.Length + $v.Length + 2) -gt $lineLengthLimit) {
                                    $formattedQ += $currentSubLine.TrimEnd().TrimEnd(',') + ",`n"
                                    $currentSubLine = "$indent    "
                                }
                                $currentSubLine += "$v, "
                            }
                            $formattedQ += $currentSubLine.TrimEnd().TrimEnd(',') + "`n$indent  }"
                            $formattedQualifiers.Add($formattedQ)
                        }
                        elseif ($q) { $formattedQualifiers.Add("$indent  $q") }
                    }
                    $formattedBlock.Add("$indent[`n" + ($formattedQualifiers -join ",`n") + "`n$indent]$rest")
                    continue
                }
            }

            # Generic formatting for all other lines
            if (($line.Length -gt $lineLengthLimit) -and $line.Trim().StartsWith("[")) {
                $line -match '(\s*)\[(.*)\](.*)' | Out-Null
                $indent, $qualifiersStr, $rest = $Matches[1], $Matches[2].Trim(), $Matches[3]
                $formattedQualifiers = $qualifiersStr

                # Strategy 1: If the line is long due to an EventType, wrap the numbers inside it.
                $match = [regex]::Match($qualifiersStr, '(EventType\{[^\}]+\})')
                if ($match.Success) {
                    $eventQualifier = $match.Groups[1].Value
                    $eventQualifier -match 'EventType\{([^\}]+)\}' | Out-Null
                    $eventNumbers = $Matches[1].Trim() -split ',\s*'

                    # FIX: The previous arbitrary length check was unreliable.
                    # This now wraps only if there are a significant number of events (more than 10).
                    if ($eventNumbers.Count -gt 10) {
                        $numberLines, $itemsPerLine = @(), 10
                        for ($j = 0; $j -lt $eventNumbers.Count; $j += $itemsPerLine) {
                            $chunk = $eventNumbers[$j..([Math]::Min($j + $itemsPerLine - 1, $eventNumbers.Count - 1))]
                            $numberLines += ($chunk -join ", ")
                        }
                        $numberIndent = "            " # 12 spaces for alignment
                        $wrappedNumbers = $numberLines[0]
                        if ($numberLines.Count -gt 1) {
                            $wrappedNumbers += ",`n" + $numberIndent + ($numberLines[1..($numberLines.Count - 1)] -join ",`n" + $numberIndent)
                        }
                        $newQualifier = "EventType{" + $wrappedNumbers + "}"
                        $formattedQualifiers = $qualifiersStr.Replace($eventQualifier, $newQualifier)
                    }
                }

                # Strategy 2: If the line is still too long, wrap the top-level qualifiers.
                $tempLine = "$indent[" + $formattedQualifiers + "]$rest"
                if ($tempLine.Contains("`n") -eq $false -and $tempLine.Length -gt $lineLengthLimit) {
                    $indentForNextLines = $indent + "  "
                    $formattedQualifiers = ($qualifiersStr -replace ',(?![^{]*})', ",`n$indentForNextLines")
                }
                $formattedBlock.Add("$indent[" + $formattedQualifiers + "]$rest")
            }
            else {
                $formattedBlock.Add($line)
            }
        }

        # Re-assemble the block
        if ($properties.Count -eq 0) {
            $formattedBlock[0] = $formattedBlock[0] -replace ' {$', '{}'
        }
        $formattedLines.Add($formattedBlock -join "`n")
        $formattedLines.Add($footer)
        $formattedLines.Add("")
    }

    return ($formattedLines -join "`n").Trim()
}


# --- Main Script Logic ---

$namespace = 'root\wmi'
$baseClassName = 'MSNT_SystemTrace'
$outputFile = "_GeneratedWindowsKernelTrace-Win10.mof"

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