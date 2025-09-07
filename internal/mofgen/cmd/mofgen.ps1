# This script automatically discovers all ETW kernel trace classes from the root\wmi
# namespace and generates a complete MOF definition file, similar to the provided
# WindowsKernelTrace.mof example.

# Set strict error handling
$ErrorActionPreference = 'Stop'

# The core function to generate a MOF representation for a single CIM class.
function Get-MofRepresentation {
    param(
        [string]$ClassName,
        [string]$Namespace = 'root\wmi'
    )

    $class = Get-CimClass -Namespace $Namespace -ClassName $ClassName -ErrorAction Stop

    # --- Class Header Formatting ---
    $classQualifiersString = ($class.CimClassQualifiers | ForEach-Object {
            $qualifierString = $_.Name
            if ($_.Value) {
                if ($_.Name -eq "EventType") {
                    # Handle single value vs array for EventType
                    if ($_.Value -is [array]) {
                        $qualifierString += "{" + ($_.Value -join ", ") + "}"
                    }
                    else {
                        $qualifierString += '(' + $_.Value + ')'
                    }
                }
                elseif ($_.Name -eq "dynamic") {
                    if ($_.Value -is [bool] -and $_.Value) {
                        $qualifierString += ":ToInstance"
                    }
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

    $classHeader = ""
    if ($classQualifiersString) {
        $classHeader += "[" + $classQualifiersString + "] "
    }
    $classHeader += "class " + $ClassName

    $fullHeader = $classHeader
    if ($class.CimSuperClassName) {
        $fullHeader += " : " + $class.CimSuperClassName
    }
    $fullHeader += " {"

    if ($fullHeader.Length -gt 90 -and $class.CimSuperClassName) {
        $output = $classHeader + "`n    : " + $class.CimSuperClassName + " {"
    }
    else {
        $output = $fullHeader
    }

    # Filter for properties with WmiDataId, but also include all properties of the base MSNT_SystemTrace class
    $propertiesToInclude = $class.CimClassProperties | Where-Object {
        $_.Qualifiers['WmiDataId'] -or $ClassName -eq 'MSNT_SystemTrace'
    }

    $sortedProperties = $propertiesToInclude | Sort-Object {
        if ($_.Qualifiers['WmiDataId']) { [int]$_.Qualifiers['WmiDataId'].Value } else { 0 }
    }

    foreach ($property in $sortedProperties) {
        $qualifierObjects = [System.Collections.Generic.List[object]]::new()
        $property.Qualifiers.ForEach({ $qualifierObjects.Add($_) })

        if ($property.Name -eq 'Flags' -and $property.CimType -eq 'UInt32' -and !$property.Qualifiers['format']) {
            $qualifierObjects.Add([pscustomobject]@{ Name = 'format'; Value = 'x' })
        }

        # Custom sort order: WmiDataId first, read last, others in between alphabetically.
        $sortedQualifiers = $qualifierObjects | Sort-Object -Property @{Expression = {
                switch ($_.Name) {
                    'WmiDataId' { 0 }
                    'read' { 2 }
                    default { 1 }
                }
            }
        }, Name

        $hasWmiDataId = $null -ne $property.Qualifiers['WmiDataId']

        $propertyQualifiersList = ($sortedQualifiers | ForEach-Object {
                # Filter out inherited or implicit qualifiers
                if ($hasWmiDataId -and ($_.Name -in @('Values', 'ValueMap', 'DefineValues'))) { return }
                if ($_.Name -in @('EmbeddedObject')) { return }

                $qualifierString = $_.Name
                if ($_.Value -is [bool] -and $_.Value -eq $false) { return }

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

        $cimType = $property.CimType.ToString()
        $dataType = switch ($cimType) {
            "SInt8" { "sint8" }
            "UInt8" { "uint8" }
            "SInt16" { "sint16" }
            "UInt16" { "uint16" }
            "SInt32" { "sint32" }
            "UInt32" { "uint32" }
            "SInt64" { "sint64" }
            "UInt64" { "uint64" }
            "String" { "string" }
            "Real32" { "real32" }
            "Real64" { "real64" }
            "DateTime" { "datetime" }
            "Boolean" { "boolean" }
            "Char16" { "char16" }
            "Object" { "object" }
            "Instance" { "object" }
            Default { $cimType }
        }
        if ($dataType.EndsWith("Array")) {
            $dataType = $dataType.Substring(0, $dataType.Length - 5)
        }

        # --- Conditional Line Breaking Logic ---
        $lineLengthLimit = 90
        $propertyDefinition = " " + $dataType + " " + $property.Name + ";"
        $singleLineQualifiers = "[ " + ($propertyQualifiersList -join ", ") + " ]"
        $fullSingleLine = "  " + $singleLineQualifiers + $propertyDefinition

        if ($fullSingleLine.Length -le $lineLengthLimit) {
            $output += "`n" + $fullSingleLine
        }
        else {
            # Multi-line block format with special handling for large array qualifiers
            $qualifiersBlock = "[`n"
            $qualifierStringsForBlock = @()

            foreach ($qualifier in $sortedQualifiers) {
                # Re-format the qualifier string, but this time with multi-line support for specific arrays
                if ($hasWmiDataId -and ($qualifier.Name -in @('Values', 'ValueMap', 'DefineValues'))) { continue }
                if ($qualifier.Name -in @('EmbeddedObject')) { continue }
                if ($qualifier.Value -is [bool] -and $qualifier.Value -eq $false) { continue }

                $qualifierString = $qualifier.Name
                if ($qualifier.Value -and ($qualifier.Value -isnot [bool])) {
                    if ($qualifier.Value -is [array]) {
                        $itemsPerLine = switch ($qualifier.Name) {
                            'DefineValues' { 1 }
                            'Values'       { 2 }
                            'ValueMap'     { 4 }
                            default        { 0 }
                        }
                        if ($itemsPerLine -gt 0) {
                            $arrayValue = $qualifier.Value
                            $lines = [System.Collections.Generic.List[string]]::new()
                            for ($i = 0; $i -lt $arrayValue.Count; $i += $itemsPerLine) {
                                $end = [math]::Min($i + $itemsPerLine - 1, $arrayValue.Count - 1)
                                $lineItems = $arrayValue[$i..$end]
                                $quotedItems = $lineItems | ForEach-Object { '"{0}"' -f $_ }
                                $lines.Add(($quotedItems -join ', '))
                            }
                            $indent = "      " # 6 spaces
                            $qualifierString += "{`n$indent  " + ($lines -join ",`n$indent  ") + "`n$indent}"
                        }
                        else {
                            $qualifierString += '{"' + ($qualifier.Value -join '", "') + '"}'
                        }
                    }
                    elseif ($qualifier.Value -is [string]) {
                        $qualifierString += '("' + $qualifier.Value + '")'
                    }
                    else {
                        $qualifierString += '(' + $qualifier.Value + ')'
                    }
                }
                $qualifierStringsForBlock += $qualifierString
            }
            $qualifiersBlock += "    " + ($qualifierStringsForBlock -join ",`n    ")
            $qualifiersBlock += "`n  ]"
            $output += "`n  " + $qualifiersBlock + $propertyDefinition
        }
    }

    $output += "`n};"
    return $output
}

# --- Main Script Logic ---

$namespace = 'root\wmi'
$baseClassName = 'MSNT_SystemTrace'
$outputFile = "GeneratedWindowsKernelTrace.mof"

Write-Host "Discovering kernel trace classes in '$namespace'..."

# 1. Get all classes and build a quick lookup map of child -> parent relationships.
Write-Host "Building class hierarchy map..."
$allClasses = Get-CimClass -Namespace $namespace
$classHierarchy = @{}
foreach ($class in $allClasses) {
    $classHierarchy[$class.CimClassName] = $class.CimSuperClassName
}

# 2. Find all classes that derive from the base class.
Write-Host "Finding all classes derived from '$baseClassName'..."
$kernelClasses = [System.Collections.Generic.List[string]]::new()
$kernelClasses.Add('EventTrace')       # Add the ultimate base class
$kernelClasses.Add($baseClassName) # Add the main base class itself

foreach ($className in $classHierarchy.Keys) {
    $currentClass = $className
    # Walk up the inheritance chain for the current class
    while ($classHierarchy[$currentClass]) {
        if ($classHierarchy[$currentClass] -eq $baseClassName) {
            $kernelClasses.Add($className)
            break # Found it, no need to check further up
        }
        $currentClass = $classHierarchy[$currentClass]
    }
}

# Define a specific order for the base classes, then sort the rest alphabetically.
$classOrder = @{
    'EventTrace'       = 1
    'MSNT_SystemTrace' = 2
}
$sortedClassNames = $kernelClasses | Sort-Object -Unique -Property @{Expression = {
        if ($classOrder.ContainsKey($_)) { $classOrder[$_] } else { 99 }
    } }, @{Expression = {$_} }

Write-Host "Found $($sortedClassNames.Count) kernel trace classes."

# 3. Generate the MOF for each discovered class.
Write-Host "Generating MOF definitions..."
$mofDefinitions = @()
foreach ($className in $sortedClassNames) {
    try {
        Write-Progress -Activity "Generating MOF" -Status "Processing $className" -PercentComplete (($mofDefinitions.Count * 100) / $sortedClassNames.Count)
        $mof = Get-MofRepresentation -ClassName $className -Namespace $namespace
        $mofDefinitions += $mof
    }
    catch {
        Write-Warning "Could not generate MOF for class '$className': $_"
    }
}

# 4. Combine all definitions and write to the output file.
$header = "// Auto-generated by mofgen.ps1 on $(Get-Date)`r`n"
$header += "// Found $($sortedClassNames.Count) classes derived from $baseClassName`r`n`r`n"
$finalContent = $header + ($mofDefinitions -join "`r`n`r`n")

Set-Content -Path $outputFile -Value $finalContent -Encoding UTF8

Write-Host "Successfully generated '$outputFile'"

# Example Usage:
# Get-MofRepresentation -ClassName "FileIo_V2_MapFile"
# Get-MofRepresentation -ClassName "Process_V4_TypeGroup1"