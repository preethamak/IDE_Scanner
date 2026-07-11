rule ide_scanner_unicode_evasion
{
  meta:
    description = "Bidirectional or invisible Unicode control bytes in executable content"
  strings:
    $bidi_1 = { E2 80 AA }
    $bidi_2 = { E2 80 AB }
    $bidi_3 = { E2 80 AC }
    $bidi_4 = { E2 80 AD }
    $bidi_5 = { E2 80 AE }
    $isolate_1 = { E2 81 A6 }
    $isolate_2 = { E2 81 A7 }
    $isolate_3 = { E2 81 A8 }
    $isolate_4 = { E2 81 A9 }
  condition:
    any of them
}

rule ide_scanner_encoded_dynamic_execution
{
  meta:
    description = "Encoded payload handling combined with dynamic execution"
  strings:
    $decode_1 = "Buffer.from" ascii
    $decode_2 = "base64" ascii nocase
    $decode_3 = "fromCharCode" ascii
    $execute_1 = "eval(" ascii
    $execute_2 = "new Function" ascii
    $execute_3 = "runInThisContext" ascii
  condition:
    1 of ($decode_*) and 1 of ($execute_*)
}

rule ide_scanner_embedded_pe
{
  meta:
    description = "Portable executable content embedded away from the start of a file"
  strings:
    $mz = { 4D 5A }
  condition:
    $mz in (1..filesize)
}
