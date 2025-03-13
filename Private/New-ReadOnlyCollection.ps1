function New-ReadOnlyCollection {
  [CmdletBinding()][Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Justification = "Not changing state")]
  param (
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()][Alias('list')]
    [Object[]]$array
  )

  process {
    if ($array.Count -eq 0) { throw [System.InvalidOperationException]::new("New-ReadOnlyCollection : NullOrEmpty InputObject, WTF man?!") }
    [string]$typeName = $array[0].GetType().Name; [ValidateNotNullOrWhiteSpace()][string]$typeName = $typeName
    $NewCollection = [scriptblock]::Create("param (`$i)`n`$l = [System.Collections.Generic.List[$typeName]]::new(`$i.objects.Count);`n`$i.objects.GetEnumerator().ForEach({ [void]`$l.Add(`$_) });`nreturn [System.Collections.ObjectModel.ReadOnlyCollection[$typeName]]::new(`$l);")
    return $NewCollection.Invoke([PSCustomObject]@{
        objects = $array
      }
    )
  }
}