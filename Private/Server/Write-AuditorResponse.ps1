function Write-AuditorHttpResponse {
    <#
    .SYNOPSIS
        Writes a raw HTTP/1.1 response to a NetworkStream.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.Sockets.NetworkStream]$Stream,

        [int]$StatusCode = 200,

        [Parameter(Mandatory)]
        [string]$ContentType,

        [Parameter(Mandatory)]
        [byte[]]$Body,

        [string]$ContentDisposition = ''
    )

    $statusText = switch ($StatusCode) {
        200     { 'OK' }
        204     { 'No Content' }
        400     { 'Bad Request' }
        401     { 'Unauthorized' }
        404     { 'Not Found' }
        405     { 'Method Not Allowed' }
        409     { 'Conflict' }
        500     { 'Internal Server Error' }
        default { 'OK' }
    }

    $header = [System.Text.StringBuilder]::new()
    [void]$header.AppendLine("HTTP/1.1 $StatusCode $statusText")
    [void]$header.AppendLine("Content-Type: $ContentType")
    [void]$header.AppendLine("Content-Length: $($Body.Length)")
    if ($ContentDisposition) {
        [void]$header.AppendLine("Content-Disposition: $ContentDisposition")
    }
    [void]$header.AppendLine('Connection: close')
    [void]$header.AppendLine('Cache-Control: no-store, no-cache')
    [void]$header.AppendLine('X-Content-Type-Options: nosniff')
    [void]$header.AppendLine('')  # blank line separating headers from body

    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header.ToString())
    $Stream.Write($headerBytes, 0, $headerBytes.Length)

    if ($Body.Length -gt 0) {
        $Stream.Write($Body, 0, $Body.Length)
    }
    $Stream.Flush()
}

function Write-AuditorJsonResponse {
    <#
    .SYNOPSIS
        Serialises $Data to JSON and writes it as an HTTP response.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.Sockets.NetworkStream]$Stream,

        [Parameter(Mandatory)]
        [object]$Data,

        [int]$StatusCode = 200
    )

    $json  = $Data | ConvertTo-Json -Depth 10 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    Write-AuditorHttpResponse -Stream $Stream -StatusCode $StatusCode `
        -ContentType 'application/json; charset=utf-8' -Body $bytes
}

function Write-AuditorFileResponse {
    <#
    .SYNOPSIS
        Reads a file from disk and writes it as an HTTP response.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.Sockets.NetworkStream]$Stream,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [switch]$AsDownload
    )

    $ext         = [System.IO.Path]::GetExtension($FilePath).ToLower()
    $contentType = switch ($ext) {
        '.html' { 'text/html; charset=utf-8' }
        '.css'  { 'text/css; charset=utf-8' }
        '.js'   { 'application/javascript; charset=utf-8' }
        default { 'application/octet-stream' }
    }

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $disposition = if ($AsDownload) {
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        "attachment; filename=`"$fileName`""
    } else { '' }
    Write-AuditorHttpResponse -Stream $Stream -StatusCode 200 `
        -ContentType $contentType -Body $bytes -ContentDisposition $disposition
}

function Write-AuditorErrorResponse {
    <#
    .SYNOPSIS
        Writes a JSON error response.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.Sockets.NetworkStream]$Stream,

        [Parameter(Mandatory)]
        [string]$Message,

        [int]$StatusCode = 500
    )

    Write-AuditorJsonResponse -Stream $Stream -StatusCode $StatusCode `
        -Data @{ error = $Message }
}
