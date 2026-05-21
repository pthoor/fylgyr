param($Timer)

$owner = $env:FYLGYR_OWNER
$repo = $env:FYLGYR_REPO

if (-not $owner) {
    throw 'FYLGYR_OWNER environment variable is required.'
}

$scanLines = Invoke-Fylgyr -Owner $owner -Repo $repo -Mode Both -OutputFormat LogAnalytics

$scanLines |
    Send-FylgyrToLogAnalytics `
        -DcrImmutableId $env:FYLGYR_DCR_IMMUTABLE_ID `
        -DceUri $env:FYLGYR_DCE_URI `
        -StreamName 'Custom-FylgyrRaw' `
        -UseManagedIdentity
