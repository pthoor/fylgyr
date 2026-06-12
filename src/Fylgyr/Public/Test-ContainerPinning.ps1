function Test-ContainerPinning {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($wf in $WorkflowFiles) {
        $lines = ($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }

        # Collect every container image reference a workflow can pull:
        # docker:// action uses, job-level container:, and services: images.
        $imageReferences = [System.Collections.Generic.List[string]]::new()
        foreach ($line in $lines) {
            if ($line -match '^\s*-?\s*uses\s*:\s*[''"]?docker://(?<image>[^\s''"#]+)') {
                $imageReferences.Add($Matches.image)
                continue
            }

            if ($line -match '^\s*(?:image|container)\s*:\s*[''"]?(?<image>[^\s''"#]+)') {
                $imageReferences.Add($Matches.image)
            }
        }

        # Expressions cannot be resolved statically; skip them rather than guess.
        $resolvable = @($imageReferences | Where-Object { $_ -notmatch '\$\{\{' })
        if ($resolvable.Count -eq 0) {
            continue
        }

        $floatingImages = [System.Collections.Generic.List[string]]::new()
        $taggedImages = [System.Collections.Generic.List[string]]::new()

        foreach ($image in $resolvable) {
            if ($image -match '@sha256:[a-fA-F0-9]{64}$') {
                continue
            }

            # The tag lives after the last path segment; a colon before the final
            # slash is a registry port, not a tag.
            $lastSegment = ($image -split '/')[-1]
            if ($lastSegment -notmatch ':' -or $image -match ':latest$') {
                $floatingImages.Add($image)
            }
            else {
                $taggedImages.Add($image)
            }
        }

        if ($floatingImages.Count -eq 0 -and $taggedImages.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'ContainerPinning' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' pins all $($resolvable.Count) container image reference(s) to immutable sha256 digests." `
                -Remediation 'No action needed.'))
            continue
        }

        $unpinnedDescriptions = [System.Collections.Generic.List[string]]::new()
        foreach ($image in @($floatingImages | Sort-Object -Unique)) {
            $unpinnedDescriptions.Add("$image (floating - resolves to :latest)")
        }
        foreach ($image in @($taggedImages | Sort-Object -Unique)) {
            $unpinnedDescriptions.Add("$image (mutable tag)")
        }

        $severity = if ($floatingImages.Count -gt 0) { 'High' } else { 'Medium' }

        $results.Add((Format-FylgyrResult `
            -CheckName 'ContainerPinning' `
            -Status 'Fail' `
            -Severity $severity `
            -Resource $wf.Path `
            -Detail "Workflow '$($wf.Name)' pulls container image(s) by mutable reference: $($unpinnedDescriptions -join ', '). Tags and :latest can be silently retargeted by anyone who controls the registry account or namespace, so a registry compromise (as in the 2019 Docker Hub credential breach) puts attacker-controlled code directly into CI jobs that hold secrets and tokens." `
            -Remediation 'Pin container images to an immutable digest (image@sha256:...) for docker:// uses, job container: blocks, and services: images. Use dependabot or renovate to keep the pinned digest updated.' `
            -AttackMapping @('docker-hub-credential-breach', 'trivy-tag-poisoning')))
    }

    $results.ToArray()
}
