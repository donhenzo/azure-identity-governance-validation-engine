# ValidateIdentity/run.ps1
#
# HTTP trigger wrapper for the PowerShell validation engine.
# Receives a JSON request from the JML Python engine,
# calls ValidationEngine.ps1 with the correct parameters,
# and returns a structured JSON response.
#
# Request body — PreProvision (payload mode, no Entra object exists yet):
#   { "mode": "PreProvision", "payload": { ...IdentityPayload fields... } }
#
# Request body — PostProvision (tenant scan against real object):
#   { "mode": "PostProvision", "targetUserId": "entra-object-id" }
#
# Response contract (Python validation gate expects this exact shape):
#   {
#     "passed": true/false,
#     "failures": [ { "ruleId": "", "category": "", "severity": "", "details": "" } ],
#     "warnings": [ { "ruleId": "", "category": "", "severity": "", "details": "" } ],
#     "matchedRuleIds": []
#   }

using namespace System.Net

param($Request, $TriggerMetadata)

# Parse and validate request body

$body = $Request.Body

if (-not $body) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::BadRequest
        Body       = '{"error": "Request body is required"}'
        Headers    = @{ "Content-Type" = "application/json" }
    })
    return
}

$mode = $body.mode

if (-not $mode) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::BadRequest
        Body       = '{"error": "mode field is required: PreProvision or PostProvision"}'
        Headers    = @{ "Content-Type" = "application/json" }
    })
    return
}

# Resolves the  path to ValidationEngine.ps1 
$enginePath = Join-Path $PSScriptRoot ".." "ValidationEngine.ps1"

if (-not (Test-Path $enginePath)) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::InternalServerError
        Body       = '{"error": "ValidationEngine.ps1 not found"}'
        Headers    = @{ "Content-Type" = "application/json" }
    })
    return
}

# this function calls the validation engine 
try {
    if ($mode -eq "PreProvision") {

        if (-not $body.payload) {
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = '{"error": "payload field is required for PreProvision mode"}'
                Headers    = @{ "Content-Type" = "application/json" }
            })
            return
        }

        # Serialise payload back to JSON string for the engine parameter
        $payloadJson = $body.payload | ConvertTo-Json -Depth 10

        $result = & $enginePath `
            -Mode            PreProvision `
            -IdentityPayload $payloadJson

    } elseif ($mode -eq "PostProvision") {

        if (-not $body.targetUserId) {
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = '{"error": "targetUserId field is required for PostProvision mode"}'
                Headers    = @{ "Content-Type" = "application/json" }
            })
            return
        }

        $result = & $enginePath `
            -Mode         PreProvision `
            -TargetUserId $body.targetUserId

    } else {
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = "{`"error`": `"Unknown mode: $mode`"}"
            Headers    = @{ "Content-Type" = "application/json" }
        })
        return
    }

    # Translate internal engine result to the HTTP response contract.
    # Blocking = true  → failures (hard block, provisioning must not proceed)
    # Blocking = false → warnings (logged in report, provisioning continues)
    # Exception: HYG-* findings in PostProvision mode are demoted to warnings.
    # Rules like MFA state, inactivity, and password age are operational signals —
    # they cannot be enforced at the point of provisioning and should not fail
    # the event. They still appear in the audit report as warnings.
    $isPostProvision = ($mode -eq "PostProvision")

    $failures = @(
        $result.Findings |
        Where-Object {
            $_.Blocking -eq $true -and
            -not ($isPostProvision -and $_.RuleId -like 'HYG-*')
        } |
        ForEach-Object {
            @{
                ruleId   = $_.RuleId
                category = $_.Category
                severity = $_.Severity
                details  = $_.Details
            }
        }
    )

    $warnings = @(
        $result.Findings |
        Where-Object {
            $_.Blocking -eq $false -or
            ($isPostProvision -and $_.RuleId -like 'HYG-*')
        } |
        ForEach-Object {
            @{
                ruleId   = $_.RuleId
                category = $_.Category
                severity = $_.Severity
                details  = $_.Details
            }
        }
    )

    $matchedRuleIds = @(
        $result.Findings |
        Where-Object { $_.RuleId } |
        Select-Object -ExpandProperty RuleId |
        Select-Object -Unique
    )

    $response = @{
        passed         = ($failures.Count -eq 0)
        failures       = $failures
        warnings       = $warnings
        matchedRuleIds = $matchedRuleIds
    }

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = ($response | ConvertTo-Json -Depth 10)
        Headers    = @{ "Content-Type" = "application/json" }
    })

} catch {
    $errorDetail = @{
        error  = "Validation engine error"
        detail = $_.Exception.Message
        mode   = $mode
    } | ConvertTo-Json

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::InternalServerError
        Body       = $errorDetail
        Headers    = @{ "Content-Type" = "application/json" }
    })
}