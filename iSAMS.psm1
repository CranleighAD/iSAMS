# Private functions

function Get-iSAMSAPIToken
{

    [CmdletBinding()]

    # Bearer token storage, in the module root folder:
    $secret_path = Join-Path -Path $MyInvocation.PSScriptRoot -ChildPath "client_secret.xml"
    Write-Verbose "Client secret path: $secret_path"
    $isams_credentials = Import-Clixml $secret_path

    # This is where the latest bearer token will be stored, along with timestamp to check expiry:
    $auth_path = Join-Path -Path $MyInvocation.PSScriptRoot -ChildPath "auth.xml"
    Write-Verbose "XML Path: $auth_path"

    # First, check if we have a bearer token stored locally:
    try
    {
        $auth = Import-Clixml -Path $auth_path -ErrorAction Stop
        $expires_in = [int]($auth.timestamp-(Get-Date)).TotalSeconds+$auth.expires_in
        Write-Verbose "Bearer token retrieved from auth.xml. Expires in $expires_in seconds."
    }
    catch
    {
        Write-Warning "No valid authentication object was imported. A new bearer token will be requested."
        $expires_in = 0
    }

    # If the bearer token has expired, request a new one:
    if($expires_in -le 0)
    {
        Write-Verbose "Expired. Requesting a new bearer token..."
        $auth_params = @{
            uri="https://isams.cranleigh.ae/Main/sso/idp/connect/token"
            method="POST"
            headers = @{
                "Content-Type"  = "application/x-www-form-urlencoded"
            }
            body = @{
                "client_id"     = $isams_credentials.UserName
                "client_secret" = $isams_credentials.GetNetworkCredential().Password
                "grant_type"    = "client_credentials"
                "scope"         = "api"
            }
        }

        try
        {
            $auth = Invoke-RestMethod @auth_params -ErrorAction Stop
        }
        catch
        {
            Write-Error "Failed to get bearer token. $($_.Exception.Message)"
            Return
        }
        $expires_in = $auth.expires_in
        $auth.access_token = ConvertTo-SecureString $auth.access_token -AsPlainText -Force
        $auth | Add-Member timestamp (Get-Date)


        Write-Output $auth | Export-Clixml -Path $auth_path
    }

    # Decode the bearer token:
    $token = (New-Object pscredential "user",$auth.access_token).GetNetworkCredential().Password
    Write-Verbose "Auth token: $token. Expires in $expires_in seconds"

    Write-Output $token
}

function Invoke-iSAMSAPIRequest
{
    <#
    .SYNOPSIS
    Invokes a generic request to the iSAMS REST API.

    .DESCRIPTION
    This is an internal function, called by other function which should supply
    the request method, resource/endpoint, query and body information.

    .PARAMETER Resource
    The iSAMS resource to be requested from the API. For example, pupils, applicants or employees.

    .PARAMETER Method
    The HTTP method for the request. This can be GET, PUT or POST.

    .PARAMETER Query
    Query parameters supplied with the request. For example, page, pageSize or filter

    .PARAMETER Body
    Body parameters supplied with the request, typically used by PUT or POST.

    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory,HelpMessage="Which resource are you conecting to? E.g. students, applicants")]
        [string]$Resource,

        [parameter(Mandatory,HelpMessage="Request method is required. E.g. GET, POST, PUT")]
        [ValidateSet("GET","POST","PUT")]
        [string]$Method,

        [parameter()]
        [string]$Query,

        [parameter()]
        [string]$Body
    )

    $BaseURL = "https://isams.cranleigh.ae/api/"
    $URI = $BaseURL + $Resource
    if($Query)
    {
        $URI = $URI + "?" + $Query
    }

    $query_params = @{
        Uri = $URI
        Method = $Method
        Headers = @{
            "Content-Type"='application/json'
            "Authorization"="Bearer $(Get-iSAMSAPIToken)"
        }
        Body = switch($Method){
            GET  {@{}}
            POST {$Body}
            PUT  {$Body}
        }
    }

    try
    {
        $response = Invoke-RestMethod @query_params -ErrorAction Stop
    }
    catch
    {
        Write-Error "$URI ($Method). $($_.Exception.Message)"
        if($Body) {Write-Verbose $Body}
    }

    Write-Output $response
}

# Public functions

function Get-iSAMSApplicant
{
    [CmdletBinding()]
    param
    (
        [parameter(ParameterSetName="ID",
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string[]]$SchoolID,

        [int]$Page=1,

        [ValidateRange (1,1000)]
        [int]$PageSize=100,
        
        [string]$Filter=""
    )

    BEGIN{}

    PROCESS
    {
        $resource = "admissions/applicants"
        $method   = "GET"

        if($SchoolID)
        {
            foreach($ID in $SchoolID)
            {
                $r="$resource/$ID"
                try
                {
                    $applicant = Invoke-iSAMSAPIRequest -Resource $r -Method $method -ErrorAction Stop
                }
                catch
                {
                    Write-Error "Error retrieving $ID. $($_.Exception.Message)"
                }
                Write-Output $applicant
            }
        }
        else
        {
            $query = ""
            if($PageSize)
            {
                $query += "pagesize=$PageSize"
            }
            if($Page)
            {
                $query += "&page=$Page"
            }
            try
            {
                $response = Invoke-iSAMSAPIRequest -Resource $resource -Method $method -Query $query
            }
            catch
            {
                Write-Warning "API request failed. $($_.Exception.Message)"
            }

            if($response.applicants)
            {
                Write-Output $response.applicants
            }
            else
            {
                Write-Output $response
            }
        }
    }
    END{}
}

function Set-iSAMSApplicant
{
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="Medium")]
    param
    (
        [parameter(Mandatory,
                   HelpMessage="The iSAMS txtSchoolID is required",
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$SchoolID,

        [string]$AdmissionStatus,
        [string]$BoardingStatus,
        [int]$CurrentSchoolID,
        [datetime]$DateOfBirth,
        [int]$EnrolmentAcademicHouseID,
        [int]$EnrolmentBoardingHouseID,
        [string]$EnrolmentSchoolForm,
        [string]$EnrolmentSchoolTerm,
        [int]$EnrolmentSchoolYear,
        [int]$EnrolmentSchoolYearGroup,
        [string]$Forename,
        [string]$Gender,
        [string]$Initials,
        [string[]]$Language,
        [string]$MiddleNames,
        [string[]]$Nationalities,
        [string]$PreferredName,
        [datetime]$RegisteredDate,
        [string]$ResidentCountry,
        [string]$SchoolCode,
        [string]$Surname,
        [string]$Title,
        [string]$UniquePupilNumber
    )

    BEGIN{}
    PROCESS
    {
        # Retrieve applicant details from iSAMS. If nothing is retrieved, issue a warning and exit.
        try
        {
            $pupil = Get-iSAMSApplicant -SchoolID $SchoolID -Verbose:$false -ErrorAction Stop
        }
        catch
        {
            Write-Warning ("Applicant $SchoolID not found in iSAMS. Hint: they may be a current pupil.")
            Return

        }
        $resource = "admissions/applicants/$SchoolID"
        $method   = "PUT"

        # Update fields from parameter values:
        $target = "$SchoolID ($($pupil.forename) $($pupil.surname))"
        $delta = @()
        foreach ($p in $PSBoundParameters.GetEnumerator())
        {
            $key   = $p.key
            $new_value = $p.value
            $current_value = $pupil.($key)
            $excluded_keys = @("SchoolID","Verbose","WhatIf","Debug","ErrorAction","ErrorVariable","WarningAction","WarningVariable")

            if($key -notin $excluded_keys)
            {
                if($new_value -ne $current_value)
                {
                    Write-Verbose "$($key): $current_value >> $new_value ($target)"
                    $pupil.($key) = $new_value
                    $delta += $key
                }
            }
        }

        # Handle any bugs in the iSAMS API:
        if($pupil.enrolmentSchoolTerm -eq "termofentry")
        {
            Write-Verbose "Fixing enrolmentSchoolTerm='termofentry'"
            $pupil.enrolmentSchoolTerm = ""
        }

        # Remove the schoolid and convert to JSON format:
        $body=($pupil | Select-Object * -ExcludeProperty schoolid | ConvertTo-Json)

        if($delta)
        {
            if ($PSCmdlet.ShouldProcess($target))
            {
                try {
                    $pupil = Invoke-iSAMSAPIRequest -Resource $resource -Method $method -Body $body -ErrorAction Stop
                    Write-Output "Success! Updated [$($delta -join ",")] for $target"
                } catch {
                    Write-Warning "Failed to update applicant data for $target. $($_.Exception.Message)"
                    Return
                }
            }
        }
        else
        {
            Write-Verbose "Nothing to update for $target"
        }
    }
    END{}
}

function Get-iSAMSPupil
{
    [CmdletBinding()]
    param
    (
        [parameter(ParameterSetName="ID",
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string[]]$SchoolID,

        [int]$Page=1,

        [ValidateRange (1,1000)]
        [int]$PageSize=100,
        
        [string]$Filter=""
    )

    BEGIN{}

    PROCESS
    {
        $resource = "students"
        $method   = "GET"

        if($SchoolID)
        {
            foreach($ID in $SchoolID)
            {
                $r="$resource/$ID"
                try
                {
                    $applicant = Invoke-iSAMSAPIRequest -Resource $r -Method $method -ErrorAction Stop
                }
                catch
                {
                    Write-Warning "Something went wrong. $($_.Exception.Message)"
                }
                Write-Output $applicant
            }
        }
        else
        {
            $query = $null
            try
            {
                $response = Invoke-iSAMSAPIRequest -Resource $resource -Method $method -Query $query
            }
            catch
            {
                Write-Warning "API request failed. $($_.Exception.Message)"
            }

            if($response.applicants)
            {
                Write-Output $response.applicants
            }
            else
            {
                Write-Output $response
            }
        }
    }
    END{}
}

function Set-iSAMSPupil
{
<#
    .SYNOPSIS

    Updates an iSAMS Pupil record via the REST API.
#>
}

function Get-iSAMSStaff
{}

function Set-iSAMSStaff
{}

function Get-iSAMSBuilding
{}

function Set-iSAMSBuilding
{}

function Get-iSAMSRoom
{}

function Set-iSAMSRoom
{}

function Get-iSAMSDepartment
{}

function Set-iSAMSDepartment
{}

function Get-iSAMSSubject
{}

function Set-iSAMSSubject
{}

function Get-iSAMSTeachingSet
{}

function Set-iSAMSTeachingSet
{}


