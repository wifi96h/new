# Pipeline

  # Formatting pipeline output
    formatting cmdlets
      get-command -verb format

    # displaying certain properties
      get-service | format-table -property name, status

    # display the name of each item in the current directory
      get-childitem | format-table name

    # view running services using formamt table
      get-service | where-object {$_.status -eq 'Running'} | format-table -property name, status | select-object -first 10

    # view running services using format-list
      get-service | format-list

## ---------------------------------------------------------

# Comparison Operators
<#
---- Table 1 Equality ----
| -eq, -ceq | Equals |
| -ne, -cne | Not Equal |
| -gt, -cgt | Greater Than |
| -lt, -clt | Less Than |
| -ge, -cge | Greater Than or Equal To |
| -le, -cle | Less Than or Equal To |

    # -c** case-sensitive

---- Table 2 Matching ----
| -like, -clike | Strings matching wildcard pattern |
| -notlike, -cnotlike | String does not match wildcard pattern |
| -match, -cmatch | String matches regex pattern |
| -notmatch, -cnotmatch | String does not match regex pattern |

---- Table 3 Replacement ----
| -replace, -creplace | replaces matching a regex pattern |

---- Table 4 Containment ----
| -contains, -ccontains | contains (collection of items) |
| -notcontains, -cnotcontains | Collection does not contain |
| -in | value in collection |
| -notin | value not in collection |

---- Table 5 Type ----
| -is | values are same type |
| -isnot | values are not the same type |

---- Table 6 Wildcards ----
| * | matches 0 or more characters |
| ? | match a single character |
| [a-z] | match a range of characters from a - z |
| [def] | match a set of characters |

    # will follow 'normal' regex rules -- regex101.com --
      i.e. IP Address regex: '^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'
#>

## -----------------------------------------------------------------

# Functions

<#
  function <name> {
    code to execute
  }
#>

  # get listening ports
  function network{
            Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Where-Object -Property State -eq "Listen"
  }

  # get listening network and processes, storing it in a pscustomobject with named headers
  # can update -eq with any network state
  function PNN{
            Get-NetTCPConnection | ForEach-Object {
                $connection = $_
                $processId = $connection.OwningProcess
                $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
                    if ($process) {
                        [PSCustomObject]@{
                            LocalAddress = $connection.LocalAddress
                            LocalPort = $connection.LocalPort
                            RemoteAddress = $connection.RemoteAddress
                            RemotePort = $connection.RemotePort
                            State = $connection.State
                            ProcessId = $processId
                            ProcessName = $process.ProcessName
                            ProcessPath = $process.Path
                    }
                }
            } | Where-Object -Property State -eq "Listen" | select -last 5 | Format-Table -AutoSize
        }

  # fuction with custom parameters to pull user and any additional details
  function UserInfo {
            param (
                [string]$Username,
                [switch]$IncludeDetails
            )

            if ($IncludeDetails) {
                Write-Host "Getting detailed information for user $Username"
                Get-LocalUser | Where-Object {$_.Name -eq $Username} | Select-Object -Property Name, Enabled, PasswordRequired, SID

            } else {
                Write-Host "Getting basic information for user $Username"
                Get-LocalUser | Where-object {$_.Name -eq $Username} | Select-Object -Property Name, Enabled
            }
        }


# # ---------------------------------------------------------------

# File IO

  # Out-file
  Out-File [-FilePath] <string> [[-Encoding] <Encoding>] [-Append] [-Force] [-NoClobber] [-Width <int>] [-NoNewline] [-InputObject <psobject>] [-WhatIf] [-Confirm] [<CommonParameters>]

  Get-LocalUser | Out-File -FilePath .\user.txt
  
  # Get-Content
  Get-Content -Path <path>

  Get-Content -Path .\user.txt

  # add-content
  Add-Content -Path <path> -Value <value>

  Get-Content -Path .\testfile.txt | Add-Content -Path .\testfile.txt

  # set-content
  Set-Content -Path <path> -Value <value>
  
  Set-Content -Path .\testfile.txt -Value (Get-LocalGroup).name

  # Export-CSV
  Get-Process -Name svchost | Export-Csv -path C:\Users\student\Desktop\svchost.csv

  # Import-CSV
  Import-Csv -Path C:\users\student\Desktop\svchost.csv

  # Convertto-JSON
  $eventsJSON = $events | ConvertTo-Json -Depth 5

## --------------------------------------------------------------

# Modules

  # Modules are imported automatically as needed, only has PSReadLine in new sessions
  get-module

  # manually installing modules
  Get-command install-module, install-psresource

  # see what cmdlets use the module
  Get-Command -Module NetTCPIP

  
