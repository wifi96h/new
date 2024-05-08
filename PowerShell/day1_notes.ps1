Powershell

Verb-Noun
  i.e. 
  get-winevent
  set-etwtracesession
  add-bitsfile

Common verbs
  get, set, move, new, add

search commands
  get-command -verb <verb>
  get-command -noun <noun>

get-winevent -logname 'windows powershell' -computername server1 -verbose
cmdlet name  1st para                      2nd para              switch para


**useful**
get-command
get-member
get-help
  get-help <> -online
  get-help <> -showwindow


## -----------------------------------------------------------------
  Variables

get-variable

$<var> = thing
  $proc = get-process -name 'adobe'

view automatic variables with descriptions
Get-Variable | Sort-Object Name | Format-Table Name, Description -autosize -wrap

pull environmental variables
  $env:userprofile

<#
variable types
  string
  int
  array
  char
  byte
  long
  single
  double
  date-time
#>

# get variable type
  ($var).gettype()


## -------------------------------------------------------------

Parameter sets

Named para
	-pid #
switch para
	-full
 	-force
  	-recursive
pos para
	-path <path>

 ## ------------------------------------------------------------

 Alias

$alias:dir

find alias
	get-alias -definition get-childitem
	get-alias -definition get-content

create alias
	set-alias -name <> -value <>
	set-alias -name edit -value notepad.exe

remove alias
	remove-item alias:<>
	remove-item alias:edit

## -------------------------------------------------------------------

Objects

get specific property
	(get-process).processname
	(get-process).id

stop a process
	(get-process notepad).kill()

view properties and methods
	get-service | get-member
 	get-member -inputobject get-service

##----------------------------------------------------------------------

Get-Member command

list all available members 
	get-process | get-member

list properties of get-process
	Get-Process | Get-Member -MemberType Properties

list methods of get-process
	Get-Process | Get-Member -MemberType method

## --------------------------------------------------------------------

Logging
creating transcript
	$transcript = "C:\Users\Student\Desktop\transcript.log"
 	start-transcript -path $transcript
  -or-
  	start-transcript -path $transcript -append -includeinvocationheader

stopping transcripts
	Stop-Transcript

##----------------------------------------------------------------------

script block logging

verify script block logging is enabled
	local group policy editor
 		computer configuration
			administrative templates
   				windows components
		  			windows powershell
		  				turn on powershell script block logging
							edit policy setting

	$ScriptBlockLoggingEnabled = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
	if ($ScriptBlockLoggingEnabled -and $ScriptBlockLoggingEnabled.EnableScriptBlockLogging -eq 1) {
              Write-Host "Script Block Logging is Enabled."
        } else {
              Write-Host "Script Block Logging is not Enabled."
        }

  
