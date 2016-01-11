param (
[alias("h")]
$ip,
[alias("c")]
$config,
[alias("u")]
$userid,
[alias("p")]
$password,
[alias("f")]
$format="t",
[alias("o")]
$outfile="out.txt"
)

function helpsyntax {
write-host "PANAUDIT - Security Audit of Palo Alto Firewall"
write-host "(c) Center for Internet Security, 2016"
write-host "Parameters:"
write-host "    -ip          <ip or hostname of firewall to audit>"
write-host "    -config      <saved configuration filename>"
write-host "    -userid    <userid for collection of configuration>"
write-host "    -password    <password>"
write-host "    -format      <t for text, h for html - default is text>`n`n"
write-host "    -o           <output file name - blank = console"
write-host "Host and config parameters are mutually exclusive"
write-host "Host parameter requires userid and password"
}

# Check for inconsistencies in config parameters (or no parameters)

if (($ip.length -eq 0) -and ($config.length -eq 0)) { write-host "ERROR: Must specify either Host or Configuration File (neither is set)`n`n" ; helpsyntax }
if (($ip.length -gt 0) -and ($config.length -gt 0)) { write-host "ERROR: Cannot specify both Host and Configuration File`n`n" ; helpsyntax }
if (($ip.length -gt 0) -and (($userid.length -eq 0) -or ($password.length -eq 0))) { write-host "ERROR: Must specify both userid Password`n`n"; helpsyntax }

$CRLF = "`n"

if (($format -eq "t") -or ($format -eq "c")) {
$h1 = $CRLF + "===========================================================" + $CRLF
$eh1 = $CRLF + "===========================================================" + $CRLF
$h2= $CRLF + "===========================================================" + $CRLF
$eh2= $CRLF + "===========================================================" + $CRLF
$h3= $CRLF + "===========================================================" + $CRLF
$eh3= $CRLF + "===========================================================" + $CRLF
$b = "`n-------------------------`n"
$eb = "`n-------------------------`n"
$pre = "" 
$epre = ""
$COMPLIANT = "COMPLIANT"
$NONCOMPLIANT = "NOT COMPLIANT"
$TMANUAL = "MANUAL ASSESSMENT _____________________________"
$MANUAL = $MANUAL
}
else
{
$h1 = "<H1>"
$eh1 = "</H1>"
$h2 = "<H2>"
$eh2= "</H2>"
$h3 = "<H3><H3><HR><p style=`"background-color: #C0C0C0;`">"
$eh3= "</H3>"
$b = "<b>"
$eb = "</b>"
$pre = "<pre>" 
$epre = "</pre>"
$CRLF = "</p>"
$p = "</p>"
$ep = "</p>"
$COMPLIANT = "<FONT COLOR=LIME><b>COMPLIANT</b></FONT>"
$NONCOMPLIANT = "<FONT COLOR=RED><b>NOT COMPLIANT</b></FONT>"
$TMANUAL = "<b>MANUAL ASSESSMENT _____________________________</b>"
$MANUAL = "MANUAL ASSESSMENT _____________________________"
}

filter out {
if ($format -eq "t") {
out-host $_
}
if ($format -eq "h") {
out-file -$outfile $_ -append
}
}

#
# Collect Configuration data in XML format
#
"DATA COLLECTION IN PROGRESS"

if ($config.length -gt 0) {
# read config from file
# this limits the effectiveness of some tests
write-host "reading config from" $config
[xml] $xcfg = get-content $config
} 
else 
{
# pull config from running firewall

$netAssembly = [Reflection.Assembly]::GetAssembly([System.Net.Configuration.SettingsSection])

    $bindingFlags = [Reflection.BindingFlags] "Static,GetProperty,NonPublic"
    $settingsType = $netAssembly.GetType("System.Net.Configuration.SettingsSectionInternal")

    $instance = $settingsType.InvokeMember("Section", $bindingFlags, $null, $null, @())

    if($instance)
    {
        $bindingFlags = "NonPublic","Instance"
        $useUnsafeHeaderParsingField = $settingsType.GetField("useUnsafeHeaderParsing", $bindingFlags)

        if($useUnsafeHeaderParsingField)
        {
          $useUnsafeHeaderParsingField.SetValue($instance, $true)
        }
    }


[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# get key
$apicall = "/api/?type=keygen"
$uri = "https://"+$ip+$apicall+"&user="+$userid+"&password="+$password

$wc = New-Object System.Net.WebClient
$wfs = New-Object System.Net.WebClient
$has = New-Object System.Net.WebClient
$sys = New-Object System.Net.WebClient
$sysi = New-Object System.Net.WebClient
$urll = New-Object System.Net.WebClient
start-sleep 3

[xml] $keyxml = $wc.downloadstring($uri)
$key = $keyxml.selectnodes("//key")."#text"

if($key.length -eq 0) {"`nERROR - Credential Mismatch or Connection Error`n        Cannot Connect to Firewall" ; break }

# now get configuration

$apicall = "/api/?type=export&category=configuration"
$uri = "https://"+$ip+$apicall+"&key="+$key

[xml] $xcfg = $wc.downloadstring($uri)

# next get wildfire status

$apicall = "/api/?type=op&cmd=<show><wildfire><status></status></wildfire></show>"
$uri = "https://"+$ip+$apicall+"&key="+$key

[xml] $wfstatus = $wfs.downloadstring($uri)

# next get HA status

$apicall = "/api/?type=op&cmd=<show><high-availability><all></all></high-availability></show>"
$uri = "https://"+$ip+$apicall+"&key="+$key


[xml] $hastatus = $has.downloadstring($uri)

# next get system state

$apicall = "/api/?type=op&cmd=<show><system><state></state></system></show>"
$uri = "https://"+$ip+$apicall+"&key="+$key

[xml] $sysstateraw = $sys.downloadstring($uri)
# this data is a mess - in no good format - convert to an array
$sysstate = $sysstate.response.result.'#cdata-section'.split("`n")

# next get url license
$apicall = "/api/?type=op&cmd=<show><running><url-license></url-license></running></show>"
$uri = "https://"+$ip+$apicall+"&key="+$key

[xml] $urllic = $urll.downloadstring($uri)

$apicall = "/api/?type=op&cmd=<show><system><info></info></system></show>"
$uri = "https://"+$ip+$apicall+"&key="+$key

[xml] $sysinfo = $sysi.downloadstring($uri)

}

"DATA COLLECTION COMPLETED"

# Title
$date = date
$hostname = $xcfg.selectnodes("//deviceconfig").system.hostname

$title =  $H1 + "Palo Alto Security Audit - CIS Benchmark " +$EH1
$title +=  $H2 + "Script Version " + $scriptver +$EH2 +$CRLF

$title += $b+"Host Name: "+ $hostname + $eb + $CRLF
$title += $b+"IP targeted: "+ $ip + $eb + $CRLF
$title += $b+"Report Date: "+$eb + $date + $CRLF + $EH1
$title += $b+"Platform Family: "+$eb + $sysinfo.response.result.system.family +$p
$title += $b+"Model: "+$eb+ $sysinfo.response.result.system.model +$p

if($sysinfo.response.result.system.family -like "*vm*") {
$varstring = $sysstate | select-string "cfg.platform.virt-host:"
$hypervisor = $varstring -replace "cfg.platform.virt-host: ",""
$title += $b+"Hypervisor: "+$eb+ $hypervisor +$p
$title += $b+"VM License: "+$eb + $sysinfo.response.result.system."vm-license" +$p
}

$title += $b+"Version: "+$eb+ $sysinfo.response.result.system."sw-version" + $CRLF
$title += $b+"Dates: "+$eb +$p
$title += $b+"GlobalProtect: "+$eb+$sysinfo.response.result.system."global-protect-datafile-release-date"+$p
$title += $b+"URL Filtering: "+$eb+$sysinfo.response.result.system."url-filtering-version"+$p
$title += $b+"Threats: "+$eb+$sysinfo.response.result.system."threat-release-date" +$p
$title += $b+"Applications: "+$eb+$sysinfo.response.result.system."app-release-date" +$p
$title += $b+"Wildfire: "+$eb+$sysinfo.response.result.system."wildfire-release-date" +$p
$title += $b+"Antivirus: "+$eb+$sysinfo.response.result.system."av-release-date" +$CRLF


# or maybe:
# $title += $sysinfo.response.result.system
# need to use css though for formatting
# and add hypervisor check

tee -filepath $outfile -inputobject $title

# ================
# compute Internet Facing Interfaces and Zones
# any interface with a default gateway is deemed "internet facing"
# any zone on an internet facing interface is also internet facing

$internetinterfaces = @()
$router = $xcfg.selectnodes("//virtual-router")
$router.entry | foreach { 
$_."routing-table".ip."static-route".entry | foreach {
if ($_.destination -eq "0.0.0.0/0") { 
$internetinterfaces += $_.interface 
}
}}

$internetzones = @()
$vsys = $xcfg.selectnodes("//vsys")
$vsys | foreach { 
$vsysname = $_.name ; $_.entry.zone.entry | foreach { 
if ($internetinterfaces -contains $_.network.layer3.member) { $internetzones += $_.name }
}}


# BENCHMARKS

# ===========================================
# LOGIN BANNER
# ===========================================

$title = "Benchmark: Login Banner"

# RAW DATA
$rawdata = $xcfg.SelectNodes("//system")."login-banner"

#COMPUTE COMPLIANCE
if ($rawdata.length -gt 0) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre + $rawdata + $epre) -append  






# ===========================================
# enable-log-high-dp-load
# ===========================================
$title = "Benchmark: enable-log-high-dp-load"


# RAW DATA
$rawdata = $xcfg.SelectNodes("//enable-log-high-dp-load")."#text"

#COMPUTE COMPLIANCE
if ($rawdata -eq "yes") {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre + $rawdata + $epre) -append  

# ===========================================
# disable http and telnet administration
# ===========================================
$title = "Benchmark: Disable Plaintext Administration (http and telnet)"


# RAW DATA
$rawdata_tel = $xcfg.SelectNodes("//service")."disable-telnet"
$rawdata_http = $xcfg.SelectNodes("//service")."disable-http"

#COMPUTE COMPLIANCE
if (($rawdata_tel -eq "yes") -and ($rawdata_http -eq "yes")) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
"telnet disabled - "+$rawdata_tel
"http disabled - "+$rawdata_http

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre + "Telnet Disabled -" + $rawdata_tel + $epre) -append  
Out-File -filepath $outfile -inputobject ($pre + "HTTP Disabled -" + $rawdata_http + $epre) -append  

# ===========================================
# restrict management addresses
# ===========================================
$title = "Benchmark: Restrict Management Addresses"


# RAW DATA
$rawdata = $xcfg.SelectNodes("//system")."permitted-ip".entry.name

#COMPUTE COMPLIANCE
if ($rawdata.count -gt 0) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre + $rawdata + $epre) -append  

# ===========================================
# interface management policies
# ===========================================
$title = "Benchmark: Interface Management Policies"

# RAW DATA
$policies = $xcfg.SelectNodes("//interface-management-profile").entry
$interfaces = $xcfg.SelectNodes("//interface").ethernet.entry
$policies_per_int = @()

$interfaces | foreach {
$val = new-object psobject
$val | add-member –membertype NoteProperty –name Name –Value $_.name
$val | add-member –membertype NoteProperty –name "Interface Comment" –Value $_.comment
$val | add-member –membertype NoteProperty –name "Interface Mgt Profile" –Value $_.layer3."interface-management-profile"
$policies_per_int += $val
}

#COMPUTE COMPLIANCE
$tresult = $TMANUAL
$result = $MANUAL

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
"Policies:"
$policies
write-host "Policies Per Interface:"
$policies_per_int | ft

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre + "Policies:" + $CRLF ) -append
Out-File -filepath $outfile -inputobject ($policies) -append  
Out-File -filepath $outfile -inputobject ( $CRLF+"Policies Per Interface:" + $CRLF ) -append  
Out-File -filepath $outfile -inputobject ( $policies_per_int | ft -autosize ) -append
Out-File -filepath $outfile -inputobject ( $epre ) -append


# ===========================================
# password complexity
# ===========================================
$title = "Benchmark: Password Complexity"

# RAW DATA
$rawdata = $xcfg.SelectNodes("//password-complexity")

#COMPUTE COMPLIANCE
$pwdscore = 0
if ($xcfg.SelectNodes("//password-complexity")."enabled" -eq "yes") {$pwdscore += 1}
if ($xcfg.SelectNodes("//password-complexity")."minimum-length" -ge "12") {$pwdscore += 1}
if ($xcfg.SelectNodes("//password-complexity")."minimum-uppercase-letters" -gt "0") {$pwdscore += 1}
if ($xcfg.SelectNodes("//password-complexity")."minimum-lowercase-letters" -gt "0") {$pwdscore += 1}
if ($xcfg.SelectNodes("//password-complexity")."minimum-numeric-letters" -gt "0") {$pwdscore += 1}
if ($xcfg.SelectNodes("//password-complexity")."minimum-special-characters" -gt "0") {$pwdscore += 1}
if ($xcfg.SelectNodes("//password-complexity")."block-username-inclusion" -eq "yes") {$pwdscore += 1}
if ($xcfg.SelectNodes("//password-complexity")."new-password-differs-by-characters" -ge "3") {$pwdscore += 1}
if ($xcfg.SelectNodes("//password-complexity")."new-password-differs-by-characters" -ge "24") {$pwdscore += 1}
if ($xcfg.SelectNodes("//password-complexity")."password-change"."expiration-period" -ge "90") {$pwdscore += 1}

if ($pwdscore -eq 10) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
[string] $pwdscore + " of 10 Password Complexity requirements met"
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF + [string]$pwdscore + " of 10 Password Complexity requirements met"+ $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject ($rawdata + $epre) -append  

# ===========================================
# disable password policies
# ===========================================
$title = "Benchmark: Disable Password Policies"


# RAW DATA
$rawdata = $xcfg.SelectNodes("//password-profile").entry
$rawdata_expanded = $rawdata | select-object -ExpandProperty password-change

#COMPUTE COMPLIANCE - REDO THIS COMPUTATION
if ($rawdata.name.count -ge 0) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata 


# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($CRLF+$pre) -append  
Out-File -filepath $outfile -inputobject ($xcfg.SelectNodes("//password-profile").entry | foreach { $_.name ; $_ | select-object -ExpandProperty password-change | select "expiration-period", "expiration-warning-period","post-expiration-admin-login-count","post-expiration-grace-period" | convertto-html -frag}  ) -append
Out-File -filepath $outfile -inputobject ($epre) -append  


# ===========================================
# idle timeout
# ===========================================
$title = "Benchmark: Idle Timeout"

# RAW DATA
$rawdata = $xcfg.SelectNodes("//idle-timeout")."#text"

#COMPUTE COMPLIANCE
if ($rawdata -gt 10) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject ($rawdata + $epre) -append 

# ===========================================
# "Forbid the use of Authentication Settings for Failed Attempts and Lockout Time."
# "Require an Authentication Profile with Failed Attempts to 3, and"
# "lockout time of 15 minutes applied to all but one Superuser account."
# ===========================================
$title = "Benchmark: Lockout Settings"

# first, verify that failed attempts and lockout times are NOT set in the Authentication Settings screen
$result = $COMPLIANT ; $tresult = "COMPLIANT"
$chk = 0
$rawdata = $xcfg.SelectNodes("//admin-lockout")

if ($rawdata."failed-attempts" -gt 0 ) {$result = $NONCOMPLIANT ; $tresult = "NONCOMPLIANT" ; $chk += 1}
if ($rawdata."lockout-time" -gt 0 ) {$result = $NONCOMPLIANT ; $tresult = "NONCOMPLIANT" ; $chk +=1 }

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Global Settings - Authentication Settings screen"
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata


# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"<u>Authentication Settings screen settings</u>"+$eb + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk+" of 2 settings are defined on the Authentication Settings screen instead of in an Authentication Profile" + $CRLF) -append
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject ($rawdata | ft -auto ) -append 
Out-File -filepath $outfile -inputobject ( $epre) -append 

# ------subcheck --------------

Out-File -filepath $outfile -inputobject ($b+"<u>Authentication Profiles Settings</u>"+$eb + $CRLF) -append 

$authprofiles = $xcfg.SelectNodes("//shared")."authentication-profile".entry

$authprofiles | foreach {
$chk=0
$rawdata = $_
if ($_.lockout."lockout-time" -ge 10) { $chk +=1 }
if ($_.lockout."failed-attempts" -le 10) { $chk +=1 }
if ($chk -eq 2) {$result = $COMPLIANT} else { $RESULT = $NONCOMPLIANT}

# TEXT OUTPUT 
"Authentication Profile: " + $_.name
"Result: "+ $tresult
"Raw Data:"
$rawdata | select -ExpandProperty lockout | ft -auto

#FILE OUTPUT
Out-File -filepath $outfile -inputobject ($b+"Authentication Profile: " +$eb + $_.name + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk + " of 2 settings correctly set"+$CRLF) -append

Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject ($rawdata | select -ExpandProperty lockout | ft -auto) -append 
Out-File -filepath $outfile -inputobject ($epre) -append 
}

# are profiles applied to all users?
$mgtusers = $xcfg.SelectNodes("//mgt-config").users.entry
$result = $mgtusers | select name, authentication-profile

# TEXT OUTPUT
$result

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($pre) -append 
Out-File -filepath $outfile -inputobject ($result | ft -auto) -append 
Out-File -filepath $outfile -inputobject ($epre) -append 

# ===========================================
# SNMPv3
# ===========================================
$title = "Benchmark: Encrypted Network Management Protocols - SNMPv3"


# RAW DATA
$rawdata = $xcfg.SelectNodes("//snmp-setting")."access-setting".version

#COMPUTE COMPLIANCE
if ($rawdata.v3.views.entry.name.length -gt 0) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($rawdata) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Require Verification of update server identity
# ===========================================
$title = "Benchmark: Require verification of update server identity"


# RAW DATA
$rawdata = $xcfg.SelectNodes("//server-verification")."#text"

#COMPUTE COMPLIANCE
if ($rawdata -eq "yes") {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre + $rawdata + $epre) -append  

# ===========================================
# redundant NTP servers
# ===========================================
$title = "Benchmark: Require Redundant NTP Servers"


# RAW DATA
$rawdata = $xcfg.SelectNodes("//ntp-server-address")."#text"

#COMPUTE COMPLIANCE
if ($rawdata.count -ge 2) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
[string] $rawdata.count + " NTP Servers Defined"
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $rawdata.count + " NTP Servers Defined"+$CRLF) -append
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($rawdata) -append
Out-File -filepath $outfile -inputobject ($epre) -append



# ===========================================
# ID Agents
# ===========================================
$title = "Benchmark: Require IP-to-username mapping for user traffic"


# RAW DATA
$idagents = $xcfg.SelectNodes("//user-id-agent").entry | select name, port, collectorname,host
$tsagents = $xcfg.SelectNodes("//ts-agent").entry
$servermonitors = $xcfg.SelectNodes("//server-monitor").entry


#COMPUTE COMPLIANCE
if ($idagents.count + $tsagents.count + $servermonitors.count -ge 0) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$idagents | ft
$tsagents | ft
$servermonitors | ft

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ("ID Agents:") -append
Out-File -filepath $outfile -inputobject ($idagents | ft -auto) -append
Out-File -filepath $outfile -inputobject ("TS Agents:") -append
Out-File -filepath $outfile -inputobject ($tsagents | ft -auto) -append
Out-File -filepath $outfile -inputobject ("Server Monitors:") -append
Out-File -filepath $outfile -inputobject ($servermonitors | ft -auto) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Enable WMI Probing
# ===========================================
$title = "Benchmark: Disable WMI probing if not required"

# RAW DATA
$rawdata = $xcfg.SelectNodes("//enable-probing")."#text"

#COMPUTE COMPLIANCE
if ($rawdata -eq "yes") {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT} else
{$tresult = "COMPLIANT"; $result = $COMPLIANT}



# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata


# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($rawdata) -append
Out-File -filepath $outfile -inputobject ($epre) -append



# ===========================================
# Forbid User-ID on external and other non-trusted zones
# ===========================================
$title = "Benchmark: Forbid User-ID on external and other non-trusted zones"

# RAW DATA
$rawdata = $xcfg.SelectNodes("//interface-management-profile")
$interfaces = $xcfg.SelectNodes("//network").interface.ethernet.entry
$tlist = @()

$interfaces | foreach {
$val = new-object psobject
$val | add-member –membertype NoteProperty –name Name –Value $_.name
$val | add-member –membertype NoteProperty –name "Interface Comment" –Value $_.comment
$val | add-member –membertype NoteProperty –name "Interface Mgt Profile" –Value $_.layer3."interface-management-profile"
$tlist += $val
}

#COMPUTE COMPLIANCE
$result = $MANUAL ; $tresult = $TMANUAL

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata
$interfaces
$tlist | ft -auto

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($rawdata | foreach {$_.entry | ft -auto }) -append
Out-File -filepath $outfile -inputobject ($tlist | ft -auto) -append
Out-File -filepath $outfile -inputobject ($epre) -append


# ===========================================
# userids + include / exclude networks
# ===========================================
$title = "Benchmark: Require the use of User-ID’s Include/Exclude Networks section, if User-ID is enabled. Include only trusted internal networks"

# RAW DATA
$rawdata = $xcfg.SelectNodes("//include-exclude-network").entry

#COMPUTE COMPLIANCE

if ($rawdata.count -gt 0) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata | ft -auto

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($rawdata | ft -auto) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Require a dedicated service account for User-ID with minimal permissions (If a User-ID Agent or Integrated User-ID Agent is utilized)
# ===========================================
$title = "Benchmark: Require a dedicated service account for User-ID with minimal permissions (If a User-ID Agent or Integrated User-ID Agent is utilized"
$result = "Active Directory Assessment, this cannot be deduced from the Firewall Configuration"

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 

# ===========================================
# Forbid Interactive Login rights for the User-ID service account ad check
# ===========================================
$title = "Benchmark: Forbid Interactive Login rights for the User-ID service account (AD check)"
$result = "Active Directory Assessment, this cannot be deduced from the Firewall Configuration"

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 

# ===========================================
# Require security policies restricting User-ID Agent traffic from crossing into untrusted zones
# ===========================================
$title = "Benchmark: Require security policies restricting User ID Agent traffic from crossing into untrusted zones"

# RAW DATA
$rawdata =  $xcfg.SelectNodes("//route").service.entry | foreach { $_.name , $_.source | ft -auto}

#COMPUTE COMPLIANCE

$result2 = $xcfg.SelectNodes("//route").service.entry | foreach { 
if($_.name -eq "uid-agent") {"Compliant "+" Source for uid-agent is "+$_.source.interface +" "+ $_.source.address} }

if (($result2.count) -gt 0) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
$result2
"---------------"
"Raw Data:"
"---------------"
$rawdata | ft

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ("Interface Results: " + $result2 + $CRLF) -append
Out-File -filepath $outfile -inputobject ($rawdata | ft) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# HA Configured
# ===========================================
$title = "Benchmark: Require a fully-synchronized High Availability peer"

# RAW DATA
$rawdata =  $xcfg.SelectNodes("//high-availability").group.entry

#COMPUTE COMPLIANCE
if ($rawdata.name.length -gt 0) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
$result2
"---------------"
"Raw Data:"
"---------------"
$rawdata | ft

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($rawdata) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# HA Configured
# ===========================================
$title = "Benchmark: For High Availability, require Link Monitoring, Path Monitoring, or both"

# RAW DATA
$rawdata   = $xcfg.SelectNodes("//high-availability").group | foreach {$_.entry.monitoring."link-monitoring"."link-group".entry}
$rawdata2 += $xcfg.SelectNodes("//high-availability").group | foreach {$_.entry.monitoring."path-monitoring"."link-group".entry}


#COMPUTE COMPLIANCE
$chk = 0
$xcfg.SelectNodes("//high-availability").group | foreach {if ($_.entry.monitoring."link-monitoring"."link-group".entry.name.length -gt 0) { $chk +=1 }}
$xcfg.SelectNodes("//high-availability").group | foreach {if ($_.entry.monitoring."path-monitoring"."link-group".entry.name.length -gt 0) { $chk +=1 }}
if ($chk -gt 0) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ("Link Monitoring") -append
Out-File -filepath $outfile -inputobject ($rawdata | fl) -append
Out-File -filepath $outfile -inputobject ("Path Monitoring") -append
Out-File -filepath $outfile -inputobject ($rawdata2) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# HA Preemption Off, Link State to Auto
# ===========================================
$title = "Benchmark: Forbid simultaneously enabling the Preemptive option, and configuring the Passive Link State to shutdown simultaneously"

# RAW DATA
$hagroups=$xcfg.SelectNodes("//high-availability").group

$tlist = @()

$hagroups.entry | foreach {
$val = new-object psobject
$val | add-member –membertype NoteProperty –name Name –Value $_.name
$val | add-member –membertype NoteProperty –name Description –Value $_.description
$val | add-member –membertype NoteProperty –name Peer_IP –Value $_.peer-ip
$val | add-member –membertype NoteProperty –name Passive_Link_State –Value $_.mode."active-passive"."passive-link-state"
$val | add-member –membertype NoteProperty –name Preemptive_Election –Value $_."election-option".preemptive
$tlist += $val
}
$rawdata = $tlist


#COMPUTE COMPLIANCE
$chk = 0
$hagroups.entry | foreach { if ($_.mode."active-passive"."passive-link-state" -eq "auto") { if ($_."election-option".preemptive -eq "no") {$chk +=1} }}
if ($chk -eq 0) {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT} else {$tresult = "COMPLIANT"; $result = $COMPLIANT}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($CRLF+"Link Monitoring:") -append
Out-File -filepath $outfile -inputobject ($rawdata | fl) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# AV SCHEDULE
# ===========================================
$title = "Benchmark: Require the Antivirus Update Schedule is set to Download and Install hourly."

# RAW DATA


#COMPUTE COMPLIANCE
$result = "cannot find in xml"

$rawdata =""

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + "not in config?"
"---------------"
"Raw Data:"
"---------------"
# $rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($rawdata ) -append
Out-File -filepath $outfile -inputobject ($epre) -append


# ===========================================
# Require the Applications and Threats Update Schedule is set to Download and Install Daily.
# ===========================================
$title = "Benchmark: Require the Applications and Threats Update Schedule is set to Download and Install Daily."


$threats = $xcfg.SelectNodes("//threats").recurring

# RAW DATA
$rawdata = if ($threats.daily.at.length -ge 1) {"Daily at "+$threats.daily.at +" "+ $threats.daily.action}
$rawdata += if ($threats.weekly.at.length -ge 1) {"Weekly at "+$threats.weekly.at +" "+ $threats.weekly.action}

#COMPUTE COMPLIANCE
if ($threats.daily.at.length -ge 1) {if ($threats.daily.action -eq "download-and-install") {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($rawdata) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Require the WildFire Update Schedule is set to Download and Install every 15 minutes.
# ===========================================
$title = "Benchmark: Require the WildFire Update Schedule is set to Download and Install every 15 minutes."


$wildfire = $xcfg.SelectNodes("//wildfire").recurring

# RAW DATA

$rawdata = if ($wildfire.'every-15-mins'.action.length -gt 1) {"Every 15 Minutes "+$wildfire.recurring.'every-15-mins'.action}
$rawdata += if ($wildfire.recurring.'every-30-mins'.action.length -gt 1) {"Every 30 Minutes "+$wildfire.recurring.'every-30-mins'.action}
$rawdata += if ($wildfire.recurring.'every-hour'.action.length -gt 1) {"Every Hour "+$wildfire.recurring.'every-hour'.action}


#COMPUTE COMPLIANCE
if ($wildfire.'every-15-mins'.action -eq "download-and-install") {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($rawdata) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Increase WildFire file size upload limits
# ===========================================
$title = "Benchmark: Increase WildFire file size upload limits"


$wildfire = $xcfg.SelectNodes("//wildfire").recurring

# RAW DATA

$rawdata = if ($wildfire.'every-15-mins'.action.length -gt 1) {"Every 15 Minutes "+$wildfire.recurring.'every-15-mins'.action}
$rawdata += if ($wildfire.recurring.'every-30-mins'.action.length -gt 1) {"Every 30 Minutes "+$wildfire.recurring.'every-30-mins'.action}
$rawdata += if ($wildfire.recurring.'every-hour'.action.length -gt 1) {"Every Hour "+$wildfire.recurring.'every-hour'.action}


#COMPUTE COMPLIANCE
function wfchk
{
param ($typ, [int] $limit)

$limits = @{
"flash"=10;
"apk"=50;
"pdf"=1000;
"jar"=10;
"pe"=10;
"ms-office"=10000}

if ($limit -ge $limits.$typ ) {return 1} else { return 0}
}

#RAW DATA
$rawdata = $xcfg.SelectNodes("//setting").wildfire."file-size-limit"

#COMPUTE COMPLIANCE
$chk = 0

$rawdata.entry | foreach { 
if ( wfchk $_.entry.name, $_.entry."size-limit" -eq 1) {$chk +=1 }
}

if ($chk -eq 6) {$tresult = "COMPLIANT"; $result = $COMPLIANT ; $result2 = "All values met or exceeded"} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT; $result2 = [string ] $chk+" out of 6 quotas met or exceeded" }


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata.entry | ft

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($result2 + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject ($rawdata.entry | ft -auto) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Require WildFire File Blocking profiles to include any application, any file type, and action set to forward
# ===========================================
$title = "Benchmark: Require WildFire File Blocking profiles to include any application, any file type, and action set to forward"



$vsys = $xcfg.selectnodes("//vsys")

$fileblocking = $vsys | foreach { $_.entry.profiles."file-blocking".entry }

# RAW DATA

$rawdata = $fileblocking | ForEach { $_.name, $_.rules | foreach {$_.entry }}

#COMPUTE COMPLIANCE (and output)

Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append

$fileblocking | ForEach {
Out-File -filepath $outfile -inputobject ($b+"File Blocking Entry: "+$eb + $_.name + $CRLF) -append ;
$_.rules | foreach {
if (($_.entry.application.member -eq "any") -and ($_.entry."file-type".member -eq "any") -and ($_.entry.action -eq "forward"))
{$tresult = "COMPLIANT"; $result = $COMPLIANT} else {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
}}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($rawdata) -append
Out-File -filepath $outfile -inputobject ($epre) -append



# ===========================================
# Require a WildFire File Blocking profile for all security policies allowing Internet traffic flows.
# ===========================================
$title = "Benchmark: Require a WildFire File Blocking profile for all security policies allowing Internet traffic flows."


# RAW DATA
$rawdata = $xcfg.SelectNodes("//security").rules.entry
$chk = 0

#COMPUTE COMPLIANCE
$tlist = @()
$rawdata | foreach { 
if ($_."profile-setting".profiles."file-blocking".member.length -ge 1) {$chk += 1; $result = $COMPLIANT} else {$result = $NONCOMPLIANT} ;
$val = new-object psobject
$val | add-member –membertype NoteProperty –name Name –Value $_.name
$val | add-member –membertype NoteProperty –name Compliance –Value $result
$tlist += $val
}


if ($chk -eq $rawdata.count) {$result = $COMPLIANT} else {$result = $NONCOMPLIANT}

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"OVERALL RESULT: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk+ " out of " + [string] $rawdata.count+ " security rules have Wildfire File-Blocking policies" + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($tlist | ft -auto) -append
Out-File -filepath $outfile -inputobject ($rawdata ) -append
Out-File -filepath $outfile -inputobject ($epre) -append


# ===========================================
# Require forwarding of decrypted content
# ===========================================
$title = "Benchmark: Require forwarding of decrypted content."


# RAW DATA
$rawdata = $xcfg.SelectNodes("//allow-forward-decrypted-content")."#text"

#COMPUTE COMPLIANCE
if ($rawdata -eq "yes") {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject ($rawdata) -append
Out-File -filepath $outfile -inputobject ($epre) -append



# ===========================================
# Require all WildFire Session Information Settings to be enabled
# ===========================================
$title = "Benchmark: Require all WildFire Session Information Settings to be enabled."


# RAW DATA
$rawdata = $xcfg.SelectNodes("//setting").wildfire."session-info-select"

# COMPUTE COMPLIANCE


$rawdata | foreach { 
$chk = 0
if ($_."exclude-src-ip" -eq "yes") { $chk += 1}
if ($_."exclude-email-subject" -eq "yes") { $chk += 1}
if ($_."exclude-email-recipient" -eq "yes") { $chk += 1}
if ($_."exclude-email-sender" -eq "yes") { $chk += 1}
if ($_."exclude-filename" -eq "yes") { $chk += 1}
if ($_."exclude-url" -eq "yes") { $chk += 1}
if ($_."exclude-username" -eq "yes") { $chk += 1}
if ($_."exclude-app-name" -eq "yes") { $chk += 1}
if ($_."exclude-vsys-id" -eq "yes") { $chk += 1}
if ($_."exclude-dest-port" -eq "yes") { $chk += 1}
if ($_."exclude-dest-ip" -eq "yes") { $chk += 1}
if ($chk -eq 11) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}
}

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata | fl

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk + " of 11 checks are correct"+$CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject ($rawdata | fl) -append
Out-File -filepath $outfile -inputobject ($epre) -append




# ===========================================
# Require sending an alert for malware detected through WildFire
# ===========================================
$title = "Benchmark: Require sending an alert for malware detected through WildFire"


# RAW DATA
$rawdata = $xcfg.SelectNodes("//log-settings").profiles.entry

# COMPUTE COMPLIANCE
$chk = 0
$tlist = @()

$rawdata | foreach {$_.wildfire | foreach {
$val = new-object psobject
$val | add-member –membertype NoteProperty –name Name –Value $_.name
$val | add-member –membertype NoteProperty –name "send-to-panorama" –Value $_.malicious."send-to-panorama"
$val | add-member –membertype NoteProperty –name "snmptrap-setting" –Value $_.malicious."send-snmptrap"."using-snmptrap-setting"
$val | add-member –membertype NoteProperty –name "email-setting" –Value $_.malicious."send-email"."using-email-setting"
$val | add-member –membertype NoteProperty –name "syslog-setting" –Value $_.malicious."send-syslog"."using-syslog-setting"

if ($val."send-to-panorama" -eq "yes") {$chk += 1}
if ($val."snmptrap-setting".length -gt 0) {$chk += 1}
if ($val."email-setting".length -gt 0) {$chk += 1}
if ($val."syslog-setting".length -gt 0) {$chk += 1}

$tlist += $val
}}

if ($chk -gt 0) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk + " alert destinations are configured"+$CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject ($tlist | fl ) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Verify WildFire file submission and alerting is functioning as expected
# ===========================================
$title = "Benchmark: Verify WildFire file submission and alerting is functioning as expected"

# RAW DATA
#break XML blob into an array of substrings
$rawdata = $wfstatus.response.result.member -split "`n"

# COMPUTE COMPLIANCE
$chk = 0
$rawdata | foreach { if (($_.contains("Status")) -and ($_.contains("Active"))) {$chk += 1} } 
$rawdata | foreach { if (($_.contains("registered")) -and ($_.contains("yes"))) {$chk += 1} } 

if ($chk -eq 2) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
if($result = $COMPLIANT) 
{ $rawdata = $rawdata -replace "Status:","<b><font color=lime>Status:" ; $rawdata = $rawdata -replace "Best Server:","</b></font color=lime>Status:" } else
{ $rawdata = $rawdata -replace "Status:","<b><font color=red>Status:" ; $rawdata = $rawdata -replace "Best Server:","</b></font color=red>Status:" } 
Out-File -filepath $outfile -inputobject ($rawdata ) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Require an Antivirus profile configured to block on all decoders except imap and pop3
# ===========================================
$title = "Benchmark: Require an Antivirus profile configured to block on all decoders except imap and pop3"

function avchk
{
param( $typ, $action)

$avactions = @{
"ftp"="block";
"http"="block";
"imap"="alert";
"pop3"="alert";
"smb"="block";
"smtp"="block"}

if ($action -eq $avactions.$typ ) {return 1} else { return 0}
}

$vsys = $xcfg.selectnodes("//vsys")
$chk = 0

# COMPUTE RAW DATA
$rawdata = $vsys | foreach { $_.entry.profiles.virus.entry | foreach {
$_.name ; $_.decoder | foreach { $_ | foreach { $_.entry  } } } }

# COMPPUTE COMPLIANCE
$rawdata | foreach { if ( (avchk ($_.name , $_.action) -eq 1) -and ($_.name.length -gt 0)) {$chk += 1; $_.name, $_.action } else { } }

if($chk -eq 6) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata | ft

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk +" of " + [string] ($rawdata.count -1) + " settings are compliant"+ $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject ($rawdata | ft -auto) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Require a securely configured Antivirus profile applied to all applicable security policies
# ===========================================
$title = "Benchmark: Require a securely configured Antivirus profile applied to all applicable security policies"

# COMPUTE RAW DATA
$rawdata = $avperrule = $xcfg.SelectNodes("//security").rules.entry

# COMPPUTE COMPLIANCE
$chk = 0

$tlist = @()
$rawdata | foreach { $_ | foreach {
$val = new-object psobject
$val | add-member –membertype NoteProperty –name Name –Value $_.name

if ($_."profile-setting".profiles.virus.member.length -ge 1)
{ $chk += 1; $result = $COMPLIANT } else { $result = $NONCOMPLIANT }
$val | add-member –membertype NoteProperty –name Compliance –Value $result
$tlist += $val
 } }

if($chk -eq $rawdata.cout) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
$resultsdetail | ft
"---------------"
"Raw Data:"
"---------------"
$rawdata | fl

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk +" of " + [string] ($rawdata.count) + " Policies have an AV Profile"+ $CRLF + $pre) -append 
Out-File -filepath $outfile -inputobject ($tlist | ft -auto) -append
Out-File -filepath $outfile -inputobject ($epre + $CRLF + $b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject ($rawdata | fl) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Require an Anti-Spyware profile configured to block on all severity levels, categories, and threats.
# ===========================================
$title = "Benchmark: Require an Anti-Spyware profile configured to block on all severity levels, categories, and threats."

# COMPUTE RAW DATA
$rawdata = $xcfg.selectnodes("//vsys").entry.profiles.spyware.entry

# COMPPUTE COMPLIANCE
$chk = 0
$resultsyes = @() ; $resultsno = @()

$compliance = $rawdata |  foreach {
$name = $_.name ; $_.rules | foreach { $_ | foreach { if (($_.entry.action | gm | select -exp name ) -contains "block") 
{ $resultsyes = $name+" "+$COMPLIANT +" Rule " + $_.entry.name ; $chk += 1 } else { resultsno += $name+" "+$NONCOMPLIANT +" Rule "+ $_.entry.name } } } }
if($chk -eq $rawdata.cout) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
$resultsyes
$resultsno
"---------------"
"Raw Data:"
"---------------"
$rawdata | fl

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk +" of " + [string] ($rawdata.name.count) + " Policies have an AV Profile"+ $CRLF) -append 
Out-File -filepath $outfile -inputobject ("Compliant Policies:"+$CRLF) -append
Out-File -filepath $outfile -inputobject ($resultsyes) -append
Out-File -filepath $outfile -inputobject ( $CRLF+"NON Compliant Policies:"+$CRLF) -append
Out-File -filepath $outfile -inputobject ($resultsno) -append
Out-File -filepath $outfile -inputobject ( $b + "Raw Data:" + $eb + $CRLF + $pre ) -append

$rawdata | foreach { 
Out-File -filepath $outfile -inputobject ("PROFILE:" + $_.name +$CRLF + "ACTION:" ) -append

Out-File -filepath $outfile -inputobject ($_.'botnet-domains'  | select "passive-dns" | fl  ) -append
Out-File -filepath $outfile -inputobject ($_.'botnet-domains'.action   | fl  ) -append
Out-File -filepath $outfile -inputobject ($_.'botnet-domains'.action.sinkhole | ft -auto ) -append

Out-File -filepath $outfile -inputobject ("RULES:" + $CRLF + ($_.rules.entry | out-string )) -append
}

Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Require DNS Sinkholing on all Anti-spyware profiles in use
# ===========================================
$title = "Benchmark: Require DNS Sinkholing on all Anti-spyware profiles in use"

# COMPUTE RAW DATA
$rawdata = $xcfg.selectnodes("//vsys").entry.profiles.spyware.entry

# COMPPUTE COMPLIANCE
$chk = 0
$resultsyes = @() ; $resultsno = @()

$rawdata | foreach {
if ($_."botnet-domains".action.sinkhole."ipv4-address".length -gt 1)
{$resultsyes +=  $_.name+ " " + $COMPLAINT + " IPV4 Sinkhole "+ $_."botnet-domains".action.sinkhole."ipv4-address" ; $chk += 1 } else 
{ $resultsno +=  $_.name+ " " + $NONCOMPLAINT + " IPV4 Sinkhole " +$_."botnet-domains".action.sinkhole."ipv4-address" } ;
$botnet = $_."botnet-domains".action.sinkhole."ipv4-address"
if ($_."botnet-domains".action.sinkhole."ipv6-address".length -gt 1)
{$resultsyes +=  $_.name+ " " + $COMPLAINT + " IPV6 Sinkhole " + $_."botnet-domains".action.sinkhole."ipv6-address" ; $chk += 1 } else 
{ $resultsno +=  $_.name+ " " + $NONCOMPLAINT + " IPV6 Sinkhole " +$_."botnet-domains".action.sinkhole."ipv6-address" } 
}

if($resultsno.count -eq 0) {$tresult = "COMPLIANT"; $result = $COMPLIANT} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT}

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
$resultsyes
$resultsno
"---------------"
"Raw Data:"
"---------------"
$rawdata | fl

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ("There are " +[string] $chk +" of " + [string] ($rawdata.name.count) + " correctly defined DNS Sinkhole Rules"+ $CRLF) -append 
Out-File -filepath $outfile -inputobject ("Compliant Settings:"+$CRLF+$pre) -append
Out-File -filepath $outfile -inputobject ($resultsyes) -append
Out-File -filepath $outfile -inputobject ($epre + $CRLF+"NON Compliant Settings:"+$CRLF + $pre) -append
Out-File -filepath $outfile -inputobject ($resultsno) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Require Passive DNS Monitoring enabled on all Anti-Spyware profiles in use.
# ===========================================
$title = "Benchmark: Require Passive DNS Monitoring enabled on all Anti-Spyware profiles in use."

# COMPUTE RAW DATA
$rawdata = $xcfg.selectnodes("//vsys").entry.profiles.spyware.entry
$chktotal = 0
$chk = 0
$resultsyes = @() ; $resultsno = @()

# COMPPUTE COMPLIANCE
$rawdata | foreach { $chktotal += 1 ; 
if ($_."botnet-domains"."passive-dns" -eq "yes") {$tresult = "COMPLIANT"; $result = $COMPLIANT ; $resultsyes += $_.name + " " + $_."botnet-domains"."passive-dns"  ; $chk += 1} else 
{$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT ; $resultsno += $_.name + " " + $_."botnet-domains"."passive-dns"} }


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
$resultsyes
$resultsno
"---------------"
"Raw Data:"
"---------------"
$rawdata | fl

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ("There are " +[string] $chk +" of " + [string] $chktotal + " correctly defined Passive DNS Rules"+ $CRLF) -append 
Out-File -filepath $outfile -inputobject ("Compliant Settings:"+$CRLF+$pre) -append
Out-File -filepath $outfile -inputobject ($resultsyes) -append
Out-File -filepath $outfile -inputobject ($epre + $CRLF+"NON Compliant Settings:"+$CRLF + $pre) -append
Out-File -filepath $outfile -inputobject ($resultsno) -append

Out-File -filepath $outfile -inputobject ($epre + $b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject ( $rawdata | fl ) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Require a securely configured Anti-Spyware profile applied to all security policies permitting traffic to the Internet.
# ===========================================
$title = "Benchmark: Require a securely configured Anti-Spyware profile applied to all security policies permitting traffic to the Internet."


# RAW DATA
$rawdata =  $xcfg.SelectNodes("//security").rules

#COMPUTE COMPLIANCE
$chktotal = 0
$chk = 0
$resultsyes = @() ; $resultsno = @()

$rawdata | foreach { write-host $_.entry.name ; $_.entry | foreach {
$res = $_."profile-setting".profiles.spyware.member
$chktotal += 1
if ($res.length -gt 0) {$resultsyes += $_.name + " " + $res + " - " + $COMPLIANT ; $chk += 1} else {$resultsno += $_.name + " " + $res + " - " + $NONCOMPLIANT}
} }

$tlist = @()

$rawdata | foreach  {
$_.entry | foreach {
$secpolname = $_.name ; write-host "secpolname = "+$secpolname
$res = $_."profile-setting".profiles.spyware.member ; write-host "res ="+$res ;
$chktotal += 1
$val = new-object psobject
if ($res.length -gt 0) 
{
$val | add-member –membertype NoteProperty –name "Security Policy" –Value $secpolname ;
$val | add-member –membertype NoteProperty –name "Spyware Profile" –Value $res ;
$val | add-member –membertype NoteProperty –name Compliance –Value $COMPLIANT ;
$chk += 1
} else {
$val | add-member –membertype NoteProperty –name "Security Policy" –Value $secpolname ;
$val | add-member –membertype NoteProperty –name "Spyware Profile" –Value "" ;
$val | add-member –membertype NoteProperty –name Compliance –Value $NONCOMPLIANT
}
$tlist += $val
}
}

if (($resultsyes.count) -eq $chktotal) {$tresult = "COMPLIANT" ; $result = $COMPLIANT } else {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT }

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$tlist | ft -auto

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ("There are " +[string] $chk +" of " + [string] $chktotal + " Policies have Anti-Spyware Profiles correctly applied"+ $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($tlist | ft -auto) -append
Out-File -filepath $outfile -inputobject ($epre) -append


# ===========================================
# Require a Vulnerability Protection profile configured to block at least high and critical vulnerabilities, and set to default on medium, low, and informational vulnerabilities
# ===========================================
$title = "Benchmark: Require a Vulnerability Protection profile configured to block at least high and critical vulnerabilities, and set to default on medium, low, and informational vulnerabilities"


# RAW DATA
$rawdata =  $xcfg.SelectNodes("//vsys").entry.profiles.vulnerability.entry

#COMPUTE COMPLIANCE
$chktotal = 0
$chk = 0
$resultsyes = @() ; $resultsno = @()

$rawdata | foreach {
$_.rules.entry | foreach {  
if ((($_.action | gm | select -exp name ) -contains "block") -and ($_.severity.innertext -like "*high*") -and ($_.severity.innertext -like "*critical*"))
{$resultsyes += $_.name  ; $chk += 1} else {$resultsno += $_.name }
}} 

if (($resultsyes.count) -eq $rawdata.rules.entry.name.count) {$tresult = "COMPLIANT" ; $result = $COMPLIANT } else {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT }

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata.entry | fl

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ("There are " +[string] $chk +" of " + [string] $rawdata.rules.entry.name.count + " Vulnerability Protection Profile correctly configured"+ $CRLF) -append 
Out-File -filepath $outfile -inputobject ("Compliant Settings:"+$CRLF+$pre) -append
Out-File -filepath $outfile -inputobject ($resultsyes) -append
Out-File -filepath $outfile -inputobject ($epre + $CRLF+"NON Compliant Settings:"+$CRLF + $pre) -append
Out-File -filepath $outfile -inputobject ($resultsno) -append
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
$rawdata | foreach { $_.rules.entry | foreach {  
# Out-File -filepath $outfile -inputobject (($_.name  )+"    "+ $_.severity.innertext) -append
Out-File -filepath $outfile -inputobject ("Policy "+ $_.name) -append
Out-File -filepath $outfile -inputobject ($_.severity.member) -append
}}
Out-File -filepath $outfile -inputobject ($epre+$epre) -append




# ===========================================
# Require a securely configured Vulnerability Protection Profile applied to all security policies allowing traffi
# ===========================================
$title = "Benchmark: Require a securely configured Vulnerability Protection Profile applied to all security policies allowing traffic"


# RAW DATA
$rawdata =  $xcfg.SelectNodes("//security").rules

#COMPUTE COMPLIANCE
$chktotal = 0
$chk = 0
$resultsyes = @() ; $resultsno = @()


$rawdata | foreach {  $_.entry | foreach { $chktotal += 1 ;
if ($_."profile-setting".profiles.vulnerability.member.length -ge 1) {$resultsyes += $_.name} else {$resultsyes += $_.name}
} }

if (($resultsyes.count) -eq ($rawdata.entry.count)) {$tresult = "COMPLIANT" ; $result = $COMPLIANT } else {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT }

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata.entry | fl

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ("There are " +[string] $resultsyes.count +" of " + [string] $rawdata.entry.count + " Vulnerability Protection Profile correctly configured"+ $CRLF) -append 
Out-File -filepath $outfile -inputobject ("Compliant Settings:"+$CRLF+$pre) -append
Out-File -filepath $outfile -inputobject ($resultsyes | fl ) -append
Out-File -filepath $outfile -inputobject ($epre + $CRLF+"NON Compliant Settings:"+$CRLF + $pre) -append
Out-File -filepath $outfile -inputobject ($resultsno | fl) -append
Out-File -filepath $outfile -inputobject ($epre + $b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($rawdata.entry | fl) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Require the use of PAN-DB URL Filtering
# ===========================================
$title = "Benchmark: Require the use of PAN-DB URL Filtering"


# RAW DATA
$rawdata =  $urllic.response.result


#COMPUTE COMPLIANCE

if ($rawdata -like "*valid*") {$tresult = "COMPLIANT" ; $result = $COMPLIANT } else {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT }

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($rawdata) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Require a URL Filtering profile with the action of “block” or
# “override” on the following categories: adult, hacking, malware, phishing, proxyavoidance-and-anonymizers
# ===========================================
$title = "Benchmark: Require a URL Filtering profile with the action of block or override on the following categories: adult, hacking, malware, phishing, proxyavoidance-and-anonymizers"

# RAW DATA
$rawdata = $xcfg.selectnodes("//vsys").entry.profiles."url-filtering"


$chk = 0
$rawdata.entry | foreach { $blklst = $_.block.member ;
if (($blklst -contains "adult") -and ($blklst -contains "hacking") -and ($blklst -contains "phishing") -and ($blklst -contains "malware") -and ($blklst -contains "proxyavoidance-and-anonymizers")) {
write-host ("Rule " + $_.name + "is COMPLIANT")} else { write-host "Rule " $_.name "is NONCOMPLIANT" ; $chk += 1 } 
write-host $blklst | fl
}


#COMPUTE COMPLIANCE
if ($chk -eq 0) {$tresult = "COMPLIANT" ; $result = $COMPLIANT } else {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT }

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata.entry | foreach {  "Rule: " + $_.name + "`n`nBlock List: " ;  $_.block.member | fl }

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk + " of " + [string] $rawdata.entry.name.count + " rules configured correctly" + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
$rawdata.entry | foreach {  
Out-File -filepath $outfile -inputobject ("Rule: " + $_.name + $CRLF + "Block List" ) -append
Out-File -filepath $outfile -inputobject (  $_.block.member | fl ) -append 
}
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Forbid a utilized URL Filtering profile with any category set to allow.
# ===========================================
$title = "Benchmark: Forbid a utilized URL Filtering profile with any category set to allow."

# RAW DATA
$rawdata = $xcfg.selectnodes("//vsys").entry.profiles."url-filtering"

$chk = 0
$rawdata.entry | foreach { 
 if ($_.allow.count -eq 0) { $chk += 1 } 
}

#COMPUTE COMPLIANCE
if ($chk -eq $rawdata.entry.name.count ) {$tresult = "COMPLIANT" ; $result = $COMPLIANT } else {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT }

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata.entry | foreach { "Rule " + $_.name ; "Allow List" ; $_.allow.member | fl }

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk + " of " + [string] $rawdata.entry.name.count + " rules configured correctly" + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
$rawdata.entry | foreach {  
Out-File -filepath $outfile -inputobject ("Rule: " + $_.name + $CRLF + "Allow List" ) -append
Out-File -filepath $outfile -inputobject (  $_.allow.member | fl ) -append 
}
Out-File -filepath $outfile -inputobject ($epre) -append



# ===========================================
# Require all HTTP Header Logging options enabled
# ===========================================
$title = "Benchmark: Require all HTTP Header Logging options enabled"

# RAW DATA
$rawdata = $xcfg.selectnodes("//vsys").entry.profiles."url-filtering"



$chk = 0
$rawdata.entry | foreach {
  if (($_."log-http-hdr-xff" -eq "yes") -and
      ($_."log-http-hdr-user-agent" -eq "yes") -and 
      ($_."log-http-hdr-referer" -eq "yes")) { $chk += 1}
}

#COMPUTE COMPLIANCE
if ($chk -eq $rawdata.entry.name.count ) {$tresult = "COMPLIANT" ; $result = $COMPLIANT } else {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT }

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawdata.entry | foreach { $_ }

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk + " of " + [string] $rawdata.entry.name.count + " rules configured correctly" + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($rawdata.entry | foreach { $_ } ) -append
Out-File -filepath $outfile -inputobject ($epre) -append


# ===========================================
# Require a securely configured URL Filtering profile applied to all security policies allowing traffic to the Internet.
# ===========================================
$title = "Benchmark: Require a securely configured URL Filtering profile applied to all security policies allowing traffic to the Internet."

# RAW DATA
$rawdata = $xcfg.SelectNodes("//security").rules

$chk = 0
$tlist = @()

$rawdata.entry | foreach { 
$val = new-object psobject
$val | add-member –membertype NoteProperty –name Name –Value $_.name
$val | add-member –membertype NoteProperty –name URLFilter –Value $_."profile-setting".profiles."url-filtering".member
if ($val.Urlfilter.length -gt 0) {
$val | add-member –membertype NoteProperty –name Compliance –Value $COMPLIANT ; $chk += 1} else {
$val | add-member –membertype NoteProperty –name Compliance –Value $NONCOMPLIANT }
$tlist += $val
}

#COMPUTE COMPLIANCE
if ($chk -eq $tlist.count ) {$tresult = "COMPLIANT" ; $result = $COMPLIANT } else {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT }

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk + " of " + [string] $tlist.count + " rules configured correctly" + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($tlist | ft -auto ) -append
Out-File -filepath $outfile -inputobject ($epre) -append



# ===========================================
# Require a Data Filtering policy set to alert after a threshold of Credit Card or Social Security numbers are detected.
# ===========================================
$title = "Benchmark: Require a Data Filtering policy set to alert after a threshold of Credit Card or Social Security numbers are detected."

# RAW DATA
$vsys = $xcfg.selectnodes("//vsys")

# SCREEN OUTPUT
"=============================="
$title
"=============================="
$subtitle = "Sub Benchmark - Set Thresholds for Credit Card and Social Security Numbers"

$tlist = @()
$chk=0

$vsys | foreach { $currentvsys = $_.entry.name ; $_.entry.profiles."data-objects".entry | foreach { 
$loopchk = 0
$val = new-object psobject
$val | add-member –membertype NoteProperty –name "VSYS" –Value $currentvsys ;
$val | add-member –membertype NoteProperty –name "Credit Card" –Value $_."credit-card-numbers".weight ;
$val | add-member –membertype NoteProperty –name "SSN" –Value $_."social-security-numbers".weight
$val | add-member –membertype NoteProperty –name "SSN-No Dash" –Value $_."social-security-numbers-without-dash".weight
$loopchk = 0
if ($val."Credit Card" -eq 10) {$loopchk +=1} else { $chk += 1}
if ($val."SSN" -eq 20) {$loopchk +=1} else { $chk += 1}
if ($val."SSN-No Dash" -eq 1) {$loopchk +=1} else { $chk += 1}
if ($loopchk = 3) {$result = $COMPLIANT ; $tresult = "COMPLIANT"} else {$result = $NONCOMPLIANT ; $tresult = "NONCOMPLIANT"}
$val | add-member –membertype NoteProperty –name "Compliance" –Value $result
$tlist += $val
}}

if (($tlist | where -property Compliance -like "*NOT*" | measure-object ).count -eq 0 ) {$tresult = "COMPLIANT" ; $result = $COMPLIANT} else {$tresult = "NOT COMPLIANT" ; $result = $NONCOMPLIANT }

"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$rawlist


# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+$subtitle+$eb+$CRLF) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] ($tlist | where -property Compliance -notlike "*NOT*" | measure-object ).count + " of " + [string] $tlist.count + " rules configured correctly" + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($tlist | ft -auto) -append
Out-File -filepath $outfile -inputobject ($epre) -append


$subtitle = "Sub Benchmark - Apply Data Filters" 

$tlist = @()
$vsys | foreach { $currentvsys = $_.entry.name ;
$_.entry.profiles."data-filtering".entry | foreach { $filtername = $_.name ; 
$chk=0 ; $_.rules.entry | foreach { write-host $rule = $_.name
$chk = 0
$val = new-object psobject
$val | add-member –membertype NoteProperty –name "VSYS" –Value $currentvsys ;
$val | add-member –membertype NoteProperty –name "Filter Name" –Value $filtername ;
$val | add-member –membertype NoteProperty –name "Rule" –Value $_.name ;
$val | add-member –membertype NoteProperty –name "Application Member" –Value $_.application.member ;
$val | add-member –membertype NoteProperty –name "File Type" –Value $_."file-type".member ;
$val | add-member –membertype NoteProperty –name "Direction" –Value $_.direction ;
$val | add-member –membertype NoteProperty –name "Block Threshold" –Value $_."alert-threshold" ;
$val | add-member –membertype NoteProperty –name "Alert Threshold" –Value $_."alert-threshold" ;
# set compliance to default yes, next loop revises
$val | add-member –membertype NoteProperty –name Compliance –Value $COMPLIANT

$tlist += $val

if ($_.application.member -eq "any") {$chk += 1} else {$val.Compliance = $NONCOMPLIANT }
if ($_."file-type".member -eq "any") {$chk += 1} else {$val.Compliance = $NONCOMPLIANT }
if ($_.direction -eq "both") {$chk += 1} else {$val.Compliance = $NONCOMPLIANT }
if ($_."alert-threshold" -eq 20) {$chk += 1} else {$val.Compliance = $NONCOMPLIANT }
if ($_."block-threshold" -eq 0) {$chk += 1} else {$val.Compliance = $NONCOMPLIANT }

if ($chk -eq 5) {$tresult = "COMPLIANT" ; $result = $COMPLIANT} else {$tresult = "NOT COMPLIANT" ; $result = $NONCOMPLIANT }
 }
 }
 }



# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($CRLF+$b+$subtitle+$eb+$CRLF) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] ($tlist | where -property Compliance -notlike "*NOT*" | measure-object ).count + " of " + [string] $tlist.count + " rules configured correctly" + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($tlist | ft -auto) -append
Out-File -filepath $outfile -inputobject ($epre) -append



# ===========================================
# Require a securely configured Data Filtering profile applied to all security policies allowing traffic to or from the Internet
# ===========================================
$title = "Benchmark: Require a securely configured Data Filtering profile applied to all security policies allowing traffic to or from the Internet"

# RAW DATA
$rawdata = $xcfg.SelectNodes("//security").rules

$chk = 0
$tlist = @()

$rawdata.entry | foreach { 
$val = new-object psobject
$val | add-member –membertype NoteProperty –name Name –Value $_.name
$val | add-member –membertype NoteProperty –name DataFilter –Value $_."profile-setting".profiles."data-filtering".member
if ($val.Datafilter.length -gt 0) {
$val | add-member –membertype NoteProperty –name Compliance –Value $COMPLIANT ; $chk += 1} else {
$val | add-member –membertype NoteProperty –name Compliance –Value $NONCOMPLIANT }
$tlist += $val
}

#COMPUTE COMPLIANCE
if ($chk -eq $tlist.count ) {$tresult = "COMPLIANT" ; $result = $COMPLIANT } else {$tresult = "NONCOMPLIANT" ; $result = $NONCOMPLIANT }

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk + " of " + [string] $tlist.count + " rules configured correctly" + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb) -append
Out-File -filepath $outfile -inputobject ($pre) -append
Out-File -filepath $outfile -inputobject ($tlist | ft -auto ) -append
Out-File -filepath $outfile -inputobject ($epre) -append


# ===========================================
# Require a Zone Protection Profile with an enabled SYN Flood Action of SYN Cookies attached to all untrusted zones
# ===========================================
$title = "Benchmark: Require a Zone Protection Profile with an enabled SYN Flood Action of SYN Cookies attached to all untrusted zones."

# RAW DATA
$maxcps = @{ "PA-VM" = "1000";
"PA-200" = "1000";
"PA-500" = "7500";
"PA-2000" = "15000";
"PA-3000" = "50000";
"PA-5000" = "120000";
"PA-7050" = "720000"; }

$model = $sysinfo.response.result.system.model

$SYNactivaterec = [int] ($maxcps.($model)) / 2

$rawdata = $xcfg.SelectNodes("//network").profiles."zone-protection-profile"
$tlist = @()
$chk = 0

$rawdata.entry | foreach { 
$chk2 = 0
$val = new-object psobject
$val | add-member –membertype NoteProperty –name Name –Value $_.name

$SYNactivate = [string] $_.flood."tcp-syn"."syn-cookies"."activate-rate"
if ( $SYNactivate -eq  $SYNactivaterec) { $chk2 += 1 ; $SYNactivate = "<FONT COLOR=LIME><b>"+$SYNactivate+"</FONT></b>" } else
{ $SYNactivate = "<FONT COLOR=RED><b>"+$SYNactivate+"</FONT></b>" }

$SYNAlarmRate =  [string] $_.flood."tcp-syn"."syn-cookies"."alarm-rate"
$SYNMAXRate = [string] $_.flood."tcp-syn"."syn-cookies"."maximal-rate"
$SYNENA = $_.flood."tcp-syn".enable

# if ([int] $SYNCookie -eq "syn-cookies" ) { $chk2 += 1 ; $SYNCookie = "<FONT COLOR=LIME><b>"+$SYNCookie+"</FONT></b>" } else
# { $SYNCookie = "<FONT COLOR=RED><b>"+$SYNCookie+"</FONT></b>" }

if ($SYNENA -eq "yes" ) { $chk2 += 1 ; $SYNENA = "<FONT COLOR=LIME><b>"+$SYNENA+"</FONT></b>" } else
{ $SYNENA = "<FONT COLOR=RED><b>"+$SYNENA+"</FONT></b>" }

$val | add-member –membertype NoteProperty –name "SYN Activate Rate" –Value ([string] $SYNactivate)
$val | add-member –membertype NoteProperty –name "SYN Alarm Rate" –Value ([string] $SYNAlarmRate)
$val | add-member –membertype NoteProperty –name "SYN Max Rate" –Value ([string] $SYNMAXRate)
$val | add-member –membertype NoteProperty –name "SYN Enabled" –Value $SYNENA

if ($chk2 -eq 3) { $result = "$COMPLIANT" ; $chk += 1 } else 
{$result = "$NONCOMPLIANT" }
$val | add-member –membertype NoteProperty –name Compliance –Value $result
$tlist += $val
}


#COMPUTE COMPLIANCE
if ($chk -eq $tlist.count ) {$tresult = "COMPLIANT" ; $result = $COMPLIANT } else {$result = $MANUAL ; $tresult = $TMANUAL }

$vsys = $xcfg.selectnodes("//vsys")

$tlist2 = @()
$vsys | foreach { 
$vsysname = $_.name ; $_.entry.zone.entry | foreach { 
$val = new-object psobject
$val | add-member –membertype NoteProperty –name VSYS –Value $vsysname
$val | add-member –membertype NoteProperty –name "Zone Name" –Value $_.name
$val | add-member –membertype NoteProperty –name Interfaces –Value $_.network.layer3.member
$val | add-member –membertype NoteProperty –name "Zone Prot Profile" –Value $_.network."zone-protection-profile"
$tlist2 += $val
}}


# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"


# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk + " of " + [string] $rawdata.entry.name.count + " rules configured correctly" + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb+$pre) -append
Out-File -filepath $outfile -inputobject ("Model =" + $model) -append
Out-File -filepath $outfile -inputobject ("Recommended SYN Activate Rate (CPS) = "+ [string] $SYNactivaterec ) -append

Out-File -filepath $outfile -inputobject ($tlist | fl ) -append 

Out-File -filepath $outfile -inputobject ($tlist2 | ft -auto ) -append 

Out-File -filepath $outfile -inputobject ($epre) -append


# ===========================================
# Require a Zone Protection Profile with tuned Flood Protection settings enabled for all flood types attached to all untrusted zones.
# ===========================================
$title = "Benchmark: Require a Zone Protection Profile with tuned Flood Protection settings enabled for all flood types attached to all untrusted zones." 

$tlist = @()
$chk = 0

$rawdata.entry | foreach { 
$val = new-object psobject
$val | add-member –membertype NoteProperty –name Name –Value $_.name

$val | add-member –membertype NoteProperty –name "SYN Enabled" –Value $_.flood."tcp-syn".enable
$val | add-member –membertype NoteProperty –name "SYN Alarm Rate" –Value ([string] $_.flood."tcp-syn"."syn-cookies"."alarm-rate")
$val | add-member –membertype NoteProperty –name "SYN Act Rate" –Value ([string] $_.flood."tcp-syn"."syn-cookies"."activate-rate")
$val | add-member –membertype NoteProperty –name "SYN Max Rate" –Value ([string] $_.flood."tcp-syn"."syn-cookies"."maximal-rate")

$val | add-member –membertype NoteProperty –name "UDP Alarm Rate" –Value ([string] $_.flood.udp.red."alarm-rate")
$val | add-member –membertype NoteProperty –name "UDP Act Rate" –Value ([string] $_.flood.udp.red."activate-rate")
$val | add-member –membertype NoteProperty –name "UDP Max Rate" –Value ([string] $_.flood.udp.red."maximal-rate")

$val | add-member –membertype NoteProperty –name "ICMP Alarm Rate" –Value ([string] $_.flood.icmp.red."alarm-rate")
$val | add-member –membertype NoteProperty –name "ICMP Act Rate" –Value ([string] $_.flood.icmp.red."activate-rate")
$val | add-member –membertype NoteProperty –name "ICMP Max Rate" –Value ([string] $_.flood.icmp.red."maximal-rate")

$val | add-member –membertype NoteProperty –name "ICMPv6 Alarm Rate" –Value ([string] $_.flood.icmpv6.red."alarm-rate")
$val | add-member –membertype NoteProperty –name "ICMPv6 Act Rate" –Value ([string] $_.flood.icmpv6.red."activate-rate")
$val | add-member –membertype NoteProperty –name "ICMPv6 Max Rate" –Value ([string] $_.flood.icmpv6.red."maximal-rate")

$tlist += $val
}

$tlist2 = @()
$vsys | foreach { 
$vsysname = $_.name ; $_.entry.zone.entry | foreach { 
$val = new-object psobject
$val | add-member –membertype NoteProperty –name VSYS –Value $vsysname
$val | add-member –membertype NoteProperty –name "Zone Name" –Value $_.name
$val | add-member –membertype NoteProperty –name Interfaces –Value $_.network.layer3.member
$val | add-member –membertype NoteProperty –name "Zone Prot Profile" –Value $_.network."zone-protection-profile"
$tlist2 += $val
}}


# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk + " of " + [string] $rawdata.entry.name.count + " rules configured correctly" + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject ($tlist | ft -auto ) -append
Out-File -filepath $outfile -inputobject ($tlist2 | ft -auto ) -append
Out-File -filepath $outfile -inputobject ($epre) -append


# ===========================================
# Require all zones have Zone Protection Profiles with all Reconnaissance Protection settings tuned and enabled, and NOT set to allow for any scan type.
# ===========================================
$title = "Benchmark: Require all zones have Zone Protection Profiles with all Reconnaissance Protection settings tuned and enabled, and NOT set to allow for any scan type."

$chk = 0
$rawdata = $xcfg.SelectNodes("//network").profiles."zone-protection-profile"

$rawdata.entry | foreach {$_.name ; 
write-host "Scan Settings" ; $_.scan | foreach { write-host "`n" ; 
$setting = ($_.entry.action | gm | select-object -last 1).name ; 
if ($setting -eq "allow" ) {$comp = "NONCOMPLIANT" ; $chk +=1 } else {$comp = "COMPLIANT"}
switch ($_.entry.name) {
"8001" {write-host $comp "TCP Port Scan" $setting }
"8002" {write-host $comp "Host Sweep" $setting}
"8003" {write-host $comp "UDP Port Scan" $setting}
}
}}
if ($chk -eq 0) {$tresult = "COMPLIANT" ; $result = $COMPLIANT } else {$result = $NONCOMPLIANT ; $tresult = "NONCOMPLIANT" }

$rulecount = ([int] $rawdata.entry.name.count ) *3
$goodcount = $rulecount - $chk

# loop through zones to ensure zone protection profile is assigned to complete the benchmark
# asdf asdf asdf

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"


# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $goodcount + " of " + [string] $rulecount + " rules configured correctly in "+ [string] $rawdata.entry.name.count + " Zones" + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append

$rawdata.entry | foreach {
Out-File -filepath $outfile -inputobject ($b+"Zone Protection Profile: " + $_.name + $eb) -append
Out-File -filepath $outfile -inputobject ("Scan Settings") -append
$_.scan | foreach { 
$setting = ($_.entry.action | gm | select-object -last 1).name ; 
switch ($_.entry.name) {
"8001" {Out-File -filepath $outfile -inputobject ("TCP Port Scan: " + $setting) -append }
"8002" {Out-File -filepath $outfile -inputobject ("Host Sweep: "+$setting) -append}
"8003" {Out-File -filepath $outfile -inputobject ("UDP Port Scan: "+$setting) -append}
}
}}
Out-File -filepath $outfile -inputobject ($epre) -append


# ===========================================
# Require all zones have Zone Protection Profiles that drop Spoofed IP address, mismatched overlapping TCP segment, 
# Malformed, Strict Source Routing, and Loose Source Routing IP options.
# ===========================================
$title = "Benchmark: Require all zones have Zone Protection Profiles that drop Spoofed IP address, mismatched overlapping TCP segment, Malformed, Strict Source Routing, and Loose Source Routing IP options."

$goodcount = 0
$rawdata = $xcfg.SelectNodes("//network").profiles."zone-protection-profile"

$rawdata.entry | foreach { 
$chk = 0
if ($_."discard-ip-spoof" -eq "yes") { } else {$chk += 1 ; write-host "NONCOMPLIANT - Discard IP Spoof is set to NO"} ;
if ($_."discard-overlapping-tcp-segment-mismatch" -eq "yes") { } else {$chk += 1 ; write-host "NONCOMPLIANT - Discard Overlapping TCP Segments is set to NO"} ;
if ($_."discard-strict-source-routing" -eq "yes") { } else {$chk += 1 ; write-host "NONCOMPLIANT - Discard Strict Source Route is set to NO"} ;
if ($_."discard-loose-source-routing" -eq "yes") { } else {$chk += 1 ; write-host "NONCOMPLIANT - Discard Loose Source Route is set to NO"} ;
if ($_."discard-malformed-option" -eq "yes") { } else {$chk += 1 ; write-host "NONCOMPLIANT - Discard Malformed Packets is set to NO"} ;
if ($chk -eq 0) {write-host $_.name "is COMPLIANT - All Recon Settings are correct"; $goodrules += 1} else 
                {$chk += 1 ; write-host $_.name " is NONCOMPLIANT" "-" $chk "of 5 recon settings are incorrectly set"} 
}
if ($chk -eq 0) {$tresult = "COMPLIANT" ; $result = $COMPLIANT } else {$result = $NONCOMPLIANT ; $tresult = "NONCOMPLIANT" }

$rulecount = ([int] $rawdata.entry.name.count )
$goodcount = $rulecount - $chk

# loop through zones to ensure zone protection profile is assigned to complete the benchmark
# asdf asdf asdf

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"


# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $goodcount + " of " + [string] $rulecount + " zones configured correctly" + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
$rawdata.entry | foreach {
Out-File -filepath $outfile -inputobject ( $_ ) -append
}
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Require specific application policies when allowing traffic from an untrusted zone to a more trusted zone.
# ===========================================
$title = "Benchmark: Require specific application policies when allowing traffic from an untrusted zone to a more trusted zone."

$rawdata = $rules = $xcfg.SelectNodes("//security").rules

$tlist = @()
$rawdata.entry | foreach {
$val = new-object psobject
$val | add-member –membertype NoteProperty –name Name –Value $_.name
$val | add-member –membertype NoteProperty –name From –Value $_.from.member
$val | add-member –membertype NoteProperty –name To –Value $_.to.member
$val | add-member –membertype NoteProperty –name Action –Value $_.action
$val | add-member –membertype NoteProperty –name Application –Value $_.application.innertext

$tlist += $val
}

$result = $MANUAL ; $tresult = $TMANUAL


# SCREEN OUTPUT
"=============================="
$title
"=============================="

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject ($tlist | ft -auto ) -append
Out-File -filepath $outfile -inputobject ($epre) -append

# ===========================================
# Forbid using the Service setting of any in a security policy.
# ===========================================
$title = "Benchmark: Forbid using the Service setting of any in a security policy."


$rawdata = $xcfg.SelectNodes("//security").rules
$chk = 0

$tlist =@()
$rawdata.entry | foreach { 

$val = new-object psobject
$val | add-member –membertype NoteProperty –name Name –Value $_.name
if ($_.application.innertext -eq "any") {$chk +=1 ; $result = "<FONT COLOR=LIME><b>SPECIFIC</b></FONT>" } else { $result = "<FONT COLOR=RED><b>ANY</b></FONT>" } 
$val | add-member –membertype NoteProperty –name "Application Setting" –Value $result
$tlist += $val
}

if ($chk -eq 0) {$result = $COMPLIANT ; $tresult = "COMPLIANT" } else
{$result = $NONCOMPLIANT ; $tresult = "NOT COMPLIANT" }


# SCREEN OUTPUT
"=============================="
$title
"=============================="


# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk +" of "+ [string] $rawdata.entry.name.count + " policies are not compliant" + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject $tlist -append
Out-File -filepath $outfile -inputobject ($epre) -append



# ===========================================
# Require a security policy denying any/all traffic at the bottom of thes ecurity policies ruleset.
# ===========================================
$title = "Benchmark: Require a security policy denying any/all traffic at the bottom of thesecurity policies ruleset."


$rules = $xcfg.SelectNodes("//security").rules

$lastrule =  $rules.entry | select-object -last 1

if (( $lastrule.source.member -eq "any") -and ($lastrule.destination.member -eq "any") -and 
( $lastrule.category.member -eq "any") -and ($lastrule.application.member -eq "any") -and 
( $lastrule.service.member -eq "any" ) -and ($lastrule.action -eq "deny") ) {
$result = $COMPLIANT ; $tresult = "COMPLIANT" } else {
$result = $NONCOMPLIANT ; $tresult = "NOT COMPLIANT" }

$val = new-object psobject
$val | add-member –membertype NoteProperty –name Name –Value $lastrule.name
$val | add-member –membertype NoteProperty –name Source –Value $lastrule.source.member
$val | add-member –membertype NoteProperty –name Destination –Value $lastrule.destination.member
$val | add-member –membertype NoteProperty –name Category –Value $lastrule.category.member
$val | add-member –membertype NoteProperty –name Application –Value $lastrule.application.member
$val | add-member –membertype NoteProperty –name Service –Value  $lastrule.service.member
$val | add-member –membertype NoteProperty –name Action –Value $lastrule.action -eq "deny"

# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult
"---------------"
"Raw Data:"
"---------------"
$lastrule | fl

# asdf - expand the rule in raw data

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append
Out-File -filepath $outfile -inputobject ($val) -append
Out-File -filepath $outfile -inputobject ($epre) -append



# ===========================================
# Require an SSL Forward Proxy policy for traffic destined to the Internet for all URL categories except financial-services and health-and medicine.
# ===========================================
$title = "Benchmark: Require an SSL Forward Proxy policy for traffic destined to the Internet for all URL categories except financial-services and health-and medicine."

$rawdata = $xcfg.selectnodes("//vsys")

$rawdata | foreach { $_.entry.name ; $_.entry.rulebase.decryption.rules | foreach { $chk = 0 ; $chk2 = 0
$mems = $_.entry.category.member ; $memcount = $_.entry.category.member.count ; 
if ($mems -contains "financial-services") {$chk +=1 ; "financial-services"} ; 
if ($mems -contains "health-and-medicine") {$chk +=1 ; "health-and-medicine"} ;
if ($chk -eq 0) {write-host "OK - Rule" $_.entry.name "has" $mems.count "categories set correctly"} else { "NOT OK - PII and/or financials are exposed" ; $chk2+= 1} ;
if ($memcount -lt 30) { $chk2 += 1 ; write-host "NOT OK - only" $memcount "categories are set"} ;
if ($_.entry.action -eq "no-decrypt") {$chk2 += 1; write-host "NOT OK - Rule does not Decrypt" } else { write-host "OK - Action is to decrypt"} ;
if ($chk2 -eq 0) {write-host $_.entry.name "is COMPLIANT on all counts"} else {write-host $_.entry.name "is NONCOMPLIANT"}
}
}



# SCREEN OUTPUT
"=============================="
$title
"=============================="
"Result:" + $tresult



# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ([string] $chk + " of the 2 sensitive categories are encrypted" + $CRLF ) -append 
Out-File -filepath $outfile -inputobject ([string] $memcount + " total categories are encrypted" + $CRLF ) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append

$rawdata | foreach { $vsysname = $_.name ; $_.entry.rulebase.decryption.rules | foreach { 
$val = new-object psobject
$val | add-member –membertype NoteProperty –name Vsys –Value $vsysname
$val | add-member –membertype NoteProperty –name "Rule Name" –Value $_.entry.name
$val | add-member –membertype NoteProperty –name From –Value $_.entry.from.member
$val | add-member –membertype NoteProperty –name To –Value $_.entry.to.member
Out-File -filepath $outfile -inputobject ($val | fl ) -append
Out-File -filepath $outfile -inputobject ($_.entry.category.member | fl) -append
}
}

Out-File -filepath $outfile -inputobject ($epre) -append


# ===========================================
# Require SSL Inbound Inspection for all untrusted traffic destined for servers using SSL.
# ===========================================
$title = "Benchmark: Require SSL Inbound Inspection for all untrusted traffic destined for servers using SSL."
$result = $MANUAL ; $tresult = $TMANUAL

# FILE OUTPUT
Out-File -filepath $outfile -inputobject ($h3+$title+$eh3) -append
Out-File -filepath $outfile -inputobject ($b+"Result: "+$eb + $result + $CRLF) -append 
Out-File -filepath $outfile -inputobject ($b + "Raw Data:" + $eb + $pre) -append

$rawdata | foreach { $vsysname = $_.name ; $_.entry.rulebase.decryption.rules | foreach { 
$val = new-object psobject
$val | add-member –membertype NoteProperty –name Vsys –Value $vsysname
$val | add-member –membertype NoteProperty –name "Rule Name" –Value $_.entry.name
$val | add-member –membertype NoteProperty –name From –Value $_.entry.from.member
$val | add-member –membertype NoteProperty –name To –Value $_.entry.to.member
Out-File -filepath $outfile -inputobject ($val | fl ) -append
Out-File -filepath $outfile -inputobject ($_.entry.category.member | fl) -append
}
}

Out-File -filepath $outfile -inputobject ($epre) -append
