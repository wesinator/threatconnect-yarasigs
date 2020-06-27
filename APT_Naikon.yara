rule APT_Naikon_1qaz
{
meta:
    author = "ThreatConnect, Inc."
    description = "Detects a RARStone related subvariant"
    example = "DB2E6BC4B8CADC372FA99C9B7F4F452D"
    license = "https://creativecommons.org/licenses/by/4.0/legalcode"
strings:
    $ = {31 71 61 7A 32 77 73 78 00 00 00 00 00 00 00 00 61 76 61 73 74 33 32}
    $ = "ERR:CREATE FILE ERROR %d" wide ascii
    $ = {73 64 6C 6C 2E 64 6C 6C 00 00 00 00 00 00 00 00 73 73 65 72 76 65 72}
condition:
    any of them
}

rule APT_Naikon_Adobe
{
meta:
    author = "ThreatConnect, Inc."
    description = "Detects Adobe themed malware variant"
    example = "52408BFFD295B3E69E983BE9BDCDD6AA"
    license = "https://creativecommons.org/licenses/by/4.0/legalcode"
strings:
    $ = "AcrobatTray.exe.pdb" fullword wide ascii
    $ = "Administrator.WIN-N63ECGRLJPD" wide ascii
    $ = "MM\\Adobe_ARM" wide ascii
    $ = "\\MyProjects\\Azclient\\" wide ascii
    $ = "Pdfbind-2012-local.pdb" wide ascii
    $ = {75 73 65 72 00 00 00 00 61 67 21 40 28 59 6A 32 00 00 00 00 64 65 62 75 67}
    $ = ":\\VS2010\\FileInject\\" wide ascii
condition:
    any of them
}

rule APT_Naikon_C2_nayingy
{
meta:
    author = "ThreatConnect, Inc."
    description = "Detects likely Naikon C2 domains registered by nayingy@gmail.com"
    license = "https://creativecommons.org/licenses/by/4.0/legalcode"
strings:
    $ = "banktools.org" fullword nocase wide ascii
    $ = "bingbinggo.com" fullword nocase wide ascii
    $ = "bkavshop.net" fullword nocase wide ascii
    $ = "bkfune.com" fullword nocase wide ascii
    $ = "blink123.net" fullword nocase wide ascii
    $ = "blxqwyszl.com" nocase wide ascii
    $ = "buythereway.com" fullword nocase wide ascii
    $ = "cacai.org" fullword nocase wide ascii
    $ = "chiangmanews.com" fullword nocase wide ascii
    $ = "cmcscan.com" fullword nocase wide ascii
    $ = "coffeecore.net" fullword nocase wide ascii
    $ = "dnsonline.cc" fullword nocase wide ascii
    $ = "domainth.net" fullword nocase wide ascii
    $ = "domainthailand.net" nocase wide ascii
    $ = "eumenides.org" nocase wide ascii
    $ = "geewu.org" fullword nocase wide ascii
    $ = "jjpdmm.com" fullword nocase wide ascii
    $ = "kyawthushwe.com" nocase wide ascii
    $ = "microsapp.org" fullword nocase wide ascii
    $ = "microso.info" fullword nocase wide ascii
    $ = "mizzima008.com" fullword nocase wide ascii
    $ = "mizzima008.net" fullword nocase wide ascii
    $ = "mopo3.net" fullword nocase wide ascii
    $ = "nb00544.net" fullword nocase wide ascii
    $ = "peacemmnn.com" fullword nocase wide ascii
    $ = "prometeuskill.com" fullword nocase wide ascii
    $ = "unikeynt.com" fullword nocase wide ascii
    $ = "vietel.org" fullword nocase wide ascii
    $ = "vnptstore.net" fullword nocase wide ascii
    $ = "yahoostore.net" fullword nocase wide ascii
    $ = "zjctmd.com" fullword nocase wide ascii
condition:
    any of them
}

rule APT_Naikon_NortonSet
{
meta:
    author = "ThreatConnect, Inc."
    description = "Detects NortonSet malware variant, which overlaps with RARStone and Recal"
    example = "5BBCCECFCD43B59E51FE902164F7D65E"
    license = "https://creativecommons.org/licenses/by/4.0/legalcode"
strings:
    $ = "/aspxabcdef.asp?" wide ascii
    $ = "No File Finded" wide
condition:
    any of them
}

rule APT_Naikon_RARStone
{
meta:
    author = "ThreatConnect, Inc."
    description = "Detects Naikon RARStone malware variant"
    example = "B31F6F4C4AA195E50BBD8A1D4A4B4B83"
    license = "https://creativecommons.org/licenses/by/4.0/legalcode"
strings:
    $ = "hx(n!z3)=d40" fullword wide ascii
    $ = "NOKIAN95/WEB" wide ascii
    $ = "skg(3)=&3.2d_u1" wide ascii
    $ = "/tag=info&id=15" wide ascii
    $ = {77 00 6F 00 72 00 6C 00 64 00 00 00 68 00 65 00 6C 00 6C 00 6F 00 00 00 6A 00 65 00 72 00 72 00 79 00 00 00 74 00 6F 00 6D 00 00 00 73 00 61 00 6E 00 64 00 79}
condition:
    any of them
}

rule APT_Naikon_Recal
{
meta:
    author = "ThreatConnect, Inc."
    description = "Detects Naikon related malware variant"
    example = "16E409CBA4A56144CBA175F5525AA8A6"
    license = "https://creativecommons.org/licenses/by/4.0/legalcode"
strings:
    $ = "aa.txt File Not Find" nocase wide ascii
    $ = ":\\RECYCLER\\desktop.imi" wide ascii
    $ = ":\\RECYCLER\\%s\\%d.rar" nocase wide ascii
    $ = ":\\RECYCLER\\cft_mon.exe" nocase wide ascii
    $ = "U_DISK Version 1.0" nocase wide ascii
condition:
    any of them
}

rule APT_Naikon_Satan
{
meta:
    author = "ThreatConnect, Inc."
    description = "Detects a likely Naikon related malware variant associated with RTF exploit MD5: 6F7FC7DEB0B3C096770E0C64AA2C821A and C2 kyawthushwe[.]com"
    example = "2F3E8F16F03952B40E4DD275F0519525"
    license = "https://creativecommons.org/licenses/by/4.0/legalcode"
strings:
    $ = "Satanserv.pdb" nocase wide ascii
    $ = ":\\Users\\johnstone\\Desktop\\" wide ascii
condition:
    any of them
}

rule APT_Naikon_Ssl
{
meta:
    author = "ThreatConnect, Inc."
    description = "Detects Ssl / SslMM malware variant"
    example = "718BA85DA97B948986FB904A68BAF1C5"
    license = "https://creativecommons.org/licenses/by/4.0/legalcode"
strings:
    $ = ":\\360\\360se\\360app\\" wide ascii
    $ = "Can't create myself on the H-drivers" wide ascii
    $ = "D-Disk:Can't create" wide ascii
    $ = "D-Disk: Can't create mm" wide ascii
    $ = "SslMM.exe" wide ascii
    $ = "Strat U-Disk!" wide ascii
    $ = {3A 5C 63 68 6F 6E 67 5C 6E 6? ?? 5C 52 65 6C 65 61 73 65 5C}
condition:
    any of them
}

rule APT_Naikon_systen
{
meta:
    author = "ThreatConnect, Inc."
    description = "Detects Sys10 malware variant"
    example = "ED5C08CED0F9A4D9D87748356D361FC6"
    license = "https://creativecommons.org/licenses/by/4.0/legalcode"
strings:
    $ = "&cp=%s&log=%s&index=%" wide ascii
    $ = "systen?index.asp=%d" wide ascii
    $ = "systen&cp=" wide ascii
condition:
    any of them
    and filesize < 1MB // Avoids false positives on BKAV antivirus binaries.
}

rule APT_Naikon_WinMM
{
meta:
    author = "ThreatConnect, Inc."
    description = "Detects Minjat / WinMM malware variant"
    example = "A2378FD84CEBE4B58C372D1C9B923542"
    license = "https://creativecommons.org/licenses/by/4.0/legalcode"
strings:
    $ = "ganran_bind_xiugai" wide ascii
    $ = "U-Disk:success unbind_and_running" wide ascii
    $ = "U-Disk: success releasing docfile" wide ascii
    $ = "WinMM Version" wide ascii
condition:
    any of them
}

rule APT_Naikon_Wininet
{
meta:
    author = "ThreatConnect, Inc."
    description = "Detects Sacto / Wininet malware variant"
    example = "92861D0A999591AEB72988B56D458040"
    license = "https://creativecommons.org/licenses/by/4.0/legalcode"
strings:
    $ = "AVCMyDownTrans" wide ascii
    $ = "AVCMyUpTrans" wide ascii
    $ = "WininetMM" wide ascii
condition:
    any of them
}

rule APT_Naikon_xServer
{
meta:
    author = "ThreatConnect, Inc."
    description = "Detects XServer malware variant"
    example = "E765E398D80F0CA3D3826E910163FC3A"
    license = "https://creativecommons.org/licenses/by/4.0/legalcode"
strings:
    $ = "\\MyProjects\\xServer\\" wide ascii
    $ = "WEBhAN95hNOKI" wide ascii // Mutation of "NOKIAN95" user-agent string
    $ = "xmlite.dat" fullword wide ascii
    $ = "x_srv_admin" fullword wide ascii
    $ = "x_srv_password" fullword wide ascii
    $ = "x_srv.vicp.net" wide ascii
condition:
    any of them
}

rule APT_Naikon_zh_EN
{
meta:
    author = "ThreatConnect, Inc."
    description = "Detects zh-EN language in hardcoded user-agent string"
    example = "9F7353EDAEDC65372A872B6E7B41FEB6"
    license = "https://creativecommons.org/licenses/by/4.0/legalcode"
strings:
    $ = {57 69 6E 64 6F 77 73 20 4E 54 20 3? 2E 3? 3B 20 7A 68 2D 45 4E 3B}
condition:
    any of them
}

rule APT_Naikon_Zhixin
{
meta:
    author = "ThreatConnect, Inc."
    description = "Detects Version string found alongside WininetMM variant"
    example = "D668291EA5DD870581EB6971BD51003D"
    license = "https://creativecommons.org/licenses/by/4.0/legalcode"
strings:
    $ = "Zhixin Version 1.0" wide ascii
condition:
    any of them
}