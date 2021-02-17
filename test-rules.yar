
rule Embedded_EXE_Cloaking {
	meta:
		description = "Detects an embedded executable in a non-executable file"
		author = "Florian Roth"
		date = "2015/02/27"
		score = 60
		nodeepdive = 1
	strings:
		$noex_png = { 89 50 4E 47 }
		$noex_pdf = { 25 50 44 46 }
		$noex_rtf = { 7B 5C 72 74 66 31 }
		$noex_jpg = { FF D8 FF E0 }
		$noex_gif = { 47 49 46 38 }
		$mz  = { 4D 5A }
		$a1 = "This program cannot be run in DOS mode"
		$a2 = "This program must be run under Win32"
	condition:
		(
			( $noex_png at 0 ) or
			( $noex_pdf at 0 ) or
			( $noex_rtf at 0 ) or
			( $noex_jpg at 0 ) or
			( $noex_gif at 0 )
		)
		and
		for any i in (1..#mz): ( @a1 < ( @mz[i] + 200 ) or @a2 < ( @mz[i] + 200 ) )
}

rule Methodology_Suspicious_Shortcut_LOLcommand
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    reference = "https://twitter.com/ItsReallyNick/status/1176601500069576704"
    description = "Detects possible shortcut usage for .URL persistence"
    score = 50
    date = "27.09.2019"
    modified = "2021-02-14"
  strings:
    $file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=[^\x0d]*(powershell|cmd|certutil|mshta|wscript|cscript|rundll32|wmic|regsvr32|msbuild)(\.exe|)[^\x0d]{2,50}\x0d/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and any of ($file*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}

rule APT_Trojan_Win_REDFLARE_5
{
    meta:
        date = "2020-12-01"
        modified = "2020-12-01"
        md5 = "dfbb1b988c239ade4c23856e42d4127b, 3322fba40c4de7e3de0fda1123b0bf5d"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "AdjustTokenPrivileges" fullword
        $s2 = "LookupPrivilegeValueW" fullword
        $s3 = "ImpersonateLoggedOnUser" fullword
        $s4 = "runCommand" fullword
        $steal_token = { FF 15 [4] 85 C0 [1-40] C7 44 24 ?? 01 00 00 00 [0-20] C7 44 24 ?? 02 00 00 00 [0-20] FF 15 [4] FF [1-5] 85 C0 [4-40] 00 04 00 00 FF 15 [4-5] 85 C0 [2-20] ( BA 0F 00 00 00 | 6A 0F ) [1-4] FF 15 [4] 85 C0 74 [1-20] FF 15 [4] 85 C0 74 [1-20] ( 6A 0B | B9 0B 00 00 00 ) E8 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule password_dump_TESTING {
	meta:
		author = "Florian Roth"
		description = "Detects output files of common password dumpers (pwdump/wce)"
		date = "23/04/2014"
		score = 55
	strings:
		$pwdump      = /[\w]{3,15}:[A-Z0-9]{3,15}:[A-F0-9]{32}:[A-F0-9]{32}/ fullword
		$pwdump_nolm = /[\w]{3,15}:[A-Z0-9]{3,15}:NO PASSWORD[\*]{21}:[A-F0-9]{32}/ fullword
	condition:
		filesize < 400 and $pwdump at 0 or $pwdump_nolm at 0
}

rule TEST_String_Short {
   meta:
      description = "Detects Taskmasters tool"
      author = "Florian Roth"
      reference = "https://www.youtube.com/watch?v=XYuclHsoQO4&feature=youtu.be"
      date = "2019-11-11"
   strings:
      $s1 = "Created  Date: " fullword
      $s4 = "IEX" fullword ascii
   condition:
      all of them
}


rule TEST_Regex_Short {
   meta:
      description = "Detects Taskmasters tool"
      author = "Florian Roth"
      reference = "https://www.youtube.com/watch?v=XYuclHsoQO4&feature=youtu.be"
      date = "2019-11-11"
   strings:
      $s1 = "[A-Z]{40}" fullword
      $sr1 = /CE[\x0d]+/ nocase
   condition:
      all of them
}

rule Hunting_Rule_ShikataGaNai {
    meta:
        author    = "Steven Miller"
        company   = "FireEye"
        score = 65
        description = "Hunting rule to detect obfuscation applied by XOR used by ShikataGaNai algorithm used by msfvenom"
        reference = "https://www.fireeye.com/blog/threat-research/2019/10/shikata-ga-nai-encoder-still-going-strong.html"
    strings:
        $varInitializeAndXorCondition1_XorEAX = { B8 ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 59 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 40 | 41 | 42 | 43 | 45 | 46 | 47 ) ?? }
        $varInitializeAndXorCondition1_XorEBP = { BD ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5B | 5C | 5E | 5F ) [0-50] 31 ( 68 | 69 | 6A | 6B | 6D | 6E | 6F ) ?? }
        $varInitializeAndXorCondition1_XorEBX = { BB ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5C | 5D | 5E | 5F ) [0-50] 31 ( 58 | 59 | 5A | 5B | 5D | 5E | 5F ) ?? }
        $varInitializeAndXorCondition1_XorECX = { B9 ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 48 | 49 | 4A | 4B | 4D | 4E | 4F ) ?? }
        $varInitializeAndXorCondition1_XorEDI = { BF ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5B | 5C | 5D | 5E ) [0-50] 31 ( 78 | 79 | 7A | 7B | 7D | 7E | 7F ) ?? }
        $varInitializeAndXorCondition1_XorEDX = { BA ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 50 | 51 | 52 | 53 | 55 | 56 | 57 ) ?? }
        $varInitializeAndXorCondition2_XorEAX = { D9 74 24 F4 [0-30] B8 ?? ?? ?? ?? [0-10] ( 59 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 40 | 41 | 42 | 43 | 45 | 46 | 47 ) ?? }
        $varInitializeAndXorCondition2_XorEBP = { D9 74 24 F4 [0-30] BD ?? ?? ?? ?? [0-10] ( 58 | 59 | 5A | 5B | 5C | 5E | 5F ) [0-50] 31 ( 68 | 69 | 6A | 6B | 6D | 6E | 6F ) ?? }
        $varInitializeAndXorCondition2_XorEBX = { D9 74 24 F4 [0-30] BB ?? ?? ?? ?? [0-10] ( 58 | 59 | 5A | 5C | 5D | 5E | 5F ) [0-50] 31 ( 58 | 59 | 5A | 5B | 5D | 5E | 5F ) ?? }
        $varInitializeAndXorCondition2_XorECX = { D9 74 24 F4 [0-30] B9 ?? ?? ?? ?? [0-10] ( 58 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 48 | 49 | 4A | 4B | 4D | 4E | 4F ) ?? }
        $varInitializeAndXorCondition2_XorEDI = { D9 74 24 F4 [0-30] BF ?? ?? ?? ?? [0-10] ( 58 | 59 | 5A | 5B | 5C | 5D | 5E ) [0-50] 31 ( 78 | 79 | 7A | 7B | 7D | 7E | 7F ) ?? }
        $varInitializeAndXorCondition2_XorEDX = { D9 74 24 F4 [0-30] BA ?? ?? ?? ?? [0-10] ( 58 | 59 | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 50 | 51 | 52 | 53 | 55 | 56 | 57 ) ?? }
    condition:
        any of them
}

