
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

rule APT_CN_Taskmasters_TimeStompingTool_Nov19_1 {
   meta:
      description = "Detects Taskmasters tool"
      author = "Florian Roth"
      reference = "https://www.youtube.com/watch?v=XYuclHsoQO4&feature=youtu.be"
      date = "2019-11-11"
   strings:
      $s1 = "Created  Date: " fullword
      $s2 = "Modified Date: " fullword
      $s3 = "Accessed Date: " fullword
      $s4 = "Success!" fullword ascii
      $s5 = "-show" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize <= 280KB and all of them
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

