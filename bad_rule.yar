import "pe"
import "math"
import "hash"

rule Dantes_YARA_Inferno {
     meta:
      author = "Florian Roth"
      description = "This rule is just really, really bad."
      reference = "Internal Research"
      date = "2022-11-30"
      score = 0
    strings:
      // Short atom
      $mz_header = "MZ"
      $zero_seq = { 00 ?? ?? ?? [1-4] 00 }  // this should cause YARA error 30 
      // Unnecessary shit
      $dos_stub = "This program cannot be run in DOS mode" nocase ascii wide
      // Bad regex
      $regex1 = /\.text.*/ nocase
      $regex2 = /(open|close).*(http|ftp)/ nocase   // no anchor
      $regex3 = /\\[\w]+\.[\w]{3}/                  // short anchor, all kinds of chars
      // Repeating characters
      $pat1 = "AAAAAAA" // this could cause YARA error 30 on some files
   condition:
      // no header and file size check
      1 of them
      // loops are bad
      and for any i in (0..pe.number_of_resources-1): (
            hash.sha256(pe.resources[i].offset,pe.resources[i].length) == "6d9bd1110034b754d9320060c3ea84a9f18b07fab5b8e0078ce11a4cbae465fa"
         )
      // a even worse loop
      and for all i in (1..#zero_seq) : (@zero_seq[i] < 10000)
      // calculating entropy over large portions of the file
      and math.entropy(0, filesize) > 0
}
