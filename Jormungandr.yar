/*
   YARA Rule Set
   Author: Ido Veltzman
   Date: 2023-06-24
   Reference: https://github.com/Idov31/Jormungandr
*/

/* Rule Set ----------------------------------------------------------------- */

rule Jormungandr {
   meta:
      description = "Jormungandr kernel COFF loader"
      author = "Ido Veltzman"
      reference = "https://github.com/Idov31/Jormungandr"
      date = "2023-06-24"

   strings:
      $s1 = "csrss.exe" fullword wide
      $s2 = "\\Device\\Jormungandr" fullword wide
      $s3 = "\\??\\Jormungandr" fullword wide
      $s4 = "__imp_" fullword ascii
      $s5 = "C:\\Windows\\System32\\ntdll.dll" fullword wide

      $op1 = { BA 60 00 00 00 33 C9 41 B8 4A 6F 72 6D }
      $op2 = { 48 8B 55 18 48 8B C8 E8 AD F3 FF FF }
      $op3 = { 48 83 EC 40 48 83 61 50 00 48 8D 05 35 21 }
      $op4 = { 48 8D 14 51 48 8B CE E8 FD 02 00 00 }

   condition:
      uint16(0) == 0x5a4d and filesize < 25KB and
      ( all of ($s*) and all of ($op*) )
}