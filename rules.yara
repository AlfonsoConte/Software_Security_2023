/* Rule Set ----------------------------------------------------------------- */

rule commentsorting {
   meta:
      description = " - file commentsorting"
      date = "2023-09-16"
      hash1 = "30bb20ed402afe7585bae4689f75e0e90e6d6580a229042c3a51eecefc153db7"
   strings:
      $s1 = "DropCypher.exe" fullword wide
      $s2 = "<!--<requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>-->" fullword ascii
      $s3 = "<description>elevate execution level</description>" fullword ascii
      $s4 = "Dropbox Encryption" fullword wide
      $s5 = "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ascii
   condition:
      uint16(0) == 0x5a4d and 3 of them
}


rule DropPayloadEmotet {
   meta:
      description = " - file DropPayloadEmotet.doc"
      date = "2023-09-16"
      hash1 = "814ab8953c401df37d57eafaf3d4b982c91bd912ee4671efbcc2085e8eb37c12"
   strings:
      $s1 = "*\\G{71B8D0D7-CFF9-4CBC-9DED-F13C852D434A}#2.0#0#C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\VBE\\MSForms.exd#Microsoft Forms 2.0" wide
      $s2 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Micr" wide
      $s3 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#" wide
      $s4 = "*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\Windows\\SysWOW64\\FM20.DLL#Microsoft Forms 2.0 Object Library" fullword wide
	  $s5 = "bABFACgAJABpAEEAdwBEAG8AdwBBACwAIAAkAGgAUQBRAEEAQgBvADEAQQApADsAJABhAEMAUQB4ADQAQQA9ACgAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAJwBxAG8A" ascii 
      $s6 = "YQBjAGgAKAAkAGkAQQB3AEQAbwB3AEEAIABpAG4AIAAkAFkAQgBBAEEAVQBfAEQAKQB7AHQAcgB5AHsAJABDAEEAYwBEAEEAQQAuAEQATwB3AE4AbABPAGEAZABGAGkA" ascii 
      $s7 = "JwAsACgAJwBrACcAKwAnAEEAQgAnACkAKQArACcAQwB3ACcAKQA7AEkAZgAgACgAKAAmACgAJwBHAGUAdAAnACsAJwAtAEkAJwArACcAdABlAG0AJwApACAAJABoAFEA" ascii 
      $s8 = "JwBvACcAKwAoACIAewAxAH0AewAwAH0AIgAtAGYAJwBtACcALAAoACcALgBjACcAKwAnAG8AJwApACkAKwAoACIAewAwAH0AewAxAH0AIgAtAGYAKAAnAC8AMQAnACsA" ascii 
      $s9 = "MAB9AHsAMQB9ACIALQBmACgAJwByAGEAJwArACcAZgAnACkALAAnAGkAJwApACsAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAKAAnAGMAbwBzACcAKwAnAGEAJwApACwA" ascii 
      $s10 = "KwAnADEAMwAnACkAOwAkAE8AUQBrAEEARABVAFUAWgA9ACgAKAAnAHEAJwArACcAQQB4ACcAKQArACcARAAnACsAKAAiAHsAMQB9AHsAMAB9ACIALQBmACcANABjACcA" ascii 
      $s11 = "KwAoACcALgAnACsAKAAnAGUAeAAnACsAJwBlACcAKQApADsAJAB1AEEAQQA0AEEAUQA0AD0AKAAoACIAewAxAH0AewAwAH0AIgAgAC0AZgAgACcAeAAnACwAKAAnAEEA" ascii 
      $s12 = "JABHAHgAUQBHAEIAQwBBAF8APQAoACgAJwBLAEMAJwArACcARAAnACkAKwAnAEQANAAnACsAJwAxACcAKQA7ACQAYwBrAEEANAAxAFEAUQBYACAAPQAgACgAJwA4ACcA" ascii 
      $s13 = "JwBAACcAKwAnAGgAJwArACgAIgB7ADAAfQB7ADEAfQAiACAALQBmACAAJwB0ACcALAAoACcAdABwACcAKwAnADoAJwApACkAKwAnAC8AJwArACcALwAxACcAKwAoACIA" ascii 
      $s14 = "LwAnACsAJwAvAGoAJwApACwAJwBwAG0AJwApACsAKAAnAHQAZQAnACsAJwBjACcAKQArACcAaAAnACsAKAAiAHsAMQB9AHsAMAB9AHsAMgB9ACIALQBmACgAJwAvAGMA" ascii 
      $s15 = "JwApACAAbgBgAGUAVAAuAFcAZQBCAEMAYABsAGAASQBFAE4AdAA7ACQAWQBCAEEAQQBVAF8ARAA9ACgAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAKAAnAGgAdAAnACsA" ascii 
      $s16 = "JwBzACcAKQArACgAIgB7ADAAfQB7ADEAfQAiACAALQBmACgAJwBzACcAKwAnAG8AYwAnACkALAAnAGkAJwApACsAKAAiAHsAMQB9AHsAMgB9AHsAMAB9ACIALQBmACAA" ascii 
      $s17 = "ZgAgACcAQAAnACwAJwAvACcALAAoACcAdAB0AHAAJwArACcAOgAvAC8AcAAnACsAJwB1AHIAJwApACwAJwBoACcAKQArACcAaQAnACsAJwBtAGEAJwArACcAcgAnACsA" ascii 
      $s18 = "JwAvACcAKQAsACcAdwB3ACcAKQArACgAJwAvACcAKwAnAEAAaAAnACkAKwAoACcAdAB0ACcAKwAnAHAAJwApACsAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAKAAnADoA" ascii 
      $s19 = "KAAnAC4AMQA2ACcAKwAnADYALwAnACkALAAnADIAMQAnACkAKwAoACIAewAyAH0AewAwAH0AewAxAH0AIgAtAGYAJwBwAC0AJwAsACgAJwBpAG4AJwArACcAYwAnACkA" ascii 
      $s20 = "aAAnACkAKQArACcAbwAnACsAJwBiAGkAJwArACcAYQAnACsAKAAiAHsAMgB9AHsAMQB9AHsAMAB9ACIALQBmACAAKAAnAGkAJwArACcAbQBhACcAKQAsACcAbQAvACcA" ascii 
	  $c1 = "ckA41QQX" ascii
	  $c2 = "OQkADUUZ" ascii
	  $c3 = "hQQABo1A" ascii
	  $c4 = "uAA4AQ4" ascii
	  $c5 = "CAcDAA" ascii
	  $c6 = "YBAAU_D" ascii
	  $c7 = "UAAX_ABB" ascii
	  $c8 = "aCQx4A" ascii
	  $c9 = "YUQAAA" ascii
	  $c10 = "iDUAwx" ascii
	  $c11 = "sAAAAAQ4" ascii
	  $c12 = "iAwDowA" ascii
	  $c13 = "GxQGBCA" ascii
	  $d1 = "rSHell" ascii  
	  $d2 = "ExeName32=" ascii 
   condition:
      uint16(0) == 0xcfd0 and (10 of ($s*) or 6 of ($c*) or ($d1 and $d2) )
}









