//POC: rules from https://github.com/fireeye/capa-rules converted to YARA using capa2yara.py by Arnim Rupp (not published yet)

//Beware: This has less rules than capa (because not all fit into YARA) and is less precise because e.g. capas function scopes are applied to the whole file

//Beware: Some rules are incomplete because an optional branch was not supported by yara. These rules are marked in a comment in meta: (search for incomplete)


import "pe"


rule capa_create_or_open_file { 
  meta: 
 	description = "create or open file (converted from capa rule)"
	author = "michael.hunhoff@fireeye.com"
	lib = "True"
	scope = "basic block"
	mbc = "File System::Create File [C0016]"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/create-or-open-file.yml"
	date = "2021-05-15"

  strings: 
 	$api_aaa = "CreateFile" ascii wide
	$api_aab = "CreateFileEx" ascii wide
	$api_aac = "IoCreateFile" ascii wide
	$api_aad = "IoCreateFileEx" ascii wide
	$api_aae = "ZwOpenFile" ascii wide
	$api_aaf = "ZwCreateFile" ascii wide
	$api_aag = "NtOpenFile" ascii wide
	$api_aah = "NtCreateFile" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_aaa 
	or 	$api_aab 
	or 	$api_aac 
	or 	$api_aad 
	or 	$api_aae 
	or 	$api_aaf 
	or 	$api_aag 
	or 	$api_aah  ) 
}

rule capa_open_thread { 
  meta: 
 	description = "open thread (converted from capa rule)"
	author = "0x534a@mailbox.org"
	lib = "True"
	scope = "basic block"
	hash = "787cbc8a6d1bc58ea169e51e1ad029a637f22560660cc129ab8a099a745bd50e:00502F4C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/open-thread.yml"
	date = "2021-05-15"

  strings: 
 	$api_aai = "NtOpenThread" ascii wide
	$api_aaj = "ZwOpenThread" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /OpenThread/) 
	or 	$api_aai 
	or 	$api_aaj  ) 
}

rule capa_allocate_memory { 
  meta: 
 	description = "allocate memory (converted from capa rule)"
	author = "0x534a@mailbox.org"
	lib = "True"
	scope = "basic block"
	mbc = "Memory::Allocate Memory [C0007]"
	hash = "Practical Malware Analysis Lab 03-03.exe_:0x4010EA"
	hash = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/allocate-memory.yml"
	date = "2021-05-15"

  strings: 
 	$api_aak = "NtAllocateVirtualMemory" ascii wide
	$api_aal = "ZwAllocateVirtualMemory" ascii wide
	$api_aam = "NtMapViewOfSection" ascii wide
	$api_aan = "ZwMapViewOfSection" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /VirtualAlloc/) 
	or 	pe.imports(/kernel32/i, /VirtualAllocEx/) 
	or 	pe.imports(/kernel32/i, /VirtualAllocExNuma/) 
	or 	pe.imports(/kernel32/i, /VirtualProtect/) 
	or 	pe.imports(/kernel32/i, /VirtualProtectEx/) 
	or 	$api_aak 
	or 	$api_aal 
	or 	$api_aam 
	or 	$api_aan  ) 
}

rule capa_delay_execution { 
  meta: 
 	description = "delay execution (converted from capa rule)"
	author = "michael.hunhoff@fireeye.com"
	lib = "True"
	scope = "basic block"
	mbc = "Anti-Behavioral Analysis::Dynamic Analysis Evasion::Delayed Execution [B0003.003]"
	references = "https://docs.microsoft.com/en-us/windows/win32/sync/wait-functions"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/TimingAttacks/timing.cpp"
	hash = "al-khaser_x86.exe_:0x449770"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/delay-execution.yml"
	date = "2021-05-15"

  strings: 
 	$api_aao = "WaitOnAddress" ascii wide
	$api_aap = "NtDelayExecution" ascii wide
	$api_aaq = "KeWaitForSingleObject" ascii wide
	$api_aar = "KeDelayExecutionThread" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /Sleep/) 
	or 	pe.imports(/kernel32/i, /SleepEx/) 
	or 	pe.imports(/kernel32/i, /WaitForSingleObject/) 
	or 	pe.imports(/kernel32/i, /SignalObjectAndWait/) 
	or 	pe.imports(/kernel32/i, /WaitForSingleObjectEx/) 
	or 	pe.imports(/kernel32/i, /WaitForMultipleObjects/) 
	or 	pe.imports(/kernel32/i, /WaitForMultipleObjectsEx/) 
	or 	pe.imports(/kernel32/i, /RegisterWaitForSingleObject/) 
	or 	$api_aao 
	or 	pe.imports(/user32/i, /MsgWaitForMultipleObjects/) 
	or 	pe.imports(/user32/i, /MsgWaitForMultipleObjectsEx/) 
	or 	$api_aap 
	or 	$api_aaq 
	or 	$api_aar  ) 
}

rule capa_write_process_memory { 
  meta: 
 	description = "write process memory (converted from capa rule)"
	author = "moritz.raabe@fireeye.com"
	lib = "True"
	scope = "function"
	attack = "Defense Evasion::Process Injection [T1055]"
	hash = "2D3EDC218A90F03089CC01715A9F047F"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/write-process-memory.yml"
	date = "2021-05-15"

  strings: 
 	$api_aas = "NtWow64WriteVirtualMemory64" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /WriteProcessMemory/) 
	or 	pe.imports(/ntdll/i, /NtWriteVirtualMemory/) 
	or 	pe.imports(/ntdll/i, /ZwWriteVirtualMemory/) 
	or 	$api_aas  ) 
}

rule capa_open_process { 
  meta: 
 	description = "open process (converted from capa rule)"
	author = "0x534a@mailbox.org"
	lib = "True"
	scope = "basic block"
	hash = "Practical Malware Analysis Lab 17-02.dll_:0x1000D10D"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/open-process.yml"
	date = "2021-05-15"

  strings: 
 	$api_aat = "NtOpenProcess" ascii wide
	$api_aau = "ZwOpenProcess" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /OpenProcess/) 
	or 	$api_aat 
	or 	$api_aau  ) 
}

rule capa_delete_volume_shadow_copies { 
  meta: 
 	description = "delete volume shadow copies (converted from capa rule)"
	namespace = "impact/inhibit-system-recovery"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Impact::Inhibit System Recovery [T1490]"
	attack = "Defense Evasion::Indicator Removal on Host::File Deletion [T1070.004]"
	mbc = "Impact::Disk Content Wipe::Delete Shadow Drive [F0014.001]"
	hash = "B87E9DD18A5533A09D3E48A7A1EFBCF6"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/impact/inhibit-system-recovery/delete-volume-shadow-copies.yml"
	date = "2021-05-15"

  strings: 
 	$aaw = /vssadmin.{,1000} delete shadows/ nocase ascii wide 
	$aax = /vssadmin.{,1000} resize shadowstorage/ nocase ascii wide 
	$aay = /wmic.{,1000} shadowcopy delete/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aaw 
	or 	$aax 
	or 	$aay  ) 
}

rule capa_reference_analysis_tools_strings { 
  meta: 
 	description = "reference analysis tools strings (converted from capa rule)"
	namespace = "anti-analysis"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	mbc = "Discovery::Analysis Tool Discovery::Process Detection [B0013.001]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiAnalysis/process.cpp"
	hash = "al-khaser_x86.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/reference-analysis-tools-strings.yml"
	date = "2021-05-15"

  strings: 
 	$aaz = /ollydbg.exe/ nocase ascii wide 
	$aba = /ProcessHacker.exe/ nocase ascii wide 
	$abb = /tcpview.exe/ nocase ascii wide 
	$abc = /autoruns.exe/ nocase ascii wide 
	$abd = /autorunsc.exe/ nocase ascii wide 
	$abe = /filemon.exe/ nocase ascii wide 
	$abf = /procmon.exe/ nocase ascii wide 
	$abg = /regmon.exe/ nocase ascii wide 
	$abh = /procexp.exe/ nocase ascii wide 
	$abi = /idaq.exe/ nocase ascii wide 
	$abj = /idaq64.exe/ nocase ascii wide 
	$abk = /ImmunityDebugger.exe/ nocase ascii wide 
	$abl = /Wireshark.exe/ nocase ascii wide 
	$abm = /dumpcap.exe/ nocase ascii wide 
	$abn = /HookExplorer.exe/ nocase ascii wide 
	$abo = /ImportREC.exe/ nocase ascii wide 
	$abp = /PETools.exe/ nocase ascii wide 
	$abq = /LordPE.exe/ nocase ascii wide 
	$abr = /SysInspector.exe/ nocase ascii wide 
	$abs = /proc_analyzer.exe/ nocase ascii wide 
	$abt = /sysAnalyzer.exe/ nocase ascii wide 
	$abu = /sniff_hit.exe/ nocase ascii wide 
	$abv = /windbg.exe/ nocase ascii wide 
	$abw = /joeboxcontrol.exe/ nocase ascii wide 
	$abx = /joeboxserver.exe/ nocase ascii wide 
	$aby = /ResourceHacker.exe/ nocase ascii wide 
	$abz = /x32dbg.exe/ nocase ascii wide 
	$aca = /x64dbg.exe/ nocase ascii wide 
	$acb = /Fiddler.exe/ nocase ascii wide 
	$acc = /httpdebugger.exe/ nocase ascii wide 
	$acd = /fakenet.exe/ nocase ascii wide 
	$ace = /netmon.exe/ nocase ascii wide 
	$acf = /WPE PRO.exe/ nocase ascii wide 
	$acg = /decompile.exe/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aaz 
	or 	$aba 
	or 	$abb 
	or 	$abc 
	or 	$abd 
	or 	$abe 
	or 	$abf 
	or 	$abg 
	or 	$abh 
	or 	$abi 
	or 	$abj 
	or 	$abk 
	or 	$abl 
	or 	$abm 
	or 	$abn 
	or 	$abo 
	or 	$abp 
	or 	$abq 
	or 	$abr 
	or 	$abs 
	or 	$abt 
	or 	$abu 
	or 	$abv 
	or 	$abw 
	or 	$abx 
	or 	$aby 
	or 	$abz 
	or 	$aca 
	or 	$acb 
	or 	$acc 
	or 	$acd 
	or 	$ace 
	or 	$acf 
	or 	$acg  ) 
}

rule capa_timestomp_file { 
  meta: 
 	description = "timestomp file (converted from capa rule)"
	namespace = "anti-analysis/anti-forensic/timestomp"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Indicator Removal on Host::Timestomp [T1070.006]"
	hash = "Practical Malware Analysis Lab 03-04.exe_:0x4014e0"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-forensic/timestomp/timestomp-file.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/kernel32/i, /GetSystemTime/) 
	or 	pe.imports(/kernel32/i, /FileTimeToLocalFileTime/) 
	or 	pe.imports(/kernel32/i, /GetSystemTimeAsFileTime/) 
	or 	pe.imports(/kernel32/i, /SystemTimeToFileTime/) 
	or 	pe.imports(/kernel32/i, /GetFileTime/)  )  ) 
	and 	pe.imports(/kernel32/i, /SetFileTime/)  ) 
}

rule capa_clear_the_Windows_event_log { 
  meta: 
 	description = "clear the Windows event log (converted from capa rule)"
	namespace = "anti-analysis/anti-forensic/clear-logs"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	attack = "Defense Evasion::Indicator Removal on Host::Clear Windows Event Logs [T1070.001]"
	hash = "82BF6347ACF15E5D883715DC289D8A2B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-forensic/clear-logs/clear-the-windows-event-log.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /ElfClearEventLogFile/)  ) 
}

rule capa_check_for_sandbox_and_av_modules { 
  meta: 
 	description = "check for sandbox and av modules (converted from capa rule)"
	namespace = "anti-analysis/anti-av"
	author = "@_re_fox"
	scope = "basic block"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	mbc = "Anti-Behavioral Analysis::Sandbox Detection [B0007]"
	hash = "ccbf7cba35bab56563c0fbe4237fdc41"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-av/check-for-sandbox-and-av-modules.yml"
	date = "2021-05-15"

  strings: 
 	$api_ach = "GetModuleHandle" ascii wide
	$aci = /avghook(x|a)\.dll/ nocase ascii wide 
	$acj = /snxhk\.dll/ nocase ascii wide 
	$ack = /sf2\.dll/ nocase ascii wide 
	$acl = /sbiedll\.dll/ nocase ascii wide 
	$acm = /dbghelp\.dll/ nocase ascii wide 
	$acn = /api_log\.dll/ nocase ascii wide 
	$aco = /dir_watch\.dll/ ascii wide 
	$acp = /pstorec\.dll/ nocase ascii wide 
	$acq = /vmcheck\.dll/ nocase ascii wide 
	$acr = /wpespy\.dll/ nocase ascii wide 
	$acs = /cmdvrt(64|32).dll/ nocase ascii wide 
	$act = /sxin.dll/ nocase ascii wide 
	$acu = /dbghelp\.dll/ nocase ascii wide 
	$acv = /printfhelp\.dll/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_ach 
	and  (  ( 	$aci 
	or 	$acj 
	or 	$ack 
	or 	$acl 
	or 	$acm 
	or 	$acn 
	or 	$aco 
	or 	$acp 
	or 	$acq 
	or 	$acr 
	or 	$acs 
	or 	$act 
	or 	$acu 
	or 	$acv  )  )  ) 
}

rule capa_packed_with_pebundle { 
  meta: 
 	description = "packed with pebundle (converted from capa rule)"
	namespace = "anti-analysis/packer/pebundle"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "db9fe790b4e18abf55df31aa0b81e558"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/pebundle/packed-with-pebundle.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any acw in pe.sections : ( acw.name == "pebundle" ) 
	or 	for any acx in pe.sections : ( acx.name == "PEBundle" )  ) 
}

rule capa_packed_with_ASPack { 
  meta: 
 	description = "packed with ASPack (converted from capa rule)"
	namespace = "anti-analysis/packer/aspack"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "http://www.aspack.com/"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "2055994ff75b4309eee3a49c5749d306"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/aspack/packed-with-aspack.yml"
	date = "2021-05-15"

  strings: 
 	$str_adc = "The procedure entry point %s could not be located in the dynamic link library %s" ascii wide
	$str_add = "The ordinal %u could not be located in the dynamic link library %s" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any acy in pe.sections : ( acy.name == ".aspack" ) 
	or 	for any acz in pe.sections : ( acz.name == ".adata" ) 
	or 	for any ada in pe.sections : ( ada.name == ".ASPack" ) 
	or 	for any adb in pe.sections : ( adb.name == "ASPack" ) 
	or 	$str_adc 
	or 	$str_add  ) 
}

rule capa_packed_with_nspack { 
  meta: 
 	description = "packed with nspack (converted from capa rule)"
	namespace = "anti-analysis/packer/nspack"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "02179f3ba93663074740b5c0d283bae2"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/nspack/packed-with-nspack.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any ade in pe.sections : ( ade.name == ".nsp0" ) 
	or 	for any adf in pe.sections : ( adf.name == ".nsp1" ) 
	or 	for any adg in pe.sections : ( adg.name == ".nsp2" )  ) 
}

rule capa_packed_with_kkrunchy { 
  meta: 
 	description = "packed with kkrunchy (converted from capa rule)"
	namespace = "anti-analysis/packer/kkrunchy"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "http://www.farbrausch.de/~fg/kkrunchy/"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "f9ac6b16273556b3a57bf2c6d7e7db97"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/kkrunchy/packed-with-kkrunchy.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any adh in pe.sections : ( adh.name == "kkrunchy" )  ) 
}

rule capa_packed_with_petite { 
  meta: 
 	description = "packed with petite (converted from capa rule)"
	namespace = "anti-analysis/packer/petite"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "2a7429d60040465f9bd27bbae2beef88"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/petite/packed-with-petite.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any adi in pe.sections : ( adi.name == ".petite" )  ) 
}

rule capa_packed_with_pelocknt { 
  meta: 
 	description = "packed with pelocknt (converted from capa rule)"
	namespace = "anti-analysis/packer/pelocknt"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "f0a6a1bd6d760497623611e8297a81df"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/pelocknt/packed-with-pelocknt.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any adj in pe.sections : ( adj.name == "PELOCKnt" )  ) 
}

rule capa_packed_with_upack { 
  meta: 
 	description = "packed with upack (converted from capa rule)"
	namespace = "anti-analysis/packer/upack"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "9d98f8519d9fee8219caca5b31eef0bd"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/upack/packed-with-upack.yml"
	date = "2021-05-15"

  strings: 
 	$str_adm = "UpackByDwing@" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any adk in pe.sections : ( adk.name == ".Upack" ) 
	or 	for any adl in pe.sections : ( adl.name == ".ByDwing" ) 
	or 	$str_adm  ) 
}

rule capa_packed_with_y0da_crypter { 
  meta: 
 	description = "packed with y0da crypter (converted from capa rule)"
	namespace = "anti-analysis/packer/y0da"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "0cd2b334aede270b14868db28211cde3"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/y0da/packed-with-y0da-crypter.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any adn in pe.sections : ( adn.name == ".y0da" ) 
	or 	for any ado in pe.sections : ( ado.name == ".y0da_1" ) 
	or 	for any adp in pe.sections : ( adp.name == ".yP" )  ) 
}

rule capa_packed_with_Confuser { 
  meta: 
 	description = "packed with Confuser (converted from capa rule)"
	namespace = "anti-analysis/packer/confuser"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing::Confuser [F0001.009]"
	hash = "b9f5bd514485fb06da39beff051b9fdc"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/confuser/packed-with-confuser.yml"
	date = "2021-05-15"

  strings: 
 	$str_adq = "ConfusedByAttribute" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_adq  ) 
}

rule capa_packed_with_amber { 
  meta: 
 	description = "packed with amber (converted from capa rule)"
	namespace = "anti-analysis/packer/amber"
	author = "john.gorman@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://github.com/EgeBalci/amber"
	hash = "bb7922d368a9a9c8d981837b5ad988f1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/amber/packed-with-amber.yml"
	date = "2021-05-15"

  strings: 
 	$str_adr = "Amber - Reflective PE Packer" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_adr  ) 
}

rule capa_packed_with_VMProtect { 
  meta: 
 	description = "packed with VMProtect (converted from capa rule)"
	namespace = "anti-analysis/packer/vmprotect"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing::VMProtect [F0001.010]"
	references = "https://www.pcworld.com/article/2824572/leaked-programming-manual-may-help-criminals-develop-more-atm-malware.html"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "971e599e6e707349eccea2fd4c8e5f67"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/vmprotect/packed-with-vmprotect.yml"
	date = "2021-05-15"

  strings: 
 	$str_ads = "A debugger has been found running in your system." ascii wide
	$str_adt = "Please, unload it from memory and restart your program." ascii wide
	$str_adu = "File corrupted!. This program has been manipulated and maybe" ascii wide
	$str_adv = "it's infected by a Virus or cracked. This file won't work anymore." ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_ads 
	or 	$str_adt 
	or 	$str_adu 
	or 	$str_adv 
	or 	for any adw in pe.sections : ( adw.name == ".vmp0" ) 
	or 	for any adx in pe.sections : ( adx.name == ".vmp1" ) 
	or 	for any ady in pe.sections : ( ady.name == ".vmp2" )  ) 
}

rule capa_packed_with_rlpack { 
  meta: 
 	description = "packed with rlpack (converted from capa rule)"
	namespace = "anti-analysis/packer/rlpack"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "068a76d4823419b376d418cf03215d5c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/rlpack/packed-with-rlpack.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any adz in pe.sections : ( adz.name == ".RLPack" ) 
	or 	for any aea in pe.sections : ( aea.name == ".packed" )  ) 
}

rule capa_packed_with_UPX { 
  meta: 
 	description = "packed with UPX (converted from capa rule)"
	namespace = "anti-analysis/packer/upx"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing::UPX [F0001.008]"
	hash = "CD2CBA9E6313E8DF2C1273593E649682"
	hash = "Practical Malware Analysis Lab 01-02.exe_:0x0401000"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/upx/packed-with-upx.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any aeb in pe.sections : ( aeb.name == "UPX0" ) 
	or 	for any aec in pe.sections : ( aec.name == "UPX1" )  ) 
}

rule capa_packed_with_peshield { 
  meta: 
 	description = "packed with peshield (converted from capa rule)"
	namespace = "anti-analysis/packer/peshield"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "a3c0a2425ea84103adde03a92176424c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/peshield/packed-with-peshield.yml"
	date = "2021-05-15"

  strings: 
 	$aef = / PE-SHiELD v[0-9]\.[0-9]/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any aed in pe.sections : ( aed.name == "PESHiELD" ) 
	or 	for any aee in pe.sections : ( aee.name == "PESHiELD_1" ) 
	or 	$aef  ) 
}

rule capa_reference_anti_VM_strings_targeting_VMWare { 
  meta: 
 	description = "reference anti-VM strings targeting VMWare (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/VMWare.cpp"
	hash = "al-khaser_x86.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-vmware.yml"
	date = "2021-05-15"

  strings: 
 	$aei = /VMWare/ nocase ascii wide 
	$aej = /VMTools/ nocase ascii wide 
	$aek = /SOFTWARE\\VMware, Inc\.\\VMware Tools/ nocase ascii wide 
	$ael = /vmnet.sys/ nocase ascii wide 
	$aem = /vmmouse.sys/ nocase ascii wide 
	$aen = /vmusb.sys/ nocase ascii wide 
	$aeo = /vm3dmp.sys/ nocase ascii wide 
	$aep = /vmci.sys/ nocase ascii wide 
	$aeq = /vmhgfs.sys/ nocase ascii wide 
	$aer = /vmmemctl.sys/ nocase ascii wide 
	$aes = /vmx86.sys/ nocase ascii wide 
	$aet = /vmrawdsk.sys/ nocase ascii wide 
	$aeu = /vmusbmouse.sys/ nocase ascii wide 
	$aev = /vmkdb.sys/ nocase ascii wide 
	$aew = /vmnetuserif.sys/ nocase ascii wide 
	$aex = /vmnetadapter.sys/ nocase ascii wide 
	$aey = /\\\\.\\HGFS/ nocase ascii wide 
	$aez = /\\\\.\\vmci/ nocase ascii wide 
	$afa = /vmtoolsd.exe/ nocase ascii wide 
	$afb = /vmwaretray.exe/ nocase ascii wide 
	$afc = /vmwareuser.exe/ nocase ascii wide 
	$afd = /VGAuthService.exe/ nocase ascii wide 
	$afe = /vmacthlp.exe/ nocase ascii wide 
	$aff = /vmci/ nocase ascii wide 
	$afg = /vmhgfs/ nocase ascii wide 
	$afh = /vmmouse/ nocase ascii wide 
	$afi = /vmmemctl/ nocase ascii wide 
	$afj = /vmusb/ nocase ascii wide 
	$afk = /vmusbmouse/ nocase ascii wide 
	$afl = /vmx_svga/ nocase ascii wide 
	$afm = /vmxnet/ nocase ascii wide 
	$afn = /vmx86/ nocase ascii wide 
	$afo = /VMwareVMware/ nocase ascii wide 
	$afp = /vmGuestLib.dll/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aei 
	or 	$aej 
	or 	$aek 
	or 	$ael 
	or 	$aem 
	or 	$aen 
	or 	$aeo 
	or 	$aep 
	or 	$aeq 
	or 	$aer 
	or 	$aes 
	or 	$aet 
	or 	$aeu 
	or 	$aev 
	or 	$aew 
	or 	$aex 
	or 	$aey 
	or 	$aez 
	or 	$afa 
	or 	$afb 
	or 	$afc 
	or 	$afd 
	or 	$afe 
	or 	$aff 
	or 	$afg 
	or 	$afh 
	or 	$afi 
	or 	$afj 
	or 	$afk 
	or 	$afl 
	or 	$afm 
	or 	$afn 
	or 	$afo 
	or 	$afp  ) 
}

rule capa_check_for_windows_sandbox_via_device { 
  meta: 
 	description = "check for windows sandbox via device (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LloydLabs/wsb-detect"
	hash = "773290480d5445f11d3dc1b800728966"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-windows-sandbox-via-device.yml"
	date = "2021-05-15"

  strings: 
 	$api_afq = "CreateFile" ascii wide
	$str_afr = "\\\\.\\GLOBALROOT\\device\\vmsmb" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_afq 
	and 	$str_afr  ) 
}

rule capa_check_for_microsoft_office_emulation { 
  meta: 
 	description = "check for microsoft office emulation (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "@_re_fox"
	scope = "function"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection::Product Key/ID Testing [B0007.005]"
	references = "https://github.com/LloydLabs/wsb-detect"
	hash = "773290480d5445f11d3dc1b800728966"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-microsoft-office-emulation.yml"
	date = "2021-05-15"

  strings: 
 	$afs = /OfficePackagesForWDAG/ ascii wide 
	$api_aft = "GetWindowsDirectory" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$afs 
	and 	$api_aft  ) 
}

rule capa_check_for_sandbox_username { 
  meta: 
 	description = "check for sandbox username (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "@_re_fox"
	scope = "function"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion [T1497]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LloydLabs/wsb-detect"
	hash = "ccbf7cba35bab56563c0fbe4237fdc41"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-sandbox-username.yml"
	date = "2021-05-15"

  strings: 
 	$api_afu = "GetUserName" ascii wide
	$afv = /MALTEST/ nocase ascii wide 
	$afw = /TEQUILABOOMBOOM/ nocase ascii wide 
	$afx = /SANDBOX/ nocase ascii wide 
	$afy = /\bVIRUS/ nocase ascii wide 
	$afz = /MALWARE/ nocase ascii wide 
	$aga = /SAND\sBOX/ nocase ascii wide 
	$agb = /Test\sUser/ nocase ascii wide 
	$agc = /CurrentUser/ nocase ascii wide 
	$agd = /7SILVIA/ nocase ascii wide 
	$age = /FORTINET/ nocase ascii wide 
	$agf = /John\sDoe/ nocase ascii wide 
	$agg = /Emily/ nocase ascii wide 
	$agh = /HANSPETER\-PC/ nocase ascii wide 
	$agi = /HAPUBWS/ nocase ascii wide 
	$agj = /Hong\sLee/ nocase ascii wide 
	$agk = /IT\-ADMIN/ nocase ascii wide 
	$agl = /JOHN\-PC/ nocase ascii wide 
	$agm = /Johnson/ nocase ascii wide 
	$agn = /Miller/ nocase ascii wide 
	$ago = /MUELLER\-PC/ nocase ascii wide 
	$agp = /Peter\sWilson/ nocase ascii wide 
	$agq = /SystemIT/ nocase ascii wide 
	$agr = /Timmy/ nocase ascii wide 
	$ags = /WIN7\-TRAPS/ nocase ascii wide 
	$agt = /WDAGUtilityAccount/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_afu 
	and  (  ( 	$afv 
	or 	$afw 
	or 	$afx 
	or 	$afy 
	or 	$afz 
	or 	$aga 
	or 	$agb 
	or 	$agc 
	or 	$agd 
	or 	$age 
	or 	$agf 
	or 	$agg 
	or 	$agh 
	or 	$agi 
	or 	$agj 
	or 	$agk 
	or 	$agl 
	or 	$agm 
	or 	$agn 
	or 	$ago 
	or 	$agp 
	or 	$agq 
	or 	$agr 
	or 	$ags 
	or 	$agt  )  )  ) 
}

rule capa_reference_anti_VM_strings_targeting_Parallels { 
  meta: 
 	description = "reference anti-VM strings targeting Parallels (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Parallels.cpp"
	hash = "al-khaser_x86.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-parallels.yml"
	date = "2021-05-15"

  strings: 
 	$agu = /Parallels/ nocase ascii wide 
	$agv = /prl_cc.exe/ nocase ascii wide 
	$agw = /prl_tools.exe/ nocase ascii wide 
	$agx = /prl hyperv/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$agu 
	or 	$agv 
	or 	$agw 
	or 	$agx  ) 
}

rule capa_reference_anti_VM_strings_targeting_VirtualBox { 
  meta: 
 	description = "reference anti-VM strings targeting VirtualBox (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/VirtualBox.cpp"
	hash = "al-khaser_x86.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-virtualbox.yml"
	date = "2021-05-15"

  strings: 
 	$agy = /VBOX/ nocase ascii wide 
	$agz = /VEN_VBOX/ nocase ascii wide 
	$aha = /VirtualBox/ nocase ascii wide 
	$ahb = /06\/23\/99/ nocase ascii wide 
	$ahc = /HARDWARE\\ACPI\\DSDT\\VBOX__/ nocase ascii wide 
	$ahd = /HARDWARE\\ACPI\\FADT\\VBOX__/ nocase ascii wide 
	$ahe = /HARDWARE\\ACPI\\RSDT\\VBOX__/ nocase ascii wide 
	$ahf = /SOFTWARE\\Oracle\\VirtualBox Guest Additions/ nocase ascii wide 
	$ahg = /SYSTEM\\ControlSet001\\Services\\VBoxGuest/ nocase ascii wide 
	$ahh = /SYSTEM\\ControlSet001\\Services\\VBoxMouse/ nocase ascii wide 
	$ahi = /SYSTEM\\ControlSet001\\Services\\VBoxService/ nocase ascii wide 
	$ahj = /SYSTEM\\ControlSet001\\Services\\VBoxSF/ nocase ascii wide 
	$ahk = /SYSTEM\\ControlSet001\\Services\\VBoxVideo/ nocase ascii wide 
	$ahl = /VBoxMouse.sys/ nocase ascii wide 
	$ahm = /VBoxGuest.sys/ nocase ascii wide 
	$ahn = /VBoxSF.sys/ nocase ascii wide 
	$aho = /VBoxVideo.sys/ nocase ascii wide 
	$ahp = /vboxdisp.dll/ nocase ascii wide 
	$ahq = /vboxhook.dll/ nocase ascii wide 
	$ahr = /vboxmrxnp.dll/ nocase ascii wide 
	$ahs = /vboxogl.dll/ nocase ascii wide 
	$aht = /vboxoglarrayspu.dll/ nocase ascii wide 
	$ahu = /vboxoglcrutil.dll/ nocase ascii wide 
	$ahv = /vboxoglerrorspu.dll/ nocase ascii wide 
	$ahw = /vboxoglfeedbackspu.dll/ nocase ascii wide 
	$ahx = /vboxoglpackspu.dll/ nocase ascii wide 
	$ahy = /vboxoglpassthroughspu.dll/ nocase ascii wide 
	$ahz = /vboxservice.exe/ nocase ascii wide 
	$aia = /vboxtray.exe/ nocase ascii wide 
	$aib = /VBoxControl.exe/ nocase ascii wide 
	$aic = /oracle\\virtualbox guest additions\\/ nocase ascii wide 
	$aid = /\\\\.\\VBoxMiniRdrDN/ nocase ascii wide 
	$aie = /\\\\.\\VBoxGuest/ nocase ascii wide 
	$aif = /\\\\.\\pipe\\VBoxMiniRdDN/ nocase ascii wide 
	$aig = /\\\\.\\VBoxTrayIPC/ nocase ascii wide 
	$aih = /\\\\.\\pipe\\VBoxTrayIPC/ nocase ascii wide 
	$aii = /VBoxTrayToolWndClass/ nocase ascii wide 
	$aij = /VBoxTrayToolWnd/ nocase ascii wide 
	$aik = /vboxservice.exe/ nocase ascii wide 
	$ail = /vboxtray.exe/ nocase ascii wide 
	$aim = /vboxvideo/ nocase ascii wide 
	$ain = /VBoxVideoW8/ nocase ascii wide 
	$aio = /VBoxWddm/ nocase ascii wide 
	$aip = /PCI\\VEN_80EE&DEV_CAFE/ nocase ascii wide 
	$aiq = /82801FB/ nocase ascii wide 
	$air = /82441FX/ nocase ascii wide 
	$ais = /82371SB/ nocase ascii wide 
	$ait = /OpenHCD/ nocase ascii wide 
	$aiu = /ACPIBus_BUS_0/ nocase ascii wide 
	$aiv = /PCI_BUS_0/ nocase ascii wide 
	$aiw = /PNP_BUS_0/ nocase ascii wide 
	$aix = /Oracle Corporation/ nocase ascii wide 
	$aiy = /VBoxWdd/ nocase ascii wide 
	$aiz = /VBoxS/ nocase ascii wide 
	$aja = /VBoxMouse/ nocase ascii wide 
	$ajb = /VBoxGuest/ nocase ascii wide 
	$ajc = /VBoxVBoxVBox/ nocase ascii wide 
	$ajd = /innotek GmbH/ nocase ascii wide 
	$aje = /drivers\\vboxdrv/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$agy 
	or 	$agz 
	or 	$aha 
	or 	$ahb 
	or 	$ahc 
	or 	$ahd 
	or 	$ahe 
	or 	$ahf 
	or 	$ahg 
	or 	$ahh 
	or 	$ahi 
	or 	$ahj 
	or 	$ahk 
	or 	$ahl 
	or 	$ahm 
	or 	$ahn 
	or 	$aho 
	or 	$ahp 
	or 	$ahq 
	or 	$ahr 
	or 	$ahs 
	or 	$aht 
	or 	$ahu 
	or 	$ahv 
	or 	$ahw 
	or 	$ahx 
	or 	$ahy 
	or 	$ahz 
	or 	$aia 
	or 	$aib 
	or 	$aic 
	or 	$aid 
	or 	$aie 
	or 	$aif 
	or 	$aig 
	or 	$aih 
	or 	$aii 
	or 	$aij 
	or 	$aik 
	or 	$ail 
	or 	$aim 
	or 	$ain 
	or 	$aio 
	or 	$aip 
	or 	$aiq 
	or 	$air 
	or 	$ais 
	or 	$ait 
	or 	$aiu 
	or 	$aiv 
	or 	$aiw 
	or 	$aix 
	or 	$aiy 
	or 	$aiz 
	or 	$aja 
	or 	$ajb 
	or 	$ajc 
	or 	$ajd 
	or 	$aje  ) 
}

rule capa_check_for_windows_sandbox_via_registry { 
  meta: 
 	description = "check for windows sandbox via registry (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "@_re_fox"
	scope = "function"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LloydLabs/wsb-detect"
	hash = "773290480d5445f11d3dc1b800728966"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-windows-sandbox-via-registry.yml"
	date = "2021-05-15"

  strings: 
 	$api_ajf = "RegOpenKeyEx" ascii wide
	$api_ajg = "RegEnumValue" ascii wide
	$ajh = /\\Microsoft\\Windows\\CurrentVersion\\RunOnce/ ascii wide 
	$aji = /wmic useraccount where \"name='WDAGUtilityAccount'\"/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_ajf 
	and 	$api_ajg 
	and 	$ajh 
	and 	$aji  ) 
}

rule capa_reference_anti_VM_strings_targeting_Xen { 
  meta: 
 	description = "reference anti-VM strings targeting Xen (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Xen.cpp"
	hash = "al-khaser_x86.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-xen.yml"
	date = "2021-05-15"

  strings: 
 	$ajj = /\bXen/ nocase ascii wide 
	$ajk = /XenVMMXenVMM/ nocase ascii wide 
	$ajl = /xenservice.exe/ nocase ascii wide 
	$ajm = /XenVMMXenVMM/ nocase ascii wide 
	$ajn = /HVM domU/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$ajj 
	or 	$ajk 
	or 	$ajl 
	or 	$ajm 
	or 	$ajn  ) 
}

rule capa_reference_anti_VM_strings { 
  meta: 
 	description = "reference anti-VM strings (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/ctxis/CAPE/blob/master/modules/signatures/antivm_*"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Generic.cpp"
	hash = "Practical Malware Analysis Lab 17-02.dll_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings.yml"
	date = "2021-05-15"

  strings: 
 	$ajo = /HARDWARE\\ACPI\\(DSDT|FADT|RSDT)\\BOCHS/ nocase ascii wide 
	$ajp = /HARDWARE\\DESCRIPTION\\System\\(SystemBiosVersion|VideoBiosVersion)/ nocase ascii wide 
	$ajq = /HARDWARE\\DESCRIPTION\\System\\CentralProcessor/ nocase ascii wide 
	$ajr = /HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0/ nocase ascii wide 
	$ajs = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Enum\\IDE/ nocase ascii wide 
	$ajt = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Services\\Disk\\Enum\\/ nocase ascii wide 
	$aju = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Control\\SystemInformation\\SystemManufacturer/ nocase ascii wide 
	$ajv = /A M I/ nocase ascii wide 
	$ajw = /Hyper-V/ nocase ascii wide 
	$ajx = /Kernel-VMDetection-Private/ nocase ascii wide 
	$ajy = /KVMKVMKVM/ nocase ascii wide 
	$ajz = /Microsoft Hv/ nocase ascii wide 
	$aka = /avghookx.dll/ nocase ascii wide 
	$akb = /avghooka.dll/ nocase ascii wide 
	$akc = /snxhk.dll/ nocase ascii wide 
	$akd = /pstorec.dll/ nocase ascii wide 
	$ake = /vmcheck.dll/ nocase ascii wide 
	$akf = /wpespy.dll/ nocase ascii wide 
	$akg = /cmdvrt64.dll/ nocase ascii wide 
	$akh = /cmdvrt32.dll/ nocase ascii wide 
	$aki = /sample.exe/ nocase ascii wide 
	$akj = /bot.exe/ nocase ascii wide 
	$akk = /sandbox.exe/ nocase ascii wide 
	$akl = /malware.exe/ nocase ascii wide 
	$akm = /test.exe/ nocase ascii wide 
	$akn = /klavme.exe/ nocase ascii wide 
	$ako = /myapp.exe/ nocase ascii wide 
	$akp = /testapp.exe/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$ajo 
	or 	$ajp 
	or 	$ajq 
	or 	$ajr 
	or 	$ajs 
	or 	$ajt 
	or 	$aju 
	or 	$ajv 
	or 	$ajw 
	or 	$ajx 
	or 	$ajy 
	or 	$ajz 
	or 	$aka 
	or 	$akb 
	or 	$akc 
	or 	$akd 
	or 	$ake 
	or 	$akf 
	or 	$akg 
	or 	$akh 
	or 	$aki 
	or 	$akj 
	or 	$akk 
	or 	$akl 
	or 	$akm 
	or 	$akn 
	or 	$ako 
	or 	$akp  ) 
}

rule capa_reference_anti_VM_strings_targeting_Qemu { 
  meta: 
 	description = "reference anti-VM strings targeting Qemu (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Qemu.cpp"
	hash = "al-khaser_x86.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-qemu.yml"
	date = "2021-05-15"

  strings: 
 	$akq = /Qemu/ nocase ascii wide 
	$akr = /qemu-ga.exe/ nocase ascii wide 
	$aks = /BOCHS/ nocase ascii wide 
	$akt = /BXPC/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$akq 
	or 	$akr 
	or 	$aks 
	or 	$akt  ) 
}

rule capa_reference_anti_VM_strings_targeting_VirtualPC { 
  meta: 
 	description = "reference anti-VM strings targeting VirtualPC (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/VirtualPC.cpp"
	hash = "al-khaser_x86.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-virtualpc.yml"
	date = "2021-05-15"

  strings: 
 	$aku = /VirtualPC/ nocase ascii wide 
	$akv = /VMSrvc.exe/ nocase ascii wide 
	$akw = /VMUSrvc.exe/ nocase ascii wide 
	$akx = /SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aku 
	or 	$akv 
	or 	$akw 
	or 	$akx  ) 
}

rule capa_check_if_process_is_running_under_wine { 
  meta: 
 	description = "check if process is running under wine (converted from capa rule)"
	namespace = "anti-analysis/anti-emulation/wine"
	author = "@_re_fox"
	scope = "function"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Emulator Detection [B0004]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Wine.cpp"
	hash = "ccbf7cba35bab56563c0fbe4237fdc41"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-emulation/wine/check-if-process-is-running-under-wine.yml"
	date = "2021-05-15"

  strings: 
 	$aky = /SOFTWARE\\Wine/ nocase ascii wide 
	$api_akz = "GetModuleHandle" ascii wide
	$api_ala = "GetProcAddress" ascii wide
	$str_alb = "wine_get_unix_file_name" ascii wide
	$str_alc = "kernel32.dll" ascii wide
	$str_ald = "ntdll.dll" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aky 
	or  (  ( 	$api_akz 
	and 	$api_ala 
	and 	$str_alb 
	and  (  ( 	$str_alc 
	or 	$str_ald  )  )  )  )  ) 
}

rule capa_check_for_debugger_via_API { 
  meta: 
 	description = "check for debugger via API (converted from capa rule)"
	namespace = "anti-analysis/anti-debugging/debugger-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Anti-Behavioral Analysis::Debugger Detection::CheckRemoteDebuggerPresent [B0001.002]"
	mbc = "Anti-Behavioral Analysis::Debugger Detection::WudfIsAnyDebuggerPresent [B0001.031]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/CheckRemoteDebuggerPresent.cpp"
	hash = "al-khaser_x86.exe_:0x420000"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-debugging/debugger-detection/check-for-debugger-via-api.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /CheckRemoteDebuggerPresent/) 
	or 	pe.imports(/wudfplatform/i, /WudfIsAnyDebuggerPresent/) 
	or 	pe.imports(/wudfplatform/i, /WudfIsKernelDebuggerPresent/) 
	or 	pe.imports(/wudfplatform/i, /WudfIsUserDebuggerPresent/)  ) 
}

rule capa_check_for_OutputDebugString_error { 
  meta: 
 	description = "check for OutputDebugString error (converted from capa rule)"
	namespace = "anti-analysis/anti-debugging/debugger-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	mbc = "Anti-Behavioral Analysis::Debugger Detection::OutputDebugString [B0001.016]"
	hash = "Practical Malware Analysis Lab 16-02.exe_:0x401020"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-debugging/debugger-detection/check-for-outputdebugstring-error.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /SetLastError/) 
	and 	pe.imports(/kernel32/i, /GetLastError/) 
	and 	pe.imports(/kernel32/i, /OutputDebugString/)  ) 
}

rule capa_contains_PDB_path { 
  meta: 
 	description = "contains PDB path (converted from capa rule)"
	namespace = "executable/pe/pdb"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	hash = "464EF2CA59782CE697BC329713698CCC"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/executable/pe/pdb/contains-pdb-path.yml"
	date = "2021-05-15"

  strings: 
 	$alf = /:\\.{,1000}\.pdb/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
	$alf 
}

rule capa_contain_a_resource___rsrc__section { 
  meta: 
 	description = "contain a resource (.rsrc) section (converted from capa rule)"
	namespace = "executable/pe/section/rsrc"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	hash = "A933A1A402775CFA94B6BEE0963F4B46"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/executable/pe/section/rsrc/contain-a-resource-rsrc-section.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
	for any alg in pe.sections : ( alg.name == ".rsrc" ) 
}

rule capa_contain_a_thread_local_storage___tls__section { 
  meta: 
 	description = "contain a thread local storage (.tls) section (converted from capa rule)"
	namespace = "executable/pe/section/tls"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	hash = "Practical Malware Analysis Lab 16-02.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/executable/pe/section/tls/contain-a-thread-local-storage-tls-section.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
	for any alh in pe.sections : ( alh.name == ".tls" ) 
}

rule capa_extract_resource_via_kernel32_functions { 
  meta: 
 	description = "extract resource via kernel32 functions (converted from capa rule)"
	namespace = "executable/resource"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	hash = "BF88E1BD4A3BDE10B419A622278F1FF7"
	hash = "Practical Malware Analysis Lab 01-04.exe_:0x4011FC"
	hash = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/executable/resource/extract-resource-via-kernel32-functions.yml"
	date = "2021-05-15"

  strings: 
 	$api_ali = "LdrAccessResource" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  (  (  ( 	pe.imports(/kernel32/i, /LoadResource/) 
	or 	pe.imports(/kernel32/i, /LockResource/) 
	or 	$api_ali  )  )  )  ) 
	or 	pe.imports(/user32/i, /LoadString/)  ) 
}

rule capa_packaged_as_an_IExpress_self_extracting_archive { 
  meta: 
 	description = "packaged as an IExpress self-extracting archive (converted from capa rule)"
	namespace = "executable/installer/iexpress"
	author = "@recvfrom"
	scope = "file"
	references = "https://en.wikipedia.org/wiki/IExpress"
	hash = "ac742739cae0d411dfcb78ae99a7baee"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/executable/installer/iexpress/packaged-as-an-iexpress-self-extracting-archive.yml"
	date = "2021-05-15"

  strings: 
 	$str_alj = "wextract_cleanup%d" ascii wide
	$str_alk = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
	$str_all = "  <description>IExpress extraction tool</description>" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_alj 
	and 	$str_alk  )  ) 
	or 	$str_all  ) 
}

rule capa_create_thread { 
  meta: 
 	description = "create thread (converted from capa rule)"
	namespace = "host-interaction/thread/create"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	mbc = "Process::Create Thread [C0038]"
	hash = "946A99F36A46D335DEC080D9A4371940"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/thread/create/create-thread.yml"
	date = "2021-05-15"

  strings: 
 	$api_alm = "_beginthread" ascii wide
	$api_aln = "_beginthreadex" ascii wide
	$api_alo = "PsCreateSystemThread" ascii wide
	$api_alp = "SHCreateThread" ascii wide
	$api_alq = "SHCreateThreadWithHandle" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /CreateThread/) 
	or 	$api_alm 
	or 	$api_aln 
	or 	$api_alo 
	or 	$api_alp 
	or 	$api_alq 
	or 	pe.imports(/kernel32/i, /CreateRemoteThread/) 
	or 	pe.imports(/kernel32/i, /CreateRemoteThreadEx/) 
	or 	pe.imports(/ntdll/i, /RtlCreateUserThread/) 
	or 	pe.imports(/ntdll/i, /NtCreateThread/) 
	or 	pe.imports(/ntdll/i, /NtCreateThreadEx/) 
	or 	pe.imports(/ntdll/i, /ZwCreateThread/) 
	or 	pe.imports(/ntdll/i, /ZwCreateThreadEx/)  ) 
}

rule capa_resume_thread { 
  meta: 
 	description = "resume thread (converted from capa rule)"
	namespace = "host-interaction/thread/resume"
	author = "0x534a@mailbox.org"
	scope = "basic block"
	mbc = "Process::Resume Thread [C0054]"
	hash = "Practical Malware Analysis Lab 12-02.exe_:0x4010EA"
	hash = "787cbc8a6d1bc58ea169e51e1ad029a637f22560660cc129ab8a099a745bd50e"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/thread/resume/resume-thread.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /ResumeThread/) 
	or 	pe.imports(/ntdll/i, /NtResumeThread/) 
	or 	pe.imports(/ntdll/i, /ZwResumeThread/)  ) 
}

rule capa_suspend_thread { 
  meta: 
 	description = "suspend thread (converted from capa rule)"
	namespace = "host-interaction/thread/suspend"
	author = "0x534a@mailbox.org"
	scope = "basic block"
	mbc = "Process::Suspend Thread [C0055]"
	hash = "787cbc8a6d1bc58ea169e51e1ad029a637f22560660cc129ab8a099a745bd50e"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/thread/suspend/suspend-thread.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /SuspendThread/) 
	or 	pe.imports(/ntdll/i, /NtSuspendThread/) 
	or 	pe.imports(/ntdll/i, /ZwSuspendThread/)  ) 
}

rule capa_terminate_thread { 
  meta: 
 	description = "terminate thread (converted from capa rule)"
	namespace = "host-interaction/thread/terminate"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	mbc = "Process::Terminate Thread [C0039]"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x10003286"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/thread/terminate/terminate-thread.yml"
	date = "2021-05-15"

  strings: 
 	$api_alr = "PsTerminateSystemThread" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /TerminateThread/) 
	or 	$api_alr  ) 
}

rule capa_manipulate_console { 
  meta: 
 	description = "manipulate console (converted from capa rule)"
	namespace = "host-interaction/console"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	mbc = "Operating System::Console [C0033]"
	references = "https://stackoverflow.com/a/15770935/87207"
	hash = "3aa7ee4d67f562933bc998f352b1f319"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/console/manipulate-console.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/kernel32/i, /SetConsoleCursorPosition/) 
	or 	pe.imports(/kernel32/i, /ReadConsoleOutputCharacter/) 
	or 	pe.imports(/kernel32/i, /WriteConsoleOutputCharacter/) 
	or 	pe.imports(/kernel32/i, /WriteConsoleOutput/) 
	or 	pe.imports(/kernel32/i, /WriteConsoleInput/)  )  )  ) 
}

rule capa_access_firewall_settings_via_INetFwMgr { 
  meta: 
 	description = "access firewall settings via INetFwMgr (converted from capa rule)"
	namespace = "host-interaction/firewall/modify"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::Software Discovery::Security Software Discovery [T1518.001]"
	attack = "Defense Evasion::Impair Defenses::Disable or Modify System Firewall [T1562.004]"
	hash = "EB355BD63BDDCE02955792B4CD6539FB"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/firewall/modify/access-firewall-settings-via-inetfwmgr.yml"
	date = "2021-05-15"

  strings: 
 	$als = { 42 E9 4C 30 39 6E D8 40 94 3A B9 13 C4 0C 9C D4 }
	$alt = { F5 8A 89 F7 C4 CA 32 46 A2 EC DA 06 E5 11 1A F2 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ole32/i, /CoCreateInstance/) 
	and 	$als 
	and 	$alt  ) 
}

rule capa_start_minifilter_driver { 
  meta: 
 	description = "start minifilter driver (converted from capa rule)"
	namespace = "host-interaction/filter"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	references = "https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/filter/start-minifilter-driver.yml"
	date = "2021-05-15"

  strings: 
 	$api_alu = "FltStartFiltering" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_alu  ) 
}

rule capa_register_minifilter_driver { 
  meta: 
 	description = "register minifilter driver (converted from capa rule)"
	namespace = "host-interaction/filter"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	references = "https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/filter/register-minifilter-driver.yml"
	date = "2021-05-15"

  strings: 
 	$api_alv = "FltRegisterFilter" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_alv  ) 
}

rule capa_get_common_file_path { 
  meta: 
 	description = "get common file path (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::File and Directory Discovery [T1083]"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x10003415"
	hash = "972B219F18379907A045431303F4DA7D"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/get-common-file-path.yml"
	date = "2021-05-15"

  strings: 
 	$api_alw = "GetAllUsersProfileDirectory" ascii wide
	$api_alx = "GetAppContainerFolderPath" ascii wide
	$api_aly = "GetCurrentDirectory" ascii wide
	$api_alz = "GetDefaultUserProfileDirectory" ascii wide
	$api_ama = "GetProfilesDirectory" ascii wide
	$api_amb = "GetUserProfileDirectory" ascii wide
	$api_amc = "SHGetFolderPathAndSubDir" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /GetTempPath/) 
	or 	pe.imports(/kernel32/i, /GetTempFileName/) 
	or 	pe.imports(/kernel32/i, /GetSystemDirectory/) 
	or 	pe.imports(/kernel32/i, /GetWindowsDirectory/) 
	or 	pe.imports(/kernel32/i, /GetSystemWow64Directory/) 
	or 	$api_alw 
	or 	$api_alx 
	or 	$api_aly 
	or 	$api_alz 
	or 	$api_ama 
	or 	$api_amb 
	or 	$api_amc 
	or 	pe.imports(/shell32/i, /SHGetFolderPath/) 
	or 	pe.imports(/shell32/i, /SHGetFolderLocation/) 
	or 	pe.imports(/shell32/i, /SHGetSpecialFolderPath/) 
	or 	pe.imports(/shell32/i, /SHGetSpecialFolderLocation/)  ) 
}

rule capa_bypass_Mark_of_the_Web { 
  meta: 
 	description = "bypass Mark of the Web (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Subvert Trust Controls::Mark-of-the-Web Bypass [T1553.005]"
	hash = "48c7ad2d9d482cb11898f2719638ceed"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/bypass-mark-of-the-web.yml"
	date = "2021-05-15"

  strings: 
 	$api_amd = "DeleteFile" ascii wide
	$str_ame = ":Zone.Identifier" ascii wide
	$str_amf = "%s:Zone.Identifier" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_amd 
	and  (  ( 	$str_ame 
	or 	$str_amf  )  )  ) 
}

rule capa_get_file_system_object_information { 
  meta: 
 	description = "get file system object information (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	attack = "Discovery::File and Directory Discovery [T1083]"
	hash = "50D5EE1CE2CA5E30C6B1019EE64EEEC2"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/get-file-system-object-information.yml"
	date = "2021-05-15"

  strings: 
 	$api_amg = "SHGetFileInfo" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_amg  ) 
}

rule capa_delete_directory { 
  meta: 
 	description = "delete directory (converted from capa rule)"
	namespace = "host-interaction/file-system/delete"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "File System::Delete Directory [C0048]"
	hash = "Practical Malware Analysis Lab 05-01.dll_:0x10009236"
	hash = "AFB6EC3D721A5CB67863487B0E51A34C167F629CF701F8BC7A038C117B4DDA44"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/delete/delete-directory.yml"
	date = "2021-05-15"

  strings: 
 	$api_amm = "RemoveDirectory" ascii wide
	$api_amn = "RemoveDirectoryTransacted" ascii wide
	$api_amo = "_rmdir" ascii wide
	$api_amp = "_wrmdir" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_amm 
	or 	$api_amn 
	or 	$api_amo 
	or 	$api_amp  ) 
}

rule capa_create_directory { 
  meta: 
 	description = "create directory (converted from capa rule)"
	namespace = "host-interaction/file-system/create"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "File System::Create Directory [C0046]"
	hash = "Practical Malware Analysis Lab 17-02.dll_:0x10008f62"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/create/create-directory.yml"
	date = "2021-05-15"

  strings: 
 	$api_amq = "NtCreateDirectoryObject" ascii wide
	$api_amr = "ZwCreateDirectoryObject" ascii wide
	$api_ams = "SHCreateDirectory" ascii wide
	$api_amt = "SHCreateDirectoryEx" ascii wide
	$api_amu = "_mkdir" ascii wide
	$api_amv = "_wmkdir" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /CreateDirectory/) 
	or 	pe.imports(/kernel32/i, /CreateDirectoryEx/) 
	or 	pe.imports(/kernel32/i, /CreateDirectoryTransacted/) 
	or 	$api_amq 
	or 	$api_amr 
	or 	$api_ams 
	or 	$api_amt 
	or 	$api_amu 
	or 	$api_amv  ) 
}

rule capa_write_file { 
  meta: 
 	description = "write file (converted from capa rule)"
	namespace = "host-interaction/file-system/write"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	mbc = "File System::Writes File [C0052]"
	hash = "Practical Malware Analysis Lab 01-04.exe_:0x4011FC"
	hash = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/write/write-file.yml"
	date = "2021-05-15"

  strings: 
 	$api_amw = "NtWriteFile" ascii wide
	$api_amx = "ZwWriteFile" ascii wide
	$api_amy = "_fwrite" ascii wide
	$api_amz = "fwrite" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/kernel32/i, /WriteFile/) 
	or 	pe.imports(/kernel32/i, /WriteFileEx/) 
	or 	$api_amw 
	or 	$api_amx 
	or 	$api_amy 
	or 	$api_amz  )  )  ) 
}

rule capa_get_file_attributes { 
  meta: 
 	description = "get file attributes (converted from capa rule)"
	namespace = "host-interaction/file-system/meta"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	mbc = "File System::Get File Attributes [C0049]"
	hash = "03B236B23B1EC37C663527C1F53AF3FE"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/meta/get-file-attributes.yml"
	date = "2021-05-15"

  strings: 
 	$api_ana = "ZwQueryDirectoryFile" ascii wide
	$api_anb = "ZwQueryInformationFile" ascii wide
	$api_anc = "NtQueryDirectoryFile" ascii wide
	$api_and = "NtQueryInformationFile" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /GetFileAttributes/) 
	or 	$api_ana 
	or 	$api_anb 
	or 	$api_anc 
	or 	$api_and  ) 
}

rule capa_set_file_attributes { 
  meta: 
 	description = "set file attributes (converted from capa rule)"
	namespace = "host-interaction/file-system/meta"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	attack = "Defense Evasion::File and Directory Permissions Modification [T1222]"
	mbc = "File System::Set File Attributes [C0050]"
	hash = "946A99F36A46D335DEC080D9A4371940"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/meta/set-file-attributes.yml"
	date = "2021-05-15"

  strings: 
 	$api_ane = "ZwSetInformationFile" ascii wide
	$api_anf = "NtSetInformationFile" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /SetFileAttributes/) 
	or 	$api_ane 
	or 	$api_anf  ) 
}

rule capa_read_virtual_disk { 
  meta: 
 	description = "read virtual disk (converted from capa rule)"
	namespace = "host-interaction/file-system/read"
	author = "@_re_fox"
	scope = "function"
	mbc = "File System::Read Virtual Disk [C0056]"
	references = "https://github.com/vxunderground/VXUG-Papers/blob/main/Weaponizing%20Windows%20Virtualization/src.cpp"
	references = "https://github.com/vxunderground/VXUG-Papers/blob/main/Weaponizing%20Windows%20Virtualization/WeaponizingWindowsVirtualization.pdf"
	hash = "3265b2b0afc6d2ad0bdd55af8edb9b37"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/read/read-virtual-disk.yml"
	date = "2021-05-15"

  strings: 
 	$api_anh = "OpenVirtualDisk" ascii wide
	$api_ani = "AttachVirtualDisk" ascii wide
	$api_anj = "GetVirtualDiskPhysicalPath" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_anh 
	and 	$api_ani 
	and 	$api_anj  ) 
}

rule capa_read_file { 
  meta: 
 	description = "read file (converted from capa rule)"
	namespace = "host-interaction/file-system/read"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "File System::Read File [C0051]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/read/read-file.yml"
	date = "2021-05-15"

  strings: 
 	$api_ank = "ReadFileEx" ascii wide
	$api_anl = "NtReadFile" ascii wide
	$api_anm = "ZwReadFile" ascii wide
	$api_ann = "_read" ascii wide
	$api_ano = "fread" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  (  (  ( 	pe.imports(/kernel32/i, /ReadFile/) 
	or 	$api_ank 
	or 	$api_anl 
	or 	$api_anm 
	or 	$api_ann 
	or 	$api_ano  )  )  )  )  ) 
}

rule capa_read__ini_file { 
  meta: 
 	description = "read .ini file (converted from capa rule)"
	namespace = "host-interaction/file-system/read"
	author = "@_re_fox"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "File System::Read File [C0051]"
	hash = "1d8fd13c890060464019c0f07b928b1a"
	hash = "E6234FB98F17201C232F4502015B47B3"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/read/read-ini-file.yml"
	date = "2021-05-15"

  strings: 
 	$api_anp = "GetPrivateProfileInt" ascii wide
	$api_anq = "GetPrivateProfileString" ascii wide
	$api_anr = "GetPrivateProfileStruct" ascii wide
	$api_ans = "GetPrivateProfileSection" ascii wide
	$api_ant = "GetPrivateProfileSectionNames" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$api_anp 
	or 	$api_anq 
	or 	$api_anr 
	or 	$api_ans 
	or 	$api_ant  )  )  ) 
}

rule capa_enumerate_files_via_kernel32_functions { 
  meta: 
 	description = "enumerate files via kernel32 functions (converted from capa rule)"
	namespace = "host-interaction/file-system/files/list"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::File and Directory Discovery [T1083]"
	hash = "Practical Malware Analysis Lab 01-01.exe_:0x4011E0"
	hash = "Practical Malware Analysis Lab 20-02.exe_:0x401000"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/files/list/enumerate-files-via-kernel32-functions.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/kernel32/i, /FindFirstFile/) 
	or 	pe.imports(/kernel32/i, /FindFirstFileEx/) 
	or 	pe.imports(/kernel32/i, /FindFirstFileTransacted/) 
	or 	pe.imports(/kernel32/i, /FindFirstFileName/) 
	or 	pe.imports(/kernel32/i, /FindFirstFileNameTransacted/)  )  ) 
	and  (  ( 	pe.imports(/kernel32/i, /FindNextFile/) 
	or 	pe.imports(/kernel32/i, /FindNextFileName/)  )  )  ) 
}

rule capa_shutdown_system { 
  meta: 
 	description = "shutdown system (converted from capa rule)"
	namespace = "host-interaction/os"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Impact::System Shutdown/Reboot [T1529]"
	hash = "39C05B15E9834AC93F206BC114D0A00C357C888DB567BA8F5345DA0529CBED41"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/os/shutdown-system.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/user32/i, /ExitWindowsEx/) 
	or 	pe.imports(/user32/i, /ExitWindows/)  ) 
}

rule capa_get_system_information { 
  meta: 
 	description = "get system information (converted from capa rule)"
	namespace = "host-interaction/os/info"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/os/info/get-system-information.yml"
	date = "2021-05-15"

  strings: 
 	$api_anw = "NtQuerySystemInformation" ascii wide
	$api_anx = "NtQuerySystemInformationEx" ascii wide
	$api_any = "ZwQuerySystemInformation" ascii wide
	$api_anz = "ZwQuerySystemInformationEx" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /GetSystemInfo/) 
	or 	pe.imports(/kernel32/i, /GetNativeSystemInfo/) 
	or 	$api_anw 
	or 	$api_anx 
	or 	pe.imports(/ntdll/i, /RtlGetNativeSystemInformation/) 
	or 	$api_any 
	or 	$api_anz  ) 
}

rule capa_get_hostname { 
  meta: 
 	description = "get hostname (converted from capa rule)"
	namespace = "host-interaction/os/hostname"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/os/hostname/get-hostname.yml"
	date = "2021-05-15"

  strings: 
 	$api_aof = "GetComputerObjectName" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /GetComputerName/) 
	or 	pe.imports(/kernel32/i, /GetComputerNameEx/) 
	or 	$api_aof 
	or 	pe.imports(/ws2_32/i, /gethostname/)  ) 
}

rule capa_query_service_status { 
  meta: 
 	description = "query service status (converted from capa rule)"
	namespace = "host-interaction/service"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Service Discovery [T1007]"
	hash = "9DC209F66DA77858E362E624D0BE86B3"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/service/query-service-status.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /QueryServiceStatusEx/) 
	or 	pe.imports(/advapi32/i, /QueryServiceStatus/)  ) 
}

rule capa_delete_service { 
  meta: 
 	description = "delete service (converted from capa rule)"
	namespace = "host-interaction/service/delete"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Persistence::Create or Modify System Process::Windows Service [T1543.003]"
	hash = "E544A4D616B60147D9774B48C2B65EF2"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x10004B18"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/service/delete/delete-service.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /DeleteService/)  ) 
}

rule capa_enumerate_services { 
  meta: 
 	description = "enumerate services (converted from capa rule)"
	namespace = "host-interaction/service/list"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Service Discovery [T1007]"
	hash = "Practical Malware Analysis Lab 05-01.dll_:0x1000B823"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/service/list/enumerate-services.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /EnumServicesStatus/) 
	or 	pe.imports(/advapi32/i, /EnumServicesStatusEx/)  ) 
}

rule capa_create_service { 
  meta: 
 	description = "create service (converted from capa rule)"
	namespace = "host-interaction/service/create"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Persistence::Create or Modify System Process::Windows Service [T1543.003]"
	attack = "Execution::System Services::Service Execution [T1569.002]"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x10004706"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/service/create/create-service.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /CreateService/)  ) 
}

rule capa_modify_service { 
  meta: 
 	description = "modify service (converted from capa rule)"
	namespace = "host-interaction/service/modify"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Persistence::Create or Modify System Process::Windows Service [T1543.003]"
	attack = "Execution::System Services::Service Execution [T1569.002]"
	hash = "7D16EFD0078F22C17A4BD78B0F0CC468"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/service/modify/modify-service.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/advapi32/i, /ChangeServiceConfig/) 
	or 	pe.imports(/advapi32/i, /ChangeServiceConfig2/)  )  )  ) 
}

rule capa_start_service { 
  meta: 
 	description = "start service (converted from capa rule)"
	namespace = "host-interaction/service/start"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Persistence::Create or Modify System Process::Windows Service [T1543.003]"
	hash = "E544A4D616B60147D9774B48C2B65EF2"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/service/start/start-service.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /StartService/)  ) 
}

rule capa_get_number_of_processor_cores { 
  meta: 
 	description = "get number of processor cores (converted from capa rule)"
	namespace = "host-interaction/hardware/cpu"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Generic.cpp#L207"
	hash = "al-khaser_x86.exe_:0x435BA0"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/cpu/get-number-of-processor-cores.yml"
	date = "2021-05-15"

  strings: 
 	$aog = /SELECT\s+\*\s+FROM\s+Win32_Processor/ ascii wide 
	$str_aoh = "NumberOfCores" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aog 
	and 	$str_aoh  ) 
}

rule capa_get_disk_information { 
  meta: 
 	description = "get disk information (converted from capa rule)"
	namespace = "host-interaction/hardware/storage"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	hash = "972B219F18379907A045431303F4DA7D"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/storage/get-disk-information.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /GetDriveType/) 
	or 	pe.imports(/kernel32/i, /GetLogicalDrives/) 
	or 	pe.imports(/kernel32/i, /GetVolumeInformation/) 
	or 	pe.imports(/kernel32/i, /GetVolumeNameForVolumeMountPoint/) 
	or 	pe.imports(/kernel32/i, /GetVolumePathNamesForVolumeName/) 
	or 	pe.imports(/kernel32/i, /GetLogicalDriveStrings/) 
	or 	pe.imports(/kernel32/i, /QueryDosDevice/)  ) 
}

rule capa_manipulate_CD_ROM_drive { 
  meta: 
 	description = "manipulate CD-ROM drive (converted from capa rule)"
	namespace = "host-interaction/hardware/cdrom"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Impact::Modify Hardware::CDROM [B0042.001]"
	hash = "39C05B15E9834AC93F206BC114D0A00C357C888DB567BA8F5345DA0529CBED41"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/cdrom/manipulate-cd-rom-drive.yml"
	date = "2021-05-15"

  strings: 
 	$str_aoi = "set cdaudio door closed wait" ascii wide
	$str_aoj = "set cdaudio door open" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/winmm/i, /mciSendString/) 
	and  (  ( 	$str_aoi 
	or 	$str_aoj  )  )  ) 
}

rule capa_get_memory_capacity { 
  meta: 
 	description = "get memory capacity (converted from capa rule)"
	namespace = "host-interaction/hardware/memory"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/memory/get-memory-capacity.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /GlobalMemoryStatus/) 
	or 	pe.imports(/kernel32/i, /GlobalMemoryStatusEx/)  ) 
}

rule capa_swap_mouse_buttons { 
  meta: 
 	description = "swap mouse buttons (converted from capa rule)"
	namespace = "host-interaction/hardware/mouse"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Impact::Modify Hardware::Mouse [B0042.002]"
	hash = "B7841B9D5DC1F511A93CC7576672EC0C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/mouse/swap-mouse-buttons.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/user32/i, /SwapMouseButton/)  ) 
}

rule capa_get_keyboard_layout { 
  meta: 
 	description = "get keyboard layout (converted from capa rule)"
	namespace = "host-interaction/hardware/keyboard/layout"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "6F99A2C8944CB02FF28C6F9CED59B161"
	hash = "C91887D861D9BD4A5872249B641BC9F9"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/keyboard/layout/get-keyboard-layout.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/user32/i, /GetKeyboardLayoutList/) 
	or 	pe.imports(/user32/i, /GetKeyboardLayout/) 
	or 	pe.imports(/user32/i, /GetKeyboardLayoutName/)  )  )  ) 
}

rule capa_open_clipboard { 
  meta: 
 	description = "open clipboard (converted from capa rule)"
	namespace = "host-interaction/clipboard"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Collection::Clipboard Data [T1115]"
	hash = "6f99a2c8944cb02ff28c6f9ced59b161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/clipboard/open-clipboard.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/user32/i, /OpenClipboard/)  ) 
}

rule capa_write_clipboard_data { 
  meta: 
 	description = "write clipboard data (converted from capa rule)"
	namespace = "host-interaction/clipboard"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Impact::Clipboard Modification [E1510]"
	hash = "6F99A2C8944CB02FF28C6F9CED59B161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/clipboard/write-clipboard-data.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/user32/i, /SetClipboardData/)  ) 
}

rule capa_read_clipboard_data { 
  meta: 
 	description = "read clipboard data (converted from capa rule)"
	namespace = "host-interaction/clipboard"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Collection::Clipboard Data [T1115]"
	hash = "C91887D861D9BD4A5872249B641BC9F9"
	hash = "93dfc146f60bd796eb28d4e4f348f2e4"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/clipboard/read-clipboard-data.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/user32/i, /GetClipboardData/)  ) 
}

rule capa_replace_clipboard_data { 
  meta: 
 	description = "replace clipboard data (converted from capa rule)"
	namespace = "host-interaction/clipboard"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Impact::Clipboard Modification [E1510]"
	hash = "6f99a2c8944cb02ff28c6f9ced59b161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/clipboard/replace-clipboard-data.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_write_clipboard_data

	and 	pe.imports(/user32/i, /EmptyClipboard/)  ) 
}

rule capa_install_driver { 
  meta: 
 	description = "install driver (converted from capa rule)"
	namespace = "host-interaction/driver"
	author = "moritz.raabe@fireeye.com"
	scope = "basic block"
	attack = "Persistence::Create or Modify System Process::Windows Service [T1543.003]"
	mbc = "Hardware::Install Driver [C0037]"
	hash = "af60700383b75727f5256a0000c1476f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/driver/install-driver.yml"
	date = "2021-05-15"

  strings: 
 	$api_aok = "ZwLoadDriver" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ntdll/i, /NtLoadDriver/) 
	or 	$api_aok  ) 
}

rule capa_disable_driver_code_integrity { 
  meta: 
 	description = "disable driver code integrity (converted from capa rule)"
	namespace = "host-interaction/driver"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.fuzzysecurity.com/tutorials/28.html"
	references = "https://j00ru.vexillium.org/2010/06/insight-into-the-driver-signature-enforcement/"
	hash = "31CEE4F66CF3B537E3D2D37A71F339F4"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/driver/disable-driver-code-integrity.yml"
	date = "2021-05-15"

  strings: 
 	$str_aol = "CiInitialize" ascii wide
	$aom = /g_CiEnabled/ ascii wide 
	$aon = /g_CiOptions/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_aol 
	or 	$aom 
	or 	$aon  )  )  ) 
}

rule capa_interact_with_driver_via_control_codes { 
  meta: 
 	description = "interact with driver via control codes (converted from capa rule)"
	namespace = "host-interaction/driver"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Execution::System Services::Service Execution [T1569.002]"
	hash = "Practical Malware Analysis Lab 10-03.exe_:0x401000"
	hash = "9412A66BC81F51A1FA916AC47C77E02AC1A7C9DFF543233ED70AA265EF6A1E76"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/driver/interact-with-driver-via-control-codes.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  strings: 
 	$api_aoo = "DeviceIoControl" ascii wide
	$api_aop = "NtUnloadDriver" ascii wide
	$api_aoq = "ZwUnloadDriver" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_aoo 
	or 	$api_aop 
	or 	$api_aoq 
  ) 
}

rule capa_manipulate_boot_configuration { 
  meta: 
 	description = "manipulate boot configuration (converted from capa rule)"
	namespace = "host-interaction/bootloader"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdedit-command-line-options"
	hash = "7FBC17A09CF5320C515FC1C5BA42C8B3"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/bootloader/manipulate-boot-configuration.yml"
	date = "2021-05-15"

  strings: 
 	$aor = /bcdedit.exe/ nocase ascii wide 
	$aos = /boot.ini/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$aor  )  ) 
	or  (  ( 	$aos  )  )  ) 
}

rule capa_set_application_hook { 
  meta: 
 	description = "set application hook (converted from capa rule)"
	namespace = "host-interaction/gui"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	hash = "Practical Malware Analysis Lab 12-03.exe_:0x401000"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/set-application-hook.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/user32/i, /SetWindowsHookEx/) 
	or 	pe.imports(/user32/i, /UnhookWindowsHookEx/)  )  )  ) 
}

rule capa_enumerate_gui_resources { 
  meta: 
 	description = "enumerate gui resources (converted from capa rule)"
	namespace = "host-interaction/gui"
	author = "johnk3r"
	scope = "function"
	attack = "Discovery::Application Window Discovery [T1010]"
	hash = "5e6764534b3a1e4d3abacc4810b6985d"
	hash = "a74ee8200aace7d19dee79871bbf2ed3"
	hash = "74fa32d2b277f583010b692a3f91b627"
	hash = "021f49678cd633dc8cf99c61b3af3dda"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/enumerate-gui-resources.yml"
	date = "2021-05-15"

  strings: 
 	$api_aot = "EnumResourceTypes" ascii wide
	$api_aou = "EnumWindowStations" ascii wide
	$api_aov = "EnumDesktops" ascii wide
	$api_aow = "EnumWindows" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_aot 
	or 	$api_aou 
	or 	$api_aov 
	or 	$api_aow  ) 
}

rule capa_find_graphical_window { 
  meta: 
 	description = "find graphical window (converted from capa rule)"
	namespace = "host-interaction/gui/window/find"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::Application Window Discovery [T1010]"
	hash = "7C843E75D4F02087B932FE280DF9C90C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/window/find/find-graphical-window.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/user32/i, /FindWindow/) 
	or 	pe.imports(/user32/i, /FindWindowEx/)  ) 
}

rule capa_references_logon_banner { 
  meta: 
 	description = "references logon banner (converted from capa rule)"
	namespace = "host-interaction/gui/logon"
	author = "@_re_fox"
	scope = "basic block"
	hash = "c3341b7dfbb9d43bca8c812e07b4299f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/logon/references-logon-banner.yml"
	date = "2021-05-15"

  strings: 
 	$aoy = /\\Microsoft\\Windows\\CurrentVersion\\Policies\\System/ ascii wide 
	$aoz = /LegalNoticeCaption/ ascii wide 
	$apa = /LegalNoticeText/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aoy 
	and  (  ( 	$aoz 
	or 	$apa  )  )  ) 
}

rule capa_lock_the_desktop { 
  meta: 
 	description = "lock the desktop (converted from capa rule)"
	namespace = "host-interaction/gui/session/lock"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Impact::Endpoint Denial of Service [T1499]"
	hash = "39C05B15E9834AC93F206BC114D0A00C357C888DB567BA8F5345DA0529CBED41"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/session/lock/lock-the-desktop.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
	pe.imports(/user32/i, /LockWorkStation/) 
}

rule capa_resolve_path_using_msvcrt { 
  meta: 
 	description = "resolve path using msvcrt (converted from capa rule)"
	namespace = "host-interaction/cli"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Discovery::File and Directory Discovery [T1083]"
	hash = "31600ad0d1a7ea615690df111ae36c73"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/cli/resolve-path-using-msvcrt.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/msvcrt/i, /__p__pgmptr/) 
	or 	pe.imports(/msvcrt/i, /__p__wpgmptr/) 
	or 	pe.imports(/msvcrt/i, /_get_pgmptr/) 
	or 	pe.imports(/msvcrt/i, /_get_wpgmptr/) 
	or 	pe.imports(/msvcrt/i, /_pgmptr/) 
	or 	pe.imports(/msvcrt/i, /_wpgmptr/)  ) 
}

rule capa_accept_command_line_arguments { 
  meta: 
 	description = "accept command line arguments (converted from capa rule)"
	namespace = "host-interaction/cli"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Execution::Command and Scripting Interpreter [T1059]"
	hash = "Practical Malware Analysis Lab 10-03.exe_:0x401140"
	hash = "AFB6EC3D721A5CB67863487B0E51A34C167F629CF701F8BC7A038C117B4DDA44"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/cli/accept-command-line-arguments.yml"
	date = "2021-05-15"

  strings: 
 	$api_apc = "GetCommandLine" ascii wide
	$api_apd = "CommandLineToArgv" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_apc 
	or 	$api_apd  ) 
}

rule capa_set_thread_local_storage_value { 
  meta: 
 	description = "set thread local storage value (converted from capa rule)"
	namespace = "host-interaction/process"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Process::Set Thread Local Storage Value [C0041]"
	hash = "03B236B23B1EC37C663527C1F53AF3FE"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/set-thread-local-storage-value.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /TlsSetValue/)  ) 
}

rule capa_allocate_thread_local_storage { 
  meta: 
 	description = "allocate thread local storage (converted from capa rule)"
	namespace = "host-interaction/process"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Process::Allocate Thread Local Storage [C0040]"
	hash = "03B236B23B1EC37C663527C1F53AF3FE"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/allocate-thread-local-storage.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /TlsAlloc/)  ) 
}

rule capa_attach_user_process_memory { 
  meta: 
 	description = "attach user process memory (converted from capa rule)"
	namespace = "host-interaction/process/inject"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Process Injection [T1055]"
	hash = "493167E85E45363D09495D0841C30648"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/inject/attach-user-process-memory.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ntoskrnl/i, /KeStackAttachProcess/) 
	and 	pe.imports(/ntoskrnl/i, /KeUnstackDetachProcess/)  ) 
}

rule capa_use_process_doppelganging { 
  meta: 
 	description = "use process doppelganging (converted from capa rule)"
	namespace = "host-interaction/process/inject"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Process Injection::Process Doppelganging [T1055.013]"
	hash = "A5D66324DAAEE5672B913AA461D4BD3A"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/inject/use-process-doppelganging.yml"
	date = "2021-05-15"

  strings: 
 	$ape = /CreateFileTransacted./ ascii wide 
	$str_apf = "ZwCreateSection" ascii wide
	$str_apg = "NtCreateSection" ascii wide
	$str_aph = "RollbackTransaction" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$ape 
	and  (  ( 	$str_apf 
	or 	$str_apg  )  ) 
	and 	$str_aph  ) 
}

rule capa_inject_APC { 
  meta: 
 	description = "inject APC (converted from capa rule)"
	namespace = "host-interaction/process/inject"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Process Injection::Asynchronous Procedure Call [T1055.004]"
	hash = "al-khaser_x64.exe_:0x140019348"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/inject/inject-apc.yml"
	date = "2021-05-15"

  strings: 
 	$api_api = "NtMapViewOfSection" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_write_process_memory

	or 	pe.imports(/kernel32/i, /MapViewOfSection/) 
	or 	$api_api 
	or 	pe.imports(/ntdll/i, /ZwMapViewOfSection/) 
	or 	pe.imports(/kernel32/i, /MapViewOfFile/)  )  ) 
	and  (  ( 	pe.imports(/kernel32/i, /QueueUserAPC/) 
	or 	pe.imports(/ntdll/i, /NtQueueApcThread/)  )  )  ) 
}

rule capa_enumerate_processes { 
  meta: 
 	description = "enumerate processes (converted from capa rule)"
	namespace = "host-interaction/process/list"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::Process Discovery [T1057]"
	attack = "Discovery::Software Discovery [T1518]"
	hash = "2D3EDC218A90F03089CC01715A9F047F"
	hash = "35d04ecd797041eee796f4ddaa96cae8"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/list/enumerate-processes.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /Process32First/) 
	and 	pe.imports(/kernel32/i, /Process32Next/)  ) 
}

rule capa_enumerate_processes_on_remote_desktop_session_host { 
  meta: 
 	description = "enumerate processes on remote desktop session host (converted from capa rule)"
	namespace = "host-interaction/process/list"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::Process Discovery [T1057]"
	hash = "6f99a2c8944cb02ff28c6f9ced59b161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/list/enumerate-processes-on-remote-desktop-session-host.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/wtsapi32/i, /WTSEnumerateProcesses/) 
	or 	pe.imports(/wtsapi32/i, /WTSEnumerateProcessesEx/)  )  )  ) 
}

rule capa_get_Explorer_PID { 
  meta: 
 	description = "get Explorer PID (converted from capa rule)"
	namespace = "host-interaction/process/list"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	attack = "Discovery::Process Discovery [T1057]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/ParentProcess.cpp"
	hash = "al-khaser_x86.exe_:0x425210"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/list/get-explorer-pid.yml"
	date = "2021-05-15"

  strings: 
 	$api_apj = "GetShellWindow" ascii wide
	$api_apk = "GetWindowThreadProcessId" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_apj 
	and 	$api_apk  ) 
}

rule capa_find_process_by_PID { 
  meta: 
 	description = "find process by PID (converted from capa rule)"
	namespace = "host-interaction/process/list"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::Process Discovery [T1057]"
	hash = "493167E85E45363D09495D0841C30648"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/list/find-process-by-pid.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ntoskrnl/i, /PsLookupProcessByProcessId/)  ) 
}

rule capa_create_process { 
  meta: 
 	description = "create process (converted from capa rule)"
	namespace = "host-interaction/process/create"
	author = "moritz.raabe@fireeye.com"
	scope = "basic block"
	mbc = "Process::Create Process [C0017]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	hash = "Practical Malware Analysis Lab 01-04.exe_:0x4011FC"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/create/create-process.yml"
	date = "2021-05-15"

  strings: 
 	$api_apl = "ZwCreateProcessEx" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /WinExec/) 
	or 	pe.imports(/kernel32/i, /CreateProcess/) 
	or 	pe.imports(/shell32/i, /ShellExecute/) 
	or 	pe.imports(/shell32/i, /ShellExecuteEx/) 
	or 	pe.imports(/advapi32/i, /CreateProcessAsUser/) 
	or 	pe.imports(/advapi32/i, /CreateProcessWithLogon/) 
	or 	pe.imports(/advapi32/i, /CreateProcessWithToken/) 
	or 	pe.imports(/kernel32/i, /CreateProcessInternal/) 
	or 	pe.imports(/ntdll/i, /NtCreateUserProcess/) 
	or 	pe.imports(/ntdll/i, /NtCreateProcess/) 
	or 	pe.imports(/ntdll/i, /NtCreateProcessEx/) 
	or 	pe.imports(/ntdll/i, /ZwCreateProcess/) 
	or 	$api_apl 
	or 	pe.imports(/ntdll/i, /ZwCreateUserProcess/) 
	or 	pe.imports(/ntdll/i, /RtlCreateUserProcess/)  ) 
}

rule capa_modify_access_privileges { 
  meta: 
 	description = "modify access privileges (converted from capa rule)"
	namespace = "host-interaction/process/modify"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Privilege Escalation::Access Token Manipulation [T1134]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/modify/modify-access-privileges.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /AdjustTokenPrivileges/)  ) 
}

rule capa_terminate_process { 
  meta: 
 	description = "terminate process (converted from capa rule)"
	namespace = "host-interaction/process/terminate"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Process::Terminate Process [C0018]"
	hash = "C91887D861D9BD4A5872249B641BC9F9"
	hash = "9B7CCAA2AE6A5B96E3110EBCBC4311F6"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/terminate/terminate-process.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/kernel32/i, /TerminateProcess/) 
	or 	pe.imports(/ntdll/i, /NtTerminateProcess/) 
	or 	pe.imports(/kernel32/i, /ExitProcess/)  )  )  ) 
}

rule capa_enumerate_process_modules { 
  meta: 
 	description = "enumerate process modules (converted from capa rule)"
	namespace = "host-interaction/process/modules/list"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::Process Discovery [T1057]"
	hash = "6F99A2C8944CB02FF28C6F9CED59B161"
	hash = "9B2FD471274C41626B75DDBB5C897877"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/modules/list/enumerate-process-modules.yml"
	date = "2021-05-15"

  strings: 
 	$api_apm = "EnumProcessModules" ascii wide
	$api_apn = "EnumProcessModulesEx" ascii wide
	$api_apo = "EnumProcesses" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/kernel32/i, /K32EnumProcessModules/) 
	or 	pe.imports(/kernel32/i, /K32EnumProcessModulesEx/) 
	or 	pe.imports(/kernel32/i, /K32EnumProcesses/) 
	or 	$api_apm 
	or 	$api_apn 
	or 	$api_apo  )  )  ) 
}

rule capa_get_domain_information { 
  meta: 
 	description = "get domain information (converted from capa rule)"
	namespace = "host-interaction/network/domain"
	author = "@recvfrom"
	description = "Looks for imported Windows APIs that can be used to collect information about the Windows domain that a computer is connected to."
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	hash = "9B7CCAA2AE6A5B96E3110EBCBC4311F6"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/domain/get-domain-information.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
	pe.imports(/netapi32/i, /DsRoleGetPrimaryDomainInformation/) 
}

rule capa_get_networking_interfaces { 
  meta: 
 	description = "get networking interfaces (converted from capa rule)"
	namespace = "host-interaction/network/interface"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	hash = "B7841B9D5DC1F511A93CC7576672EC0C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/interface/get-networking-interfaces.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/iphlpapi/i, /GetIfTable/) 
	or 	pe.imports(/iphlpapi/i, /GetAdaptersInfo/)  ) 
}

rule capa_register_network_filter_via_WFP_API { 
  meta: 
 	description = "register network filter via WFP API (converted from capa rule)"
	namespace = "host-interaction/network/traffic/filter"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Impact::Data Manipulation::Transmitted Data Manipulation [T1565]"
	hash = "493167E85E45363D09495D0841C30648"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/traffic/filter/register-network-filter-via-wfp-api.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/fwpkclnt/i, /FwpmFilterAdd0/)  ) 
}

rule capa_copy_network_traffic { 
  meta: 
 	description = "copy network traffic (converted from capa rule)"
	namespace = "host-interaction/network/traffic/copy"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::Network Sniffing [T1040]"
	hash = "493167E85E45363D09495D0841C30648"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/traffic/copy/copy-network-traffic.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/fwpkclnt/i, /FwpsCopyStreamDataToBuffer0/)  ) 
}

rule capa_resolve_DNS { 
  meta: 
 	description = "resolve DNS (converted from capa rule)"
	namespace = "host-interaction/network/dns/resolve"
	author = "william.ballenthin@fireeye.com"
	author = "johnk3r"
	scope = "function"
	mbc = "Communication::DNS Communication::Resolve [C0011.001]"
	hash = "17264e3126a97c319a6a0c61e6da951e"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/dns/resolve/resolve-dns.yml"
	date = "2021-05-15"

  strings: 
 	$api_app = "DnsQuery_A" ascii wide
	$api_apq = "DnsQuery_W" ascii wide
	$api_apr = "DnsQuery_UTF8" ascii wide
	$api_aps = "DnsQueryEx" ascii wide
	$api_apt = "getaddrinfo" ascii wide
	$api_apu = "GetAddrInfo" ascii wide
	$api_apv = "GetAddrInfoEx" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ws2_32/i, /gethostbyname/) 
	or 	$api_app 
	or 	$api_apq 
	or 	$api_apr 
	or 	$api_aps 
	or 	$api_apt 
	or 	$api_apu 
	or 	$api_apv  ) 
}

rule capa_check_Internet_connectivity_via_WinINet { 
  meta: 
 	description = "check Internet connectivity via WinINet (converted from capa rule)"
	namespace = "host-interaction/network/connectivity"
	author = "matthew.williams@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	attack = "Discovery::System Network Configuration Discovery::Internet Connection Discovery [T1016.001]"
	hash = "648FC498110B11B4313A47A776E6BA40"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/connectivity/check-internet-connectivity-via-wininet.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/wininet/i, /InternetGetConnectedState/) 
	or 	pe.imports(/wininet/i, /InternetCheckConnection/)  )  )  ) 
}

rule capa_get_local_IPv4_addresses { 
  meta: 
 	description = "get local IPv4 addresses (converted from capa rule)"
	namespace = "host-interaction/network/address"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	hash = "Practical Malware Analysis Lab 05-01.dll_:0x100037e6"
	hash = "4C0553285D724DCAF5909924B4E3E90A"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/address/get-local-ipv4-addresses.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  strings: 
 	$api_apx = "GetAdaptersAddresses" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$api_apx  )  )  ) 
}

rule capa_create_mutex { 
  meta: 
 	description = "create mutex (converted from capa rule)"
	namespace = "host-interaction/mutex"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Process::Create Mutex [C0042]"
	hash = "Practical Malware Analysis Lab 01-01.dll_:0x10001010"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/mutex/create-mutex.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /CreateMutex/) 
	or 	pe.imports(/kernel32/i, /CreateMutexEx/)  ) 
}

rule capa_bypass_UAC_via_token_manipulation { 
  meta: 
 	description = "bypass UAC via token manipulation (converted from capa rule)"
	namespace = "host-interaction/uac/bypass"
	author = "richard.cole@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Abuse Elevation Control Mechanism::Bypass User Access Control [T1548.002]"
	references = "https://github.com/hfiref0x/UACME/blob/0a4d2bd67f4872c595f0217ef6ebdcf135186945/Source/Akagi/methods/tyranid.c#L83"
	hash = "2f43138aa75fb12ac482b486cbc98569"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/uac/bypass/bypass-uac-via-token-manipulation.yml"
	date = "2021-05-15"

  strings: 
 	$str_aqb = "wusa.exe" ascii wide
	$api_aqc = "ShellExecuteExW" ascii wide
	$api_aqd = "ImpersonateLoggedOnUser" ascii wide
	$api_aqe = "GetStartupInfoW" ascii wide
	$api_aqf = "CreateProcessWithLogonW" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_aqb 
	and 	$api_aqc 
	and 	$api_aqd 
	and 	$api_aqe 
	and 	$api_aqf  ) 
}

rule capa_bypass_UAC_via_AppInfo_ALPC { 
  meta: 
 	description = "bypass UAC via AppInfo ALPC (converted from capa rule)"
	namespace = "host-interaction/uac/bypass"
	author = "richard.cole@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Abuse Elevation Control Mechanism::Bypass User Access Control [T1548.002]"
	references = "https://github.com/hfiref0x/UACME/blob/0a4d2bd67f4872c595f0217ef6ebdcf135186945/Source/Akagi/methods/tyranid.c#L597"
	hash = "2f43138aa75fb12ac482b486cbc98569"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/uac/bypass/bypass-uac-via-appinfo-alpc.yml"
	date = "2021-05-15"

  strings: 
 	$str_aqg = "winver.exe" ascii wide
	$str_aqh = "WinSta0\\Default" ascii wide
	$str_aqi = "taskmgr.exe" ascii wide
	$api_aqj = "WaitForDebugEvent" ascii wide
	$api_aqk = "ContinueDebugEvent" ascii wide
	$api_aql = "TerminateProcess" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_aqg 
	and 	$str_aqh 
	and 	$str_aqi 
	and 	$api_aqj 
	and 	$api_aqk 
	and 	$api_aql  ) 
}

rule capa_access_the_Windows_event_log { 
  meta: 
 	description = "access the Windows event log (converted from capa rule)"
	namespace = "host-interaction/log/winevt/access"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Discovery::File and Directory Discovery::Log File [E1083.m01]"
	hash = "mimikatz.exe_:0x45228B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/log/winevt/access/access-the-windows-event-log.yml"
	date = "2021-05-15"

  strings: 
 	$api_aqm = "OpenEventLog" ascii wide
	$api_aqn = "ClearEventLog" ascii wide
	$api_aqo = "OpenBackupEventLog" ascii wide
	$api_aqp = "ReportEvent" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_aqm 
	or 	$api_aqn 
	or 	$api_aqo 
	or 	$api_aqp  ) 
}

rule capa_print_debug_messages { 
  meta: 
 	description = "print debug messages (converted from capa rule)"
	namespace = "host-interaction/log/debug/write-event"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	hash = "493167E85E45363D09495D0841C30648"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/log/debug/write-event/print-debug-messages.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ntoskrnl/i, /DbgPrint/) 
	or 	pe.imports(/kernel32/i, /OutputDebugString/)  ) 
}

rule capa_set_environment_variable { 
  meta: 
 	description = "set environment variable (converted from capa rule)"
	namespace = "host-interaction/environment-variable"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Operating System::Environment Variable::Set Variable [C0034.001]"
	hash = "Practical Malware Analysis Lab 11-03.exe_:0x406580"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/environment-variable/set-environment-variable.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /SetEnvironmentStrings/) 
	or 	pe.imports(/kernel32/i, /SetEnvironmentVariable/)  ) 
}

rule capa_query_environment_variable { 
  meta: 
 	description = "query environment variable (converted from capa rule)"
	namespace = "host-interaction/environment-variable"
	author = "michael.hunhoff@fireeye.com"
	author = "@_re_fox"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "Practical Malware Analysis Lab 14-02.exe_:0x401880"
	hash = "0761142efbda6c4b1e801223de723578"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/environment-variable/query-environment-variable.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /GetEnvironmentVariable/) 
	or 	pe.imports(/kernel32/i, /GetEnvironmentStrings/) 
	or 	pe.imports(/kernel32/i, /ExpandEnvironmentStrings/) 
	or 	pe.imports(/msvcr90/i, /getenv/) 
	or 	pe.imports(/msvcrt/i, /getenv/)  ) 
}

rule capa_open_registry_key_via_offline_registry_library { 
  meta: 
 	description = "open registry key via offline registry library (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "johnk3r"
	scope = "function"
	mbc = "Operating System::Registry::Open Registry Key [C0036.003]"
	hash = "5fbbfeed28b258c42e0cfeb16718b31c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/open-registry-key-via-offline-registry-library.yml"
	date = "2021-05-15"

  strings: 
 	$api_aqq = "OROpenHive" ascii wide
	$api_aqr = "OROpenKey" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_aqq 
	or 	$api_aqr  ) 
}

rule capa_query_or_enumerate_registry_value { 
  meta: 
 	description = "query or enumerate registry value (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "william.ballenthin@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::Query Registry [T1012]"
	mbc = "Operating System::Registry::Query Registry Value [C0036.006]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x100047AD"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/query-or-enumerate-registry-value.yml"
	date = "2021-05-15"

  strings: 
 	$api_aqs = "ZwQueryValueKey" ascii wide
	$api_aqt = "ZwEnumerateValueKey" ascii wide
	$api_aqu = "NtQueryValueKey" ascii wide
	$api_aqv = "NtEnumerateValueKey" ascii wide
	$api_aqw = "RtlQueryRegistryValues" ascii wide
	$api_aqx = "SHGetValue" ascii wide
	$api_aqy = "SHEnumValue" ascii wide
	$api_aqz = "SHRegGetInt" ascii wide
	$api_ara = "SHRegGetPath" ascii wide
	$api_arb = "SHRegGetValue" ascii wide
	$api_arc = "SHQueryValueEx" ascii wide
	$api_ard = "SHRegGetUSValue" ascii wide
	$api_are = "SHOpenRegStream" ascii wide
	$api_arf = "SHRegEnumUSValue" ascii wide
	$api_arg = "SHOpenRegStream2" ascii wide
	$api_arh = "SHRegQueryUSValue" ascii wide
	$api_ari = "SHRegGetBoolUSValue" ascii wide
	$api_arj = "SHRegGetValueFromHKCUHKLM" ascii wide
	$api_ark = "SHRegGetBoolValueFromHKCUHKLM" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/advapi32/i, /RegGetValue/) 
	or 	pe.imports(/advapi32/i, /RegEnumValue/) 
	or 	pe.imports(/advapi32/i, /RegQueryValue/) 
	or 	pe.imports(/advapi32/i, /RegQueryValueEx/) 
	or 	pe.imports(/advapi32/i, /RegQueryMultipleValues/) 
	or 	$api_aqs 
	or 	$api_aqt 
	or 	$api_aqu 
	or 	$api_aqv 
	or 	$api_aqw 
	or 	$api_aqx 
	or 	$api_aqy 
	or 	$api_aqz 
	or 	$api_ara 
	or 	$api_arb 
	or 	$api_arc 
	or 	$api_ard 
	or 	$api_are 
	or 	$api_arf 
	or 	$api_arg 
	or 	$api_arh 
	or 	$api_ari 
	or 	$api_arj 
	or 	$api_ark  )  )  ) 
}

rule capa_set_registry_key_via_offline_registry_library { 
  meta: 
 	description = "set registry key via offline registry library (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "johnk3r"
	scope = "function"
	attack = "Defense Evasion::Modify Registry [T1112]"
	mbc = "Operating System::Registry::Set Registry Key [C0036.001]"
	hash = "5fbbfeed28b258c42e0cfeb16718b31c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/set-registry-key-via-offline-registry-library.yml"
	date = "2021-05-15"

  strings: 
 	$api_arl = "ORSetValue" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_arl  ) 
}

rule capa_query_registry_key_via_offline_registry_library { 
  meta: 
 	description = "query registry key via offline registry library (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "johnk3r"
	scope = "function"
	attack = "Discovery::Query Registry [T1012]"
	mbc = "Operating System::Registry::Query Registry Value [C0036.006]"
	hash = "5fbbfeed28b258c42e0cfeb16718b31c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/query-registry-key-via-offline-registry-library.yml"
	date = "2021-05-15"

  strings: 
 	$api_arm = "ORGetValue" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_arm  ) 
}

rule capa_query_or_enumerate_registry_key { 
  meta: 
 	description = "query or enumerate registry key (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::Query Registry [T1012]"
	mbc = "Operating System::Registry::Query Registry Key [C0036.005]"
	hash = "493167E85E45363D09495D0841C30648"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/query-or-enumerate-registry-key.yml"
	date = "2021-05-15"

  strings: 
 	$api_arn = "ZwQueryKey" ascii wide
	$api_aro = "ZwEnumerateKey" ascii wide
	$api_arp = "NtQueryKey" ascii wide
	$api_arq = "NtEnumerateKey" ascii wide
	$api_arr = "RtlCheckRegistryKey" ascii wide
	$api_ars = "SHEnumKeyEx" ascii wide
	$api_art = "SHQueryInfoKey" ascii wide
	$api_aru = "SHRegEnumUSKey" ascii wide
	$api_arv = "SHRegQueryInfoUSKey" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/advapi32/i, /RegEnumKey/) 
	or 	pe.imports(/advapi32/i, /RegEnumKeyEx/) 
	or 	pe.imports(/advapi32/i, /RegQueryInfoKeyA/) 
	or 	$api_arn 
	or 	$api_aro 
	or 	$api_arp 
	or 	$api_arq 
	or 	$api_arr 
	or 	$api_ars 
	or 	$api_art 
	or 	$api_aru 
	or 	$api_arv  )  )  ) 
}

rule capa_create_registry_key_via_offline_registry_library { 
  meta: 
 	description = "create registry key via offline registry library (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "johnk3r"
	scope = "function"
	attack = "Defense Evasion::Modify Registry [T1112]"
	mbc = "Operating System::Registry::Create Registry Key [C0036.004]"
	hash = "5fbbfeed28b258c42e0cfeb16718b31c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/create-registry-key-via-offline-registry-library.yml"
	date = "2021-05-15"

  strings: 
 	$api_arw = "ORCreateHive" ascii wide
	$api_arx = "ORCreateKey" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_arw 
	or 	$api_arx  ) 
}

rule capa_create_or_open_registry_key { 
  meta: 
 	description = "create or open registry key (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	mbc = "Operating System::Registry::Create Registry Key [C0036.004]"
	mbc = "Operating System::Registry::Open Registry Key [C0036.003]"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x10004706"
	hash = "Practical Malware Analysis Lab 11-01.exe_:0x401000"
	hash = "493167E85E45363D09495D0841C30648"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/create-or-open-registry-key.yml"
	date = "2021-05-15"

  strings: 
 	$api_ary = "ZwOpenKey" ascii wide
	$api_arz = "ZwOpenKeyEx" ascii wide
	$api_asa = "ZwCreateKey" ascii wide
	$api_asb = "ZwOpenKeyTransacted" ascii wide
	$api_asc = "ZwOpenKeyTransactedEx" ascii wide
	$api_asd = "ZwCreateKeyTransacted" ascii wide
	$api_ase = "NtOpenKey" ascii wide
	$api_asf = "NtCreateKey" ascii wide
	$api_asg = "SHRegOpenUSKey" ascii wide
	$api_ash = "SHRegCreateUSKey" ascii wide
	$api_asi = "RtlCreateRegistryKey" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /RegOpenKey/) 
	or 	pe.imports(/advapi32/i, /RegOpenKeyEx/) 
	or 	pe.imports(/advapi32/i, /RegCreateKey/) 
	or 	pe.imports(/advapi32/i, /RegCreateKeyEx/) 
	or 	pe.imports(/advapi32/i, /RegOpenCurrentUser/) 
	or 	pe.imports(/advapi32/i, /RegOpenKeyTransacted/) 
	or 	pe.imports(/advapi32/i, /RegOpenUserClassesRoot/) 
	or 	pe.imports(/advapi32/i, /RegCreateKeyTransacted/) 
	or 	$api_ary 
	or 	$api_arz 
	or 	$api_asa 
	or 	$api_asb 
	or 	$api_asc 
	or 	$api_asd 
	or 	$api_ase 
	or 	$api_asf 
	or 	$api_asg 
	or 	$api_ash 
	or 	$api_asi  ) 
}

rule capa_delete_registry_key { 
  meta: 
 	description = "delete registry key (converted from capa rule)"
	namespace = "host-interaction/registry/delete"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	author = "johnk3r"
	scope = "function"
	attack = "Defense Evasion::Modify Registry [T1112]"
	mbc = "Operating System::Registry::Delete Registry Key [C0036.002]"
	hash = "4f11bdb380dafa2518053c6d20147a05"
	hash = "493167E85E45363D09495D0841C30648"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/delete/delete-registry-key.yml"
	date = "2021-05-15"

  strings: 
 	$api_asj = "ZwDeleteKey" ascii wide
	$api_ask = "NtDeleteKey" ascii wide
	$api_asl = "SHDeleteKey" ascii wide
	$api_asm = "SHDeleteEmptyKey" ascii wide
	$api_asn = "SHRegDeleteEmptyUSKey" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/advapi32/i, /RegDeleteKey/) 
	or 	pe.imports(/advapi32/i, /RegDeleteTree/) 
	or 	pe.imports(/advapi32/i, /RegDeleteKeyEx/) 
	or 	pe.imports(/advapi32/i, /RegDeleteKeyTransacted/) 
	or 	$api_asj 
	or 	$api_ask 
	or 	$api_asl 
	or 	$api_asm 
	or 	$api_asn  )  )  ) 
}

rule capa_delete_registry_value { 
  meta: 
 	description = "delete registry value (converted from capa rule)"
	namespace = "host-interaction/registry/delete"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Modify Registry [T1112]"
	mbc = "Operating System::Registry::Delete Registry Value [C0036.007]"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/delete/delete-registry-value.yml"
	date = "2021-05-15"

  strings: 
 	$api_aso = "ZwDeleteValueKey" ascii wide
	$api_asp = "NtDeleteValueKey" ascii wide
	$api_asq = "RtlDeleteRegistryValue" ascii wide
	$api_asr = "SHDeleteValue" ascii wide
	$api_ass = "SHRegDeleteUSValue" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/advapi32/i, /RegDeleteValue/) 
	or 	pe.imports(/advapi32/i, /RegDeleteKeyValue/) 
	or 	$api_aso 
	or 	$api_asp 
	or 	$api_asq 
	or 	$api_asr 
	or 	$api_ass  )  )  ) 
}

rule capa_set_registry_value { 
  meta: 
 	description = "set registry value (converted from capa rule)"
	namespace = "host-interaction/registry/create"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Operating System::Registry::Set Registry Key [C0036.001]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/create/set-registry-value.yml"
	date = "2021-05-15"

  strings: 
 	$api_ast = "ZwSetValueKey" ascii wide
	$api_asu = "NtSetValueKey" ascii wide
	$api_asv = "RtlWriteRegistryValue" ascii wide
	$api_asw = "SHSetValue" ascii wide
	$api_asx = "SHRegSetPath" ascii wide
	$api_asy = "SHRegSetValue" ascii wide
	$api_asz = "SHRegSetUSValue" ascii wide
	$api_ata = "SHRegWriteUSValue" ascii wide
	$atb = /reg(.exe)? add / nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  (  (  ( 	pe.imports(/advapi32/i, /RegSetValue/) 
	or 	pe.imports(/advapi32/i, /RegSetValueEx/) 
	or 	pe.imports(/advapi32/i, /RegSetKeyValue/) 
	or 	$api_ast 
	or 	$api_asu 
	or 	$api_asv 
	or 	$api_asw 
	or 	$api_asx 
	or 	$api_asy 
	or 	$api_asz 
	or 	$api_ata  )  )  )  ) 
	or  (  ( 	capa_create_process

	and 	$atb  )  )  ) 
}

rule capa_get_logon_sessions { 
  meta: 
 	description = "get logon sessions (converted from capa rule)"
	namespace = "host-interaction/session"
	author = "@recvfrom"
	description = "Looks for imported Windows APIs that can be used to enumerate user sessions."
	scope = "function"
	attack = "Discovery::Account Discovery [T1087]"
	hash = "9B7CCAA2AE6A5B96E3110EBCBC4311F6"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/session/get-logon-sessions.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/secur32/i, /LsaEnumerateLogonSessions/)  ) 
}

rule capa_get_session_integrity_level { 
  meta: 
 	description = "get session integrity level (converted from capa rule)"
	namespace = "host-interaction/session"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Owner/User Discovery [T1033]"
	hash = "9879D201DC5ACA863F357184CD1F170E"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/session/get-session-integrity-level.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/shell32/i, /IsUserAnAdmin/)  ) 
}

rule capa_link_function_at_runtime { 
  meta: 
 	description = "link function at runtime (converted from capa rule)"
	namespace = "linking/runtime-linking"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Execution::Shared Modules [T1129]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	hash = "Practical Malware Analysis Lab 01-04.exe_:0x401350"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/runtime-linking/link-function-at-runtime.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/kernel32/i, /LoadLibrary/) 
	or 	pe.imports(/kernel32/i, /GetModuleHandle/) 
	or 	pe.imports(/kernel32/i, /GetModuleHandleEx/) 
	or 	pe.imports(/ntdll/i, /LdrLoadDll/)  )  ) 
	and  (  ( 	pe.imports(/kernel32/i, /GetProcAddress/) 
	or 	pe.imports(/ntdll/i, /LdrGetProcedureAddress/)  )  )  ) 
}

rule capa_linked_against_Crypto__ { 
  meta: 
 	description = "linked against Crypto++ (converted from capa rule)"
	namespace = "linking/static/cryptopp"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	mbc = "Cryptography::Crypto Library [C0059]"
	hash = "8BA66E4B618FFDC8255F1DF01F875DDE6FD0561305D9F8307BE7BB11D02AE363"
	hash = "66602B5FAB602CB4E6F754748D249542"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/cryptopp/linked-against-crypto.yml"
	date = "2021-05-15"

  strings: 
 	$str_atc = "Cryptographic algorithms are disabled after a power-up self test failed." ascii wide
	$str_atd = ": this object requires an IV" ascii wide
	$str_ate = "BER decode error" ascii wide
	$str_atf = ".?AVException@CryptoPP@@" ascii wide
	$str_atg = "FileStore: error reading file" ascii wide
	$str_ath = "StreamTransformationFilter: PKCS_PADDING cannot be used with " ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_atc 
	or 	$str_atd 
	or 	$str_ate 
	or 	$str_atf 
	or 	$str_atg 
	or 	$str_ath  ) 
}

rule capa_linked_against_OpenSSL { 
  meta: 
 	description = "linked against OpenSSL (converted from capa rule)"
	namespace = "linking/static/openssl"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	mbc = "Cryptography::Crypto Library [C0059]"
	hash = "6cc148363200798a12091b97a17181a1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/openssl/linked-against-openssl.yml"
	date = "2021-05-15"

  strings: 
 	$str_ati = "RC4 for x86_64, CRYPTOGAMS by <appro@openssl.org>" ascii wide
	$str_atj = "AES for x86_64, CRYPTOGAMS by <appro@openssl.org>" ascii wide
	$str_atk = "DSA-SHA1-old" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_ati 
	or 	$str_atj 
	or 	$str_atk  ) 
}

rule capa_linked_against_PolarSSL_mbed_TLS { 
  meta: 
 	description = "linked against PolarSSL/mbed TLS (converted from capa rule)"
	namespace = "linking/static/polarssl"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	mbc = "Cryptography::Crypto Library [C0059]"
	hash = "232b0a8546035d9017fadf68398826edb0a1e055566bc1d356d6c9fdf1d7e485"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/polarssl/linked-against-polarsslmbed-tls.yml"
	date = "2021-05-15"

  strings: 
 	$str_atl = "PolarSSLTest" ascii wide
	$str_atm = "mbedtls_cipher_setup" ascii wide
	$str_atn = "mbedtls_pk_verify" ascii wide
	$str_ato = "mbedtls_ssl_write_record" ascii wide
	$str_atp = "mbedtls_ssl_fetch_input" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_atl 
	or 	$str_atm 
	or 	$str_atn 
	or 	$str_ato 
	or 	$str_atp  ) 
}

rule capa_linked_against_libcurl { 
  meta: 
 	description = "linked against libcurl (converted from capa rule)"
	namespace = "linking/static/libcurl"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	hash = "A90E5B3454AA71D9700B2EA54615F44B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/libcurl/linked-against-libcurl.yml"
	date = "2021-05-15"

  strings: 
 	$atq = /CLIENT libcurl/ ascii wide 
	$atr = /curl\.haxx\.se/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$atq 
	or 	$atr  ) 
}

rule capa_linked_against_Microsoft_Detours { 
  meta: 
 	description = "linked against Microsoft Detours (converted from capa rule)"
	namespace = "linking/static/msdetours"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Hijack Execution Flow [T1574]"
	references = "https://github.com/microsoft/Detours"
	hash = "071F2D1C4C2201EE95FFE2AA965000F5F615A11A12D345E33B9FB060E5597740"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/msdetours/linked-against-microsoft-detours.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any ats in pe.sections : ( ats.name == ".detourc" ) 
	or 	for any att in pe.sections : ( att.name == ".detourd" )  ) 
}

rule capa_linked_against_ZLIB { 
  meta: 
 	description = "linked against ZLIB (converted from capa rule)"
	namespace = "linking/static/zlib"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	mbc = "Data::Compression Library [C0060]"
	hash = "6cc148363200798a12091b97a17181a1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/zlib/linked-against-zlib.yml"
	date = "2021-05-15"

  strings: 
 	$atu = /deflate .{,1000} Copyright/ ascii wide 
	$atv = /inflate .{,1000} Copyright/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$atu 
	or 	$atv  ) 
}

rule capa_reference_Base64_string { 
  meta: 
 	description = "reference Base64 string (converted from capa rule)"
	namespace = "data-manipulation/encoding/base64"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Data::Encode Data::Base64 [C0026.001]"
	mbc = "Data::Check String [C0019]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	hash = "074072B261FC27B65C72671F13510C05"
	hash = "5DB2D2BE20D59AA0BE6709A6850F1775"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encoding/base64/reference-base64-string.yml"
	date = "2021-05-15"

  strings: 
 	$atw = /ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
	$atw 
}

rule capa_import_public_key { 
  meta: 
 	description = "import public key (converted from capa rule)"
	namespace = "data-manipulation/encryption"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	mbc = "Cryptography::Encryption Key::Import Public Key [C0028.001]"
	hash = "ffeae4a391a1d5203bd04b4161557227"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/import-public-key.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /CryptAcquireContext/) 
	and 	pe.imports(/crypt32/i, /CryptImportPublicKeyInfo/)  ) 
}

rule capa_encrypt_or_decrypt_via_WinCrypt { 
  meta: 
 	description = "encrypt or decrypt via WinCrypt (converted from capa rule)"
	namespace = "data-manipulation/encryption"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Cryptography::Decrypt Data [C0031]"
	mbc = "Cryptography::Encrypt Data [C0027]"
	hash = "A45E377DBB98A6B44FD4034BC3FFF9B0"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/encrypt-or-decrypt-via-wincrypt.yml"
	date = "2021-05-15"

  strings: 
 	$api_atx = "CryptEncrypt" ascii wide
	$api_aty = "CryptDecrypt" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$api_atx 
	or 	$api_aty  )  )  ) 
}

rule capa_encrypt_data_using_DPAPI { 
  meta: 
 	description = "encrypt data using DPAPI (converted from capa rule)"
	namespace = "data-manipulation/encryption/dpapi"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Cryptography::Encrypt Data [C0027]"
	hash = "6cc148363200798a12091b97a17181a1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/dpapi/encrypt-data-using-dpapi.yml"
	date = "2021-05-15"

  strings: 
 	$api_atz = "CryptProtectMemory" ascii wide
	$api_aua = "CryptUnprotectMemory" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_atz 
	or 	$api_aua 
	or 	pe.imports(/crypt32/i, /CryptProtectData/) 
	or 	pe.imports(/crypt32/i, /CryptUnprotectData/)  ) 
}

rule capa_encrypt_data_using_Camellia { 
  meta: 
 	description = "encrypt data using Camellia (converted from capa rule)"
	namespace = "data-manipulation/encryption/camellia"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::Camellia [C0027.003]"
	hash = "0761142efbda6c4b1e801223de723578"
	hash = "112f9f0e8d349858a80dd8c14190e620"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/camellia/encrypt-data-using-camellia.yml"
	date = "2021-05-15"

  strings: 
 	$aub = { 00 70 70 70 00 82 82 82 00 2C 2C 2C 00 EC EC EC 00 B3 B3 B3 00 27 27 27 00 C0 C0 C0 00 E5 E5 E5 00 E4 E4 E4 00 85 85 85 00 57 57 57 00 35 35 35 00 EA EA EA 00 0C 0C 0C 00 AE AE AE 00 41 41 41 00 23 23 23 00 EF EF EF 00 6B 6B 6B 00 93 93 93 00 45 45 45 00 19 19 19 00 A5 A5 A5 00 21 21 21 00 ED ED ED 00 0E 0E 0E 00 4F 4F 4F 00 4E 4E 4E 00 1D 1D 1D 00 65 65 65 00 92 92 92 00 BD BD BD 00 86 86 86 00 B8 B8 B8 00 AF AF AF 00 8F 8F 8F 00 7C 7C 7C 00 EB EB EB 00 1F 1F 1F 00 CE CE CE 00 3E 3E 3E 00 30 30 30 00 DC DC }
	$auc = { E0 E0 E0 00 05 05 05 00 58 58 58 00 D9 D9 D9 00 67 67 67 00 4E 4E 4E 00 81 81 81 00 CB CB CB 00 C9 C9 C9 00 0B 0B 0B 00 AE AE AE 00 6A 6A 6A 00 D5 D5 D5 00 18 18 18 00 5D 5D 5D 00 82 82 82 00 46 46 46 00 DF DF DF 00 D6 D6 D6 00 27 27 27 00 8A 8A 8A 00 32 32 32 00 4B 4B 4B 00 42 42 42 00 DB DB DB 00 1C 1C 1C 00 9E 9E 9E 00 9C 9C 9C 00 3A 3A 3A 00 CA CA CA 00 25 25 25 00 7B 7B 7B 00 0D 0D 0D 00 71 71 71 00 5F 5F 5F 00 1F 1F 1F 00 F8 F8 F8 00 D7 D7 D7 00 3E 3E 3E 00 9D 9D 9D 00 7C 7C 7C 00 60 60 60 00 B9 B9 B9 }
	$aud = { 38 38 00 38 41 41 00 41 16 16 00 16 76 76 00 76 D9 D9 00 D9 93 93 00 93 60 60 00 60 F2 F2 00 F2 72 72 00 72 C2 C2 00 C2 AB AB 00 AB 9A 9A 00 9A 75 75 00 75 06 06 00 06 57 57 00 57 A0 A0 00 A0 91 91 00 91 F7 F7 00 F7 B5 B5 00 B5 C9 C9 00 C9 A2 A2 00 A2 8C 8C 00 8C D2 D2 00 D2 90 90 00 90 F6 F6 00 F6 07 07 00 07 A7 A7 00 A7 27 27 00 27 8E 8E 00 8E B2 B2 00 B2 49 49 00 49 DE DE 00 DE 43 43 00 43 5C 5C 00 5C D7 D7 00 D7 C7 C7 00 C7 3E 3E 00 3E F5 F5 00 F5 8F 8F 00 8F 67 67 00 67 1F 1F 00 1F 18 18 00 18 6E 6E 00 }
	$aue = { 70 00 70 70 2C 00 2C 2C B3 00 B3 B3 C0 00 C0 C0 E4 00 E4 E4 57 00 57 57 EA 00 EA EA AE 00 AE AE 23 00 23 23 6B 00 6B 6B 45 00 45 45 A5 00 A5 A5 ED 00 ED ED 4F 00 4F 4F 1D 00 1D 1D 92 00 92 92 86 00 86 86 AF 00 AF AF 7C 00 7C 7C 1F 00 1F 1F 3E 00 3E 3E DC 00 DC DC 5E 00 5E 5E 0B 00 0B 0B A6 00 A6 A6 39 00 39 39 D5 00 D5 D5 5D 00 5D 5D D9 00 D9 D9 5A 00 5A 5A 51 00 51 51 6C 00 6C 6C 8B 00 8B 8B 9A 00 9A 9A FB 00 FB FB B0 00 B0 B0 74 00 74 74 2B 00 2B 2B F0 00 F0 F0 84 00 84 84 DF 00 DF DF CB 00 CB CB 34 00 34 }
	$auf = { 70 82 2C EC B3 27 C0 E5 E4 85 57 35 EA 0C AE 41 23 EF 6B 93 45 19 A5 21 ED 0E 4F 4E 1D 65 92 BD 86 B8 AF 8F 7C EB 1F CE 3E 30 DC 5F 5E C5 0B 1A A6 E1 39 CA D5 47 5D 3D D9 01 5A D6 51 56 6C 4D 8B 0D 9A 66 FB CC B0 2D 74 12 2B 20 F0 B1 84 99 DF 4C CB C2 34 7E 76 05 6D B7 A9 31 D1 17 04 D7 14 58 3A 61 DE 1B 11 1C 32 0F 9C 16 53 18 F2 22 FE 44 CF B2 C3 B5 7A 91 24 08 E8 A8 60 FC 69 50 AA D0 A0 7D A1 89 62 97 54 5B 1E 95 E0 FF 64 D2 10 C4 00 48 A3 F7 75 DB 8A 03 E6 DA 09 3F DD 94 87 5C 83 02 CD 4A 90 33 73 67 F6 F3 9D 7F BF E2 52 9B D8 26 C8 37 C6 3B 81 96 6F 4B 13 BE 63 2E E9 79 A7 8C 9F 6E BC 8E 29 F5 F9 B6 2F FD B4 59 78 98 06 6A E7 46 71 BA D4 25 AB 42 88 A2 8D FA 72 07 B9 55 F8 EE AC 0A 36 49 2A 68 3C 38 F1 A4 40 28 D3 7B BB C9 43 C1 15 E3 AD F4 77 C7 80 9E }
	$num_aug = { 8B 90 CC 3B }
	$num_auh = { 7F 66 9E A0 }
	$num_aui = { B2 73 AA 4C }
	$num_auj = { 58 E8 7A B6 }
	$num_auk = { 2F 37 EF C6 }
	$num_aul = { BE 82 4F E9 }
	$num_aum = { A5 53 FF 54 }
	$num_aun = { 1C 6F D3 F1 }
	$num_auo = { FA 27 E5 10 }
	$num_aup = { 1D 2D 68 DE }
	$num_auq = { C2 88 56 B0 }
	$num_aur = { FD C1 E6 B3 }
	$aus = { 8B 90 CC 3B 7F 66 9E A0 }
	$aut = { B2 73 AA 4C 58 E8 7A B6 }
	$auu = { BE 82 4F E9 2F 37 EF C6 }
	$auv = { 1C 6F D3 F1 A5 53 FF 54 }
	$auw = { 1D 2D 68 DE FA 27 E5 10 }
	$aux = { FD C1 E6 B3 C2 88 56 B0 }
	$auy = /A09E667F3BCC908B/ nocase ascii wide 
	$str_auz = "/B67AE8584CAA73B" ascii wide
	$ava = /C6EF372FE94F82BE/ nocase ascii wide 
	$avb = /54FF53A5F1D36F1C/ nocase ascii wide 
	$avc = /10E527FADE682D1D/ nocase ascii wide 
	$avd = /B05688C2B3E6C1FD/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aub 
	or 	$auc 
	or 	$aud 
	or 	$aue 
	or 	$auf 
	or  (  (  (  ( $num_aug 
	and $num_auh 
	and $num_aui 
	and $num_auj 
	and $num_auk 
	and $num_aul 
	and $num_aum 
	and $num_aun 
	and $num_auo 
	and $num_aup 
	and $num_auq 
	and $num_aur  )  ) 
	or  (  ( 	$aus 
	and 	$aut 
	and 	$auu 
	and 	$auv 
	and 	$auw 
	and 	$aux  )  ) 
	or  (  ( 	$auy 
	and 	$str_auz 
	and 	$ava 
	and 	$avb 
	and 	$avc 
	and 	$avd  )  )  )  )  ) 
}

rule capa_encrypt_data_using_RC6 { 
  meta: 
 	description = "encrypt data using RC6 (converted from capa rule)"
	namespace = "data-manipulation/encryption/rc6"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::RC6 [C0027.010]"
	hash = "D87BA0BFCE1CDB17FD243B8B1D247E88"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/rc6/encrypt-data-using-rc6.yml"
	date = "2021-05-15"

  strings: 
 	$num_ave = { 63 51 E1 B7 }
	$num_avf = { B9 79 37 9E }
	$num_avg = { 47 86 C8 61 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( $num_ave 
	and  (  ( $num_avf 
	or $num_avg  )  )  ) 
}

rule capa_encrypt_data_using_twofish { 
  meta: 
 	description = "encrypt data using twofish (converted from capa rule)"
	namespace = "data-manipulation/encryption/twofish"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::Twofish [C0027.005]"
	hash = "0761142efbda6c4b1e801223de723578"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/twofish/encrypt-data-using-twofish.yml"
	date = "2021-05-15"

  strings: 
 	$avh = { A9 67 B3 E8 04 FD A3 76 9A 92 80 78 E4 DD D1 38 0D C6 35 98 18 F7 EC 6C 43 75 37 26 FA 13 94 48 F2 D0 8B 30 84 54 DF 23 19 5B 3D 59 F3 AE A2 82 63 01 83 2E D9 51 9B 7C A6 EB A5 BE 16 0C E3 61 C0 8C 3A F5 73 2C 25 0B BB 4E 89 6B 53 6A B4 F1 E1 E6 BD 45 E2 F4 B6 66 CC 95 03 56 D4 1C 1E D7 FB C3 8E B5 E9 CF BF BA EA 77 39 AF 33 C9 62 71 81 79 09 AD 24 CD F9 D8 E5 C5 B9 4D 44 08 86 E7 A1 1D AA ED 06 70 B2 D2 41 7B A0 11 31 C2 27 90 20 F6 60 FF 96 5C B1 AB 9E 9C 52 1B 5F 93 0A EF 91 85 49 EE 2D 4F 8F 3B 47 87 6D }
	$avi = { 75 F3 C6 F4 DB 7B FB C8 4A D3 E6 6B 45 7D E8 4B D6 32 D8 FD 37 71 F1 E1 30 0F F8 1B 87 FA 06 3F 5E BA AE 5B 8A 00 BC 9D 6D C1 B1 0E 80 5D D2 D5 A0 84 07 14 B5 90 2C A3 B2 73 4C 54 92 74 36 51 38 B0 BD 5A FC 60 62 96 6C 42 F7 10 7C 28 27 8C 13 95 9C C7 24 46 3B 70 CA E3 85 CB 11 D0 93 B8 A6 83 20 FF 9F 77 C3 CC 03 6F 08 BF 40 E7 2B E2 79 0C AA 82 41 3A EA B9 E4 9A A4 97 7E DA 7A 17 66 94 A1 1D 3D F0 DE B3 0B 72 A7 1C EF D1 53 3E 8F 33 26 5F EC 76 2A 49 81 88 EE 21 C4 1A EB D9 C5 39 99 CD AD 31 8B 01 18 23 DD }
	$avj = { 75 32 BC BC F3 21 EC EC C6 43 20 20 F4 C9 B3 B3 DB 03 DA DA 7B 8B 02 02 FB 2B E2 E2 C8 FA 9E 9E 4A EC C9 C9 D3 09 D4 D4 E6 6B 18 18 6B 9F 1E 1E 45 0E 98 98 7D 38 B2 B2 E8 D2 A6 A6 4B B7 26 26 D6 57 3C 3C 32 8A 93 93 D8 EE 82 82 FD 98 52 52 37 D4 7B 7B 71 37 BB BB F1 97 5B 5B E1 83 47 47 30 3C 24 24 0F E2 51 51 F8 C6 BA BA 1B F3 4A 4A 87 48 BF BF FA 70 0D 0D 06 B3 B0 B0 3F DE 75 75 5E FD D2 D2 BA 20 7D 7D AE 31 66 66 5B A3 3A 3A 8A 1C 59 59 00 00 00 00 BC 93 CD CD 9D E0 1A 1A 6D 2C AE AE C1 AB 7F 7F B1 C7 2B }
	$avk = { 39 39 D9 A9 17 17 90 67 9C 9C 71 B3 A6 A6 D2 E8 07 07 05 04 52 52 98 FD 80 80 65 A3 E4 E4 DF 76 45 45 08 9A 4B 4B 02 92 E0 E0 A0 80 5A 5A 66 78 AF AF DD E4 6A 6A B0 DD 63 63 BF D1 2A 2A 36 38 E6 E6 54 0D 20 20 43 C6 CC CC 62 35 F2 F2 BE 98 12 12 1E 18 EB EB 24 F7 A1 A1 D7 EC 41 41 77 6C 28 28 BD 43 BC BC 32 75 7B 7B D4 37 88 88 9B 26 0D 0D 70 FA 44 44 F9 13 FB FB B1 94 7E 7E 5A 48 03 03 7A F2 8C 8C E4 D0 B6 B6 47 8B 24 24 3C 30 E7 E7 A5 84 6B 6B 41 54 DD DD 06 DF 60 60 C5 23 FD FD 45 19 3A 3A A3 5B C2 C2 68 }
	$avl = { 32 BC 75 BC 21 EC F3 EC 43 20 C6 20 C9 B3 F4 B3 03 DA DB DA 8B 02 7B 02 2B E2 FB E2 FA 9E C8 9E EC C9 4A C9 09 D4 D3 D4 6B 18 E6 18 9F 1E 6B 1E 0E 98 45 98 38 B2 7D B2 D2 A6 E8 A6 B7 26 4B 26 57 3C D6 3C 8A 93 32 93 EE 82 D8 82 98 52 FD 52 D4 7B 37 7B 37 BB 71 BB 97 5B F1 5B 83 47 E1 47 3C 24 30 24 E2 51 0F 51 C6 BA F8 BA F3 4A 1B 4A 48 BF 87 BF 70 0D FA 0D B3 B0 06 B0 DE 75 3F 75 FD D2 5E D2 20 7D BA 7D 31 66 AE 66 A3 3A 5B 3A 1C 59 8A 59 00 00 00 00 93 CD BC CD E0 1A 9D 1A 2C AE 6D AE AB 7F C1 7F C7 2B B1 }
	$avm = { D9 A9 39 D9 90 67 17 90 71 B3 9C 71 D2 E8 A6 D2 05 04 07 05 98 FD 52 98 65 A3 80 65 DF 76 E4 DF 08 9A 45 08 02 92 4B 02 A0 80 E0 A0 66 78 5A 66 DD E4 AF DD B0 DD 6A B0 BF D1 63 BF 36 38 2A 36 54 0D E6 54 43 C6 20 43 62 35 CC 62 BE 98 F2 BE 1E 18 12 1E 24 F7 EB 24 D7 EC A1 D7 77 6C 41 77 BD 43 28 BD 32 75 BC 32 D4 37 7B D4 9B 26 88 9B 70 FA 0D 70 F9 13 44 F9 B1 94 FB B1 5A 48 7E 5A 7A F2 03 7A E4 D0 8C E4 47 8B B6 47 3C 30 24 3C A5 84 E7 A5 41 54 6B 41 06 DF DD 06 C5 23 60 C5 45 19 FD 45 A3 5B 3A A3 68 3D C2 }
	$avn = { 01 02 04 08 10 20 40 80 4D 9A 79 F2 A9 1F 3E 7C F8 BD 37 6E DC F5 A7 03 06 0C 18 30 60 C0 CD D7 E3 8B 5B B6 21 42 84 45 8A 59 B2 29 52 A4 05 0A 14 28 50 A0 0D 1A 34 68 D0 ED 97 63 C6 C1 CF D3 EB 9B 7B F6 A1 0F 1E 3C 78 F0 AD 17 2E 5C B8 3D 7A F4 A5 07 0E 1C 38 70 E0 8D 57 AE 11 22 44 88 5D BA 39 72 E4 85 47 8E 51 A2 09 12 24 48 90 6D DA F9 BF 33 66 CC D5 E7 83 4B 96 61 C2 C9 DF F3 AB 1B 36 6C D8 FD B7 23 46 8C 55 AA 19 32 64 C8 DD F7 A3 0B 16 2C 58 B0 2D 5A B4 25 4A 94 65 CA D9 FF B3 2B 56 AC 15 2A 54 A8 1D }
	$avo = { A9 75 67 F3 B3 C6 E8 F4 04 DB FD 7B A3 FB 76 C8 9A 4A 92 D3 80 E6 78 6B E4 45 DD 7D D1 E8 38 4B 0D D6 C6 32 35 D8 98 FD 18 37 F7 71 EC F1 6C E1 43 30 75 0F 37 F8 26 1B FA 87 13 FA 94 06 48 3F F2 5E D0 BA 8B AE 30 5B 84 8A 54 00 DF BC 23 9D 19 6D 5B C1 3D B1 59 0E F3 80 AE 5D A2 D2 82 D5 63 A0 01 84 83 07 2E 14 D9 B5 51 90 9B 2C 7C A3 A6 B2 EB 73 A5 4C BE 54 16 92 0C 74 E3 36 61 51 C0 38 8C B0 3A BD F5 5A 73 FC 2C 60 25 62 0B 96 BB 6C 4E 42 89 F7 6B 10 53 7C 6A 28 B4 27 F1 8C E1 13 E6 95 BD 9C 45 C7 E2 24 F4 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$avh 
	or 	$avi 
	or 	$avj 
	or 	$avk 
	or 	$avl 
	or 	$avm 
	or 	$avn 
	or 	$avo  ) 
}

rule capa_encrypt_data_using_Sosemanuk { 
  meta: 
 	description = "encrypt data using Sosemanuk (converted from capa rule)"
	namespace = "data-manipulation/encryption/sosemanuk"
	author = "@recvfrom"
	description = "Looks for cryptographic constants associated with the Sosemanuk stream cipher"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::Sosemanuk [C0027.008]"
	references = "https://labs.sentinelone.com/enter-the-maze-demystifying-an-affiliate-involved-in-maze-snow/"
	hash = "ea7bb99e03606702c1cbe543bb32b27e"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/sosemanuk/encrypt-data-using-sosemanuk.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  strings: 
 	$avp = { 00 00 00 00 E1 9F CF 13 6B 97 37 26 8A 08 F8 35 D6 87 6E 4C 37 18 A1 5F BD 10 59 6A 5C 8F 96 79 05 A7 DC 98 E4 38 13 8B 6E 30 EB BE 8F AF 24 AD D3 20 B2 D4 32 BF 7D C7 B8 B7 85 F2 59 28 4A E1 0A E7 11 99 EB 78 DE 8A 61 70 26 BF 80 EF E9 AC DC 60 7F D5 3D FF B0 C6 B7 F7 48 F3 56 68 87 E0 0F 40 CD 01 EE DF 02 12 64 D7 FA 27 85 48 35 34 D9 C7 A3 4D 38 58 6C 5E B2 50 94 6B 53 CF 5B 78 }
	$avq = { 00 00 00 00 13 CF 9F E1 26 37 97 6B 35 F8 08 8A 4C 6E 87 D6 5F A1 18 37 6A 59 10 BD 79 96 8F 5C 98 DC A7 05 8B 13 38 E4 BE EB 30 6E AD 24 AF 8F D4 B2 20 D3 C7 7D BF 32 F2 85 B7 B8 E1 4A 28 59 99 11 E7 0A 8A DE 78 EB BF 26 70 61 AC E9 EF 80 D5 7F 60 DC C6 B0 FF 3D F3 48 F7 B7 E0 87 68 56 01 CD 40 0F 12 02 DF EE 27 FA D7 64 34 35 48 85 4D A3 C7 D9 5E 6C 58 38 6B 94 50 B2 78 5B CF 53 }
	$avr = { 00 00 00 00 18 0F 40 CD 30 1E 80 33 28 11 C0 FE 60 3C A9 66 78 33 E9 AB 50 22 29 55 48 2D 69 98 C0 78 FB CC D8 77 BB 01 F0 66 7B FF E8 69 3B 32 A0 44 52 AA B8 4B 12 67 90 5A D2 99 88 55 92 54 29 F0 5F 31 31 FF 1F FC 19 EE DF 02 01 E1 9F CF 49 CC F6 57 51 C3 B6 9A 79 D2 76 64 61 DD 36 A9 E9 88 A4 FD F1 87 E4 30 D9 96 24 CE C1 99 64 03 89 B4 0D 9B 91 BB 4D 56 B9 AA 8D A8 A1 A5 CD 65 }
	$avs = { 00 00 00 00 CD 40 0F 18 33 80 1E 30 FE C0 11 28 66 A9 3C 60 AB E9 33 78 55 29 22 50 98 69 2D 48 CC FB 78 C0 01 BB 77 D8 FF 7B 66 F0 32 3B 69 E8 AA 52 44 A0 67 12 4B B8 99 D2 5A 90 54 92 55 88 31 5F F0 29 FC 1F FF 31 02 DF EE 19 CF 9F E1 01 57 F6 CC 49 9A B6 C3 51 64 76 D2 79 A9 36 DD 61 FD A4 88 E9 30 E4 87 F1 CE 24 96 D9 03 64 99 C1 9B 0D B4 89 56 4D BB 91 A8 8D AA B9 65 CD A5 A1 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$avp 
	or 	$avq 
	or 	$avr 
	or 	$avs 
  ) 
}

rule capa_encrypt_data_using_DES { 
  meta: 
 	description = "encrypt data using DES (converted from capa rule)"
	namespace = "data-manipulation/encryption/des"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::3DES [C0027.004]"
	hash = "91a12a4cf437589ba70b1687f5acad19"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/des/encrypt-data-using-des.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  strings: 
 	$avt = { 0E 04 0D 01 02 0F 0B 08 03 0A 06 0C 05 09 00 07 00 0F 07 04 0E 02 0D 01 0A 06 0C 0B 09 05 03 08 04 01 0E 08 0D 06 02 0B 0F 0C 09 07 03 0A 05 00 0F 0C 08 02 04 09 01 07 05 0B 03 0E 0A 00 06 0D }
	$avu = { 0F 01 08 0E 06 0B 03 04 09 07 02 0D 0C 00 05 0A 03 0D 04 07 0F 02 08 0E 0C 00 01 0A 06 09 0B 05 00 0E 07 0B 0A 04 0D 01 05 08 0C 06 09 03 02 0F 0D 08 0A 01 03 0F 04 02 0B 06 07 0C 00 05 0E 09 }
	$avv = { 0A 00 09 0E 06 03 0F 05 01 0D 0C 07 0B 04 02 08 0D 07 00 09 03 04 06 0A 02 08 05 0E 0C 0B 0F 01 0D 06 04 09 08 0F 03 00 0B 01 02 0C 05 0A 0E 07 01 0A 0D 00 06 09 08 07 04 0F 0E 03 0B 05 02 0C }
	$avw = { 07 0D 0E 03 00 06 09 0A 01 02 08 05 0B 0C 04 0F 0D 08 0B 05 06 0F 00 03 04 07 02 0C 01 0A 0E 09 0A 06 09 00 0C 0B 07 0D 0F 01 03 0E 05 02 08 04 03 0F 00 06 0A 01 0D 08 09 04 05 0B 0C 07 02 0E }
	$avx = { 02 0C 04 01 07 0A 0B 06 08 05 03 0F 0D 00 0E 09 0E 0B 02 0C 04 07 0D 01 05 00 0F 0A 03 09 08 06 04 02 01 0B 0A 0D 07 08 0F 09 0C 05 06 03 00 0E 0B 08 0C 07 01 0E 02 0D 06 0F 00 09 0A 04 05 03 }
	$avy = { 0C 01 0A 0F 09 02 06 08 00 0D 03 04 0E 07 05 0B 0A 0F 04 02 07 0C 09 05 06 01 0D 0E 00 0B 03 08 09 0E 0F 05 02 08 0C 03 07 00 04 0A 01 0D 0B 06 04 03 02 0C 09 05 0F 0A 0B 0E 01 07 06 00 08 0D }
	$avz = { 04 0B 02 0E 0F 00 08 0D 03 0C 09 07 05 0A 06 01 0D 00 0B 07 04 09 01 0A 0E 03 05 0C 02 0F 08 06 01 04 0B 0D 0C 03 07 0E 0A 0F 06 08 00 05 09 02 06 0B 0D 08 01 04 0A 07 09 05 00 0F 0E 02 03 0C }
	$awa = { 0D 02 08 04 06 0F 0B 01 0A 09 03 0E 05 00 0C 07 01 0F 0D 08 0A 03 07 04 0C 05 06 0B 00 0E 09 02 07 0B 04 01 09 0C 0E 02 00 06 0A 0D 0F 03 05 08 02 01 0E 07 04 0A 08 0D 0F 0C 09 00 03 05 06 0B }
	$awb = { 39 31 29 21 19 11 09 01 3A 32 2A 22 1A 12 0A 02 3B 33 2B 23 1B 13 0B 03 3C 34 2C 24 3F 37 2F 27 1F 17 0F 07 3E 36 2E 26 1E 16 0E 06 3D 35 2D 25 1D 15 0D 05 1C 14 0C 04 }
	$awc = { 0E 11 0B 18 01 05 03 1C 0F 06 15 0A 17 13 0C 04 1A 08 10 07 1B 14 0D 02 29 34 1F 25 2F 37 1E 28 33 2D 21 30 2C 31 27 38 22 35 2E 2A 32 24 1D 20 }
	$awd = { 3A 32 2A 22 1A 12 0A 02 3C 34 2C 24 1C 14 0C 04 3E 36 2E 26 1E 16 0E 06 40 38 30 28 20 18 10 08 39 31 29 21 19 11 09 01 3B 33 2B 23 1B 13 0B 03 3D 35 2D 25 1D 15 0D 05 3F 37 2F 27 1F 17 0F 07 }
	$awe = { 28 08 30 10 38 18 40 20 27 07 2F 0F 37 17 3F 1F 26 06 2E 0E 36 16 3E 1E 25 05 2D 0D 35 15 3D 1D 24 04 2C 0C 34 14 3C 1C 23 03 2B 0B 33 13 3B 1B 22 02 2A 0A 32 12 3A 1A 21 01 29 09 31 11 39 19 }
	$awf = { 20 01 02 03 04 05 04 05 06 07 08 09 08 09 0A 0B 0C 0D 0C 0D 0E 0F 10 11 10 11 12 13 14 15 14 15 16 17 18 19 18 19 1A 1B 1C 1D 1C 1D 1E 1F 20 01 }
	$awg = { 10 07 14 15 1D 0C 1C 11 01 0F 17 1A 05 12 1F 0A 02 08 18 0E 20 1B 03 09 13 0D 1E 06 16 0B 04 19 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$avt 
	or 	$avu 
	or 	$avv 
	or 	$avw 
	or 	$avx 
	or 	$avy 
	or 	$avz 
	or 	$awa 
	or 	$awb 
	or 	$awc 
	or 	$awd 
	or 	$awe 
	or 	$awf 
	or 	$awg 
  ) 
}

rule capa_encrypt_data_using_AES_via__NET { 
  meta: 
 	description = "encrypt data using AES via .NET (converted from capa rule)"
	namespace = "data-manipulation/encryption/aes"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::AES [C0027.001]"
	hash = "b9f5bd514485fb06da39beff051b9fdc"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/aes/encrypt-data-using-aes-via-net.yml"
	date = "2021-05-15"

  strings: 
 	$str_awh = "RijndaelManaged" ascii wide
	$str_awi = "CryptoStream" ascii wide
	$str_awj = "System.Security.Cryptography" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_awh 
	and 	$str_awi 
	and 	$str_awj  ) 
}

rule capa_encrypt_data_using_skipjack { 
  meta: 
 	description = "encrypt data using skipjack (converted from capa rule)"
	namespace = "data-manipulation/encryption/skipjack"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::Skipjack [C0027.013]"
	hash = "94d3c854aadbcfde46b2f82801015c31"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/skipjack/encrypt-data-using-skipjack.yml"
	date = "2021-05-15"

  strings: 
 	$awk = { A3 D7 09 83 F8 48 F6 F4 B3 21 15 78 99 B1 AF F9 E7 2D 4D 8A CE 4C CA 2E 52 95 D9 1E 4E 38 44 28 0A DF 02 A0 17 F1 60 68 12 B7 7A C3 E9 FA 3D 53 96 84 6B BA F2 63 9A 19 7C AE E5 F5 F7 16 6A A2 39 B6 7B 0F C1 93 81 1B EE B4 1A EA D0 91 2F B8 55 B9 DA 85 3F 41 BF E0 5A 58 80 5F 66 0B D8 90 35 D5 C0 A7 33 06 65 69 45 00 94 56 6D 98 9B 76 97 FC B2 C2 B0 FE DB 20 E1 EB D6 E4 DD 47 4A 1D 42 ED 9E 6E 49 3C CD 43 27 D2 07 D4 DE C7 67 18 89 CB 30 1F 8D C6 8F AA C8 74 DC C9 5D 5C 31 A4 70 88 61 2C 9F 0D 2B 87 50 82 54 64 26 7D 03 40 34 4B 1C 73 D1 C4 FD 3B CC FB 7F AB E6 3E 5B A5 AD 04 23 9C 14 51 22 F0 29 79 71 7E FF 8C 0E E2 0C EF BC 72 75 6F 37 A1 EC D3 8E 62 8B 86 10 E8 08 77 11 BE 92 4F 24 C5 32 36 9D CF F3 A6 BB AC 5E 6C A9 13 57 25 B5 E3 BD A8 3A 01 05 59 2A 46 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$awk  ) 
}

rule capa_reference_public_RSA_key { 
  meta: 
 	description = "reference public RSA key (converted from capa rule)"
	namespace = "data-manipulation/encryption/rsa"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Cryptography::Encryption Key [C0028]"
	hash = "b7b5e1253710d8927cbe07d52d2d2e10"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/rsa/reference-public-rsa-key.yml"
	date = "2021-05-15"

  strings: 
 	$awl = { 06 02 00 00 00 A4 00 00 52 53 41 31 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$awl  ) 
}

rule capa_encrypt_data_using_vest { 
  meta: 
 	description = "encrypt data using vest (converted from capa rule)"
	namespace = "data-manipulation/encryption/vest"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data [C0027]"
	references = "https://www.ecrypt.eu.org/stream/vest.html"
	hash = "9a00ebe67d833edb70ed6dd0f4652592"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/vest/encrypt-data-using-vest.yml"
	date = "2021-05-15"

  strings: 
 	$awm = { 07 56 D2 37 3A F7 0A 52 5D C6 2C 87 DA 05 C1 D7 F4 1F 8C 34 }
	$awn = { 41 4B 1B DD 0D 65 72 EE 09 E7 A1 93 3F 0E 55 9C 63 89 3F B2 AB 5A 0E CB 2F 13 E3 9A C7 09 C5 8D C9 09 0D D7 59 1F A2 D6 CB B0 61 E5 39 44 F8 C5 8B C6 E5 B2 BD E3 82 D2 AB 04 DD D6 1F 94 CA EC 73 43 E7 94 5D 52 66 86 4F 4B 05 D4 AD 0F 66 A3 F9 15 9C C6 C9 3E 3A B8 9D 31 65 F8 C7 9A CE E0 6D BD 18 8D 63 F5 0A CD 11 B4 B5 EE 9B 28 9C A5 93 78 5B D1 D3 B1 2B 84 17 AB F4 85 EF 22 E1 D1 }
	$awo = { 4F 70 46 DA E1 8D F6 41 59 E8 5D 26 1E CC 2F 89 26 6D 52 BA BC 11 6B A9 C6 47 E4 9C 1E B6 65 A2 B6 CD 90 47 1C DF F8 10 4B D2 7C C4 72 25 C6 97 25 5D C6 1D 4B 36 BC 38 36 33 F8 89 B4 4C 65 A7 96 CA 1B 63 C3 4B 6A 63 DC 85 4C 57 EE 2A 05 C7 0C E7 39 35 8A C1 BF 13 D9 52 51 3D 2E 41 F5 72 85 23 FE A1 AA 53 61 3B 25 5F 62 B4 36 EE 2A 51 AF 18 8E 9A C6 CF C4 07 4A 9B 25 9B 76 62 0E 3E 96 3A A7 64 23 6B B6 19 BC 2D 40 D7 36 3E E2 85 9A D1 22 9F BC 30 15 9F C2 5D F1 23 E6 3A 73 C0 A6 AD 71 B0 94 1C 9D B6 56 B6 2B }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$awm 
	or 	$awn 
	or 	$awo  ) 
}

rule capa_encrypt_data_using_blowfish { 
  meta: 
 	description = "encrypt data using blowfish (converted from capa rule)"
	namespace = "data-manipulation/encryption/blowfish"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::Blowfish [C0027.002]"
	hash = "0761142efbda6c4b1e801223de723578"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/blowfish/encrypt-data-using-blowfish.yml"
	date = "2021-05-15"

  strings: 
 	$num_awr = { 37 CE 39 3A }
	$num_aws = { 68 5A 3D E9 }
	$num_awt = { E9 70 7A 4B }
	$num_awu = { A6 0B 31 D1 }
	$awv = { 88 6A 3F 24 D3 08 A3 85 2E 8A 19 13 44 73 70 03 22 38 09 A4 D0 31 9F 29 98 FA 2E 08 89 6C 4E EC E6 21 28 45 77 13 D0 38 CF 66 54 BE 6C 0C E9 34 B7 29 AC C0 DD 50 7C C9 B5 D5 84 3F 17 09 47 B5 D9 D5 16 92 1B FB 79 89 }
	$aww = { A6 0B 31 D1 AC B5 DF 98 DB 72 FD 2F B7 DF 1A D0 ED AF E1 B8 96 7E 26 6A 45 90 7C BA 99 7F 2C F1 47 99 A1 24 F7 6C 91 B3 E2 F2 01 08 16 FC 8E 85 D8 20 69 63 69 4E 57 71 A3 FE 58 A4 7E 3D 93 F4 8F 74 95 0D 58 B6 8E 72 58 CD 8B 71 EE 4A 15 82 1D A4 54 7B B5 59 5A C2 39 D5 30 9C 13 60 F2 2A 23 B0 D1 C5 F0 85 60 28 18 79 41 CA EF 38 DB B8 B0 DC 79 8E 0E 18 3A 60 8B 0E 9E 6C 3E 8A 1E B0 C1 77 15 D7 27 4B 31 BD DA 2F AF 78 60 5C 60 55 F3 25 55 E6 94 AB 55 AA 62 98 48 57 40 14 E8 63 6A 39 CA 55 B6 10 AB 2A 34 5C CC }
	$awx = { E9 70 7A 4B 44 29 B3 B5 2E 09 75 DB 23 26 19 C4 B0 A6 6E AD 7D DF A7 49 B8 60 EE 9C 66 B2 ED 8F 71 8C AA EC FF 17 9A 69 6C 52 64 56 E1 9E B1 C2 A5 02 36 19 29 4C 09 75 40 13 59 A0 3E 3A 18 E4 9A 98 54 3F 65 9D 42 5B D6 E4 8F 6B D6 3F F7 99 07 9C D2 A1 F5 30 E8 EF E6 38 2D 4D C1 5D 25 F0 86 20 DD 4C 26 EB 70 84 C6 E9 82 63 5E CC 1E 02 3F 6B 68 09 C9 EF BA 3E 14 18 97 3C A1 70 6A 6B 84 35 7F 68 86 E2 A0 52 05 53 9C B7 37 07 50 AA 1C 84 07 3E 5C AE DE 7F EC 44 7D 8E B8 F2 16 57 37 DA 3A B0 0D 0C 50 F0 04 1F 1C }
	$awy = { 68 5A 3D E9 F7 40 81 94 1C 26 4C F6 34 29 69 94 F7 20 15 41 F7 D4 02 76 2E 6B F4 BC 68 00 A2 D4 71 24 08 D4 6A F4 20 33 B7 D4 B7 43 AF 61 00 50 2E F6 39 1E 46 45 24 97 74 4F 21 14 40 88 8B BF 1D FC 95 4D AF 91 B5 96 D3 DD F4 70 45 2F A0 66 EC 09 BC BF 85 97 BD 03 D0 6D AC 7F 04 85 CB 31 B3 27 EB 96 41 39 FD 55 E6 47 25 DA 9A 0A CA AB 25 78 50 28 F4 29 04 53 DA 86 2C 0A FB 6D B6 E9 62 14 DC 68 00 69 48 D7 A4 C0 0E 68 EE 8D A1 27 A2 FE 3F 4F 8C AD 87 E8 06 E0 8C B5 B6 D6 F4 7A 7C 1E CE AA EC 5F 37 D3 99 A3 78 }
	$awz = { 37 CE 39 3A CF F5 FA D3 37 77 C2 AB 1B 2D C5 5A 9E 67 B0 5C 42 37 A3 4F 40 27 82 D3 BE 9B BC 99 9D 8E 11 D5 15 73 0F BF 7E 1C 2D D6 7B C4 00 C7 6B 1B 8C B7 45 90 A1 21 BE B1 6E B2 B4 6E 36 6A 2F AB 48 57 79 6E 94 BC D2 76 A3 C6 C8 C2 49 65 EE F8 0F 53 7D DE 8D 46 1D 0A 73 D5 C6 4D D0 4C DB BB 39 29 50 46 BA A9 E8 26 95 AC 04 E3 5E BE F0 D5 FA A1 9A 51 2D 6A E2 8C EF 63 22 EE 86 9A B8 C2 89 C0 F6 2E 24 43 AA 03 1E A5 A4 D0 F2 9C BA 61 C0 83 4D 6A E9 9B 50 15 E5 8F D6 5B 64 BA F9 A2 26 28 E1 3A 3A A7 86 95 A9 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( $num_awr 
	and $num_aws 
	and $num_awt 
	and $num_awu  )  ) 
	or  (  ( 	$awv 
	or 	$aww 
	or 	$awx 
	or 	$awy 
	or 	$awz  )  )  ) 
}

rule capa_generate_random_numbers_via_WinAPI { 
  meta: 
 	description = "generate random numbers via WinAPI (converted from capa rule)"
	namespace = "data-manipulation/prng"
	author = "michael.hunhoff@fireeye.com"
	author = "johnk3r"
	scope = "function"
	mbc = "Cryptography::Generate Pseudo-random Sequence::Use API [C0021.003]"
	hash = "ba947eb07d8c823949316a97364d060f"
	hash = "3ca359f5085bb96a7950d4735b089ffe"
	hash = "e59ffeaf7acb0c326e452fa30bb71a36"
	hash = "1195d0d18be9362fb8dd9e1738404c9d"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/prng/generate-random-numbers-via-winapi.yml"
	date = "2021-05-15"

  strings: 
 	$api_axa = "BCryptGenRandom" ascii wide
	$api_axb = "CryptGenRandom" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$api_axa 
	or 	$api_axb  )  )  ) 
}

rule capa_generate_random_numbers_using_a_Mersenne_Twister { 
  meta: 
 	description = "generate random numbers using a Mersenne Twister (converted from capa rule)"
	namespace = "data-manipulation/prng/mersenne"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Cryptography::Generate Pseudo-random Sequence::Mersenne Twister [C0021.005]"
	hash = "D9630C174B8FF5C0AA26168DF523E63E"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/prng/mersenne/generate-random-numbers-using-a-mersenne-twister.yml"
	date = "2021-05-15"

  strings: 
 	$num_axc = { 65 89 07 6C }
	$num_axd = { DF B0 08 99 }
	$num_axe = { 80 56 2C 9D }
	$num_axf = { 00 00 C6 EF }
	$num_axg = { AD 58 3A FF }
	$num_axh = { E9 19 66 A9 5A 6F 02 B5 }
	$num_axi = { 00 00 A6 ED FF 7F D6 71 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( $num_axc 
	or $num_axd 
	or $num_axe 
	or $num_axf 
	or $num_axg 
	or $num_axh 
	or $num_axi  ) 
}

rule capa_compress_data_via_WinAPI { 
  meta: 
 	description = "compress data via WinAPI (converted from capa rule)"
	namespace = "data-manipulation/compression"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Collection::Archive Collected Data::Archive via Library [T1560.002]"
	mbc = "Data::Compress Data [C0024]"
	hash = "638dcc3d37b3a574044233c9637d7288"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/compression/compress-data-via-winapi.yml"
	date = "2021-05-15"

  strings: 
 	$api_axl = "RtlDecompressBuffer" ascii wide
	$str_axm = "RtlDecompressBuffer" ascii wide
	$api_axn = "RtlDecompressBufferEx" ascii wide
	$str_axo = "RtlDecompressBufferEx" ascii wide
	$api_axp = "RtlDecompressBufferEx2" ascii wide
	$str_axq = "RtlDecompressBufferEx2" ascii wide
	$api_axr = "RtlCompressBuffer" ascii wide
	$str_axs = "RtlCompressBuffer" ascii wide
	$api_axt = "RtlCompressBufferLZNT1" ascii wide
	$str_axu = "RtlCompressBufferLZNT1" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_axl 
	or 	$str_axm 
	or 	$api_axn 
	or 	$str_axo 
	or 	$api_axp 
	or 	$str_axq 
	or 	$api_axr 
	or 	$str_axs 
	or 	$api_axt 
	or 	$str_axu  ) 
}

rule capa_hash_data_with_CRC32 { 
  meta: 
 	description = "hash data with CRC32 (converted from capa rule)"
	namespace = "data-manipulation/checksum/crc32"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Data::Checksum::CRC32 [C0032.001]"
	hash = "2D3EDC218A90F03089CC01715A9F047F"
	hash = "7D28CB106CB54876B2A5C111724A07CD"
	hash = "7EFF498DE13CC734262F87E6B3EF38AB"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/checksum/crc32/hash-data-with-crc32.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  strings: 
 	$api_axv = "RtlComputeCrc32" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_axv  ) 
}

rule capa_hash_data_via_WinCrypt { 
  meta: 
 	description = "hash data via WinCrypt (converted from capa rule)"
	namespace = "data-manipulation/hashing"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Cryptography::Cryptographic Hash [C0029]"
	hash = "03B236B23B1EC37C663527C1F53AF3FE"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/hashing/hash-data-via-wincrypt.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /CryptHashData/)  ) 
}

rule capa_hash_data_using_SHA256 { 
  meta: 
 	description = "hash data using SHA256 (converted from capa rule)"
	namespace = "data-manipulation/hashing/sha256"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Cryptography::Cryptographic Hash::SHA256 [C0029.003]"
	hash = "C0CFFCF211035A839E28D542DE300298"
	hash = "6CC148363200798A12091B97A17181A1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/hashing/sha256/hash-data-using-sha256.yml"
	date = "2021-05-15"

  strings: 
 	$num_axw = { 67 E6 09 6A }
	$num_axx = { 85 AE 67 BB }
	$num_axy = { 72 F3 6E 3C }
	$num_axz = { 3A F5 4F A5 }
	$num_aya = { 7F 52 0E 51 }
	$num_ayb = { 8C 68 05 9B }
	$num_ayc = { AB D9 83 1F }
	$num_ayd = { 19 CD E0 5B }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( $num_axw 
	and $num_axx 
	and $num_axy 
	and $num_axz 
	and $num_aya 
	and $num_ayb 
	and $num_ayc 
	and $num_ayd  ) 
}

rule capa_hash_data_using_tiger { 
  meta: 
 	description = "hash data using tiger (converted from capa rule)"
	namespace = "data-manipulation/hashing/tiger"
	author = "@_re_fox"
	scope = "basic block"
	mbc = "Cryptography::Cryptographic Hash::Tiger [C0029.005]"
	hash = "0761142efbda6c4b1e801223de723578"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/hashing/tiger/hash-data-using-tiger.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  strings: 
 	$ayk = { 5E 0C E9 F7 7C B1 AA 02 EC A8 43 E2 03 4B 42 AC D3 FC D5 0D E3 5B CD 72 3A 7F F9 F6 93 9B 01 6D 93 91 1F D2 FF 78 99 CD E2 29 80 70 C9 A1 73 75 C3 83 2A 92 6B 32 64 B1 70 58 91 04 EE 3E 88 46 E6 EC 03 71 05 E3 AC EA 5C 53 A3 08 B8 69 41 C5 7C C4 DE 8D 91 54 E7 4C 0C F4 0D DC DF F4 A2 0A FA BE 4D A7 18 6F B7 10 6A AB D1 5A 23 B6 CC C6 FF E2 2F 57 21 61 72 13 1E 92 9D 19 6F 8C 48 1A CA 07 00 DA F4 F9 C9 4B C7 41 52 E8 F6 E6 F5 26 B6 47 59 EA DB 79 90 85 92 8C 9E C9 C5 85 18 4F 4B 86 6F A9 1E 76 8E D7 7D C1 B5 }
	$ayl = { 38 21 A1 05 5A BE A6 E6 98 7C F8 B4 A5 22 A1 B5 90 69 0B 14 89 60 3C 56 D5 5D 1F 39 2E CB 46 4C 34 94 B7 C9 DB AD 32 D9 F5 AF 15 20 E4 70 EA 08 F1 8C 47 3E 67 A6 65 D7 99 8D 27 AB 7E 75 FB C4 92 06 6E 2D 86 C6 11 DF 16 3B 7F 0D F1 84 EB DD 04 EA 65 A6 04 F6 2E 6F B3 DF E0 F0 0F 0F 8E 4A 51 BA BC 3D F8 EE ED A5 1E 37 A4 0E 2A 0A 4F FC 29 84 B3 5C A8 1D 3E E8 E2 1C 1B BA 82 F8 8F DC 0D E8 53 83 5E 50 45 CD 17 07 DB D4 00 9A D1 18 01 81 F3 A5 ED CF A0 34 F2 CA 87 88 51 7E E7 0B 36 51 C4 B3 38 14 34 1E F9 CC 89 }
	$aym = { 9B F3 DA F1 2F CC 9F F4 81 92 F2 6F C6 D5 7F 48 3F A8 DC FC 67 06 A3 E8 63 CE FC D2 E3 4B 9B 2C C2 BB FB 93 4B F7 3F DA 66 BA 70 FE D2 65 A1 2F D4 93 0E 97 79 E2 03 A1 71 5E E4 B0 77 EC CD BE 97 E4 85 39 72 1E B4 CF 17 50 F7 5E 02 AA 0A B7 E0 B8 40 38 F0 09 23 D4 79 85 89 35 D0 1A FC 8E C5 AB B2 E2 0B 92 C6 96 72 91 5A 37 63 41 AF 66 FB 27 71 CA DC AB 74 21 41 FF 72 4A A6 CE 3C B3 A5 66 30 08 33 49 4A F0 F5 9A 28 D7 CD 0A 97 8D 5E C2 C8 31 E0 E8 96 8F 47 5D 87 76 22 C0 FE F3 DD 90 61 05 10 F3 7B EC 91 14 0F }
	$ayn = { 55 3C 32 26 85 60 0E 5B F5 59 1B FA A9 C1 46 1A FA 8F 4C 7C A1 45 E2 A9 D7 55 29 DB 59 51 CA 65 C2 AF 35 CE 76 0A DB 05 45 3D 11 A9 7E C7 EA 81 0D 0A AC B6 8A F8 8E 52 FF E3 7B 59 53 A2 9E A0 56 CD 48 AC B3 DF 0D 43 6F E4 5C F4 7A A6 B3 C4 5E D0 E2 FB D8 CF CE 4E F0 35 99 B3 10 6F F5 3E C6 19 D6 9C 82 D6 22 0B 69 20 DF 74 0A 46 FD 17 40 ED 10 85 8E CC F8 6C A7 CA 6E 3A BF 24 C8 D6 49 70 81 1A 58 3D 24 61 A2 63 C1 BB B6 AC 8B 04 32 CC 44 7D C2 8A A3 D9 AB 10 F4 AA 5B FF DD 7F 4B 82 04 A8 5A 49 6D AD 94 9F 8C }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$ayk 
	or 	$ayl 
	or 	$aym 
	or 	$ayn 
  ) 
}

rule capa_hash_data_using_SHA224 { 
  meta: 
 	description = "hash data using SHA224 (converted from capa rule)"
	namespace = "data-manipulation/hashing/sha224"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Cryptography::Cryptographic Hash::SHA224 [C0029.004]"
	hash = "6CC148363200798A12091B97A17181A1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/hashing/sha224/hash-data-using-sha224.yml"
	date = "2021-05-15"

  strings: 
 	$num_azc = { D8 9E 05 C1 }
	$num_azd = { 07 D5 7C 36 }
	$num_aze = { 17 DD 70 30 }
	$num_azf = { 39 59 0E F7 }
	$num_azg = { 31 0B C0 FF }
	$num_azh = { 11 15 58 68 }
	$num_azi = { A7 8F F9 64 }
	$num_azj = { A4 4F FA BE }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( $num_azc 
	and $num_azd 
	and $num_aze 
	and $num_azf 
	and $num_azg 
	and $num_azh 
	and $num_azi 
	and $num_azj  ) 
}

rule capa_schedule_task_via_command_line { 
  meta: 
 	description = "schedule task via command line (converted from capa rule)"
	namespace = "persistence/scheduled-tasks"
	author = "0x534a@mailbox.org"
	scope = "function"
	attack = "Persistence::Scheduled Task/Job::Scheduled Task [T1053.005]"
	hash = "79cde1aa711e321b4939805d27e160be"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/scheduled-tasks/schedule-task-via-command-line.yml"
	date = "2021-05-15"

  strings: 
 	$azk = /schtasks/ nocase ascii wide 
	$azl = /\/create / nocase ascii wide 
	$azm = /Register-ScheduledTask / nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_create_process

	and  (  (  (  ( 	$azk 
	and 	$azl  )  ) 
	or 	$azm  )  )  ) 
}

rule capa_persist_via_Windows_service { 
  meta: 
 	description = "persist via Windows service (converted from capa rule)"
	namespace = "persistence/service"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Persistence::Create or Modify System Process::Windows Service [T1543.003]"
	attack = "Execution::System Services::Service Execution [T1569.002]"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x10004706"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/service/persist-via-windows-service.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  strings: 
 	$azp = /\bsc(\.exe)?$/ nocase ascii wide 
	$azq = /create / nocase ascii wide 
	$azr = /\bsc(\.exe)? create/ nocase ascii wide 
	$azs = /New-Service / nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_create_process

	and  (  (  (  ( 	$azp 
	and 	$azq  )  ) 
	or 	$azr 
	or 	$azs  )  )  )  )  ) 
}

rule capa_persist_via_Active_Setup_registry_key { 
  meta: 
 	description = "persist via Active Setup registry key (converted from capa rule)"
	namespace = "persistence/registry"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Persistence::Boot or Logon Autostart Execution::Active Setup [T1547.014]"
	references = "https://www.fireeye.com/blog/threat-research/2017/02/spear_phishing_techn.html"
	hash = "c335a9d41185a32ad918c5389ee54235"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/persist-via-active-setup-registry-key.yml"
	date = "2021-05-15"

  strings: 
 	$num_azt = { 02 00 00 80 }
	$azu = /Software\\Microsoft\\Active Setup\\Installed Components/ nocase ascii wide 
	$str_azv = "StubPath" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_set_registry_value

	or $num_azt  )  ) 
	and 	$azu 
	and 	$str_azv  ) 
}

rule capa_persist_via_GinaDLL_registry_key { 
  meta: 
 	description = "persist via GinaDLL registry key (converted from capa rule)"
	namespace = "persistence/registry/ginadll"
	author = "michael.hunhoff@fireye.com"
	scope = "function"
	attack = "Persistence::Event Triggered Execution [T1546]"
	hash = "Practical Malware Analysis Lab 11-01.exe_:0x401000"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/ginadll/persist-via-ginadll-registry-key.yml"
	date = "2021-05-15"

  strings: 
 	$num_azw = { 02 00 00 80 }
	$azx = /SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon/ nocase ascii wide 
	$azy = /GinaDLL/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_set_registry_value

	or $num_azw  )  ) 
	and 	$azx 
	and 	$azy  ) 
}

rule capa_persist_via_AppInit_DLLs_registry_key { 
  meta: 
 	description = "persist via AppInit_DLLs registry key (converted from capa rule)"
	namespace = "persistence/registry/appinitdlls"
	author = "michael.hunhoff@fireye.com"
	scope = "function"
	attack = "Persistence::Event Triggered Execution::AppInit DLLs [T1546.010]"
	references = "https://docs.microsoft.com/en-us/windows/win32/win7appqual/appinit-dlls-in-windows-7-and-windows-server-2008-r2"
	hash = "Practical Malware Analysis Lab 11-02.dll_:0x1000158b"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/appinitdlls/persist-via-appinit_dlls-registry-key.yml"
	date = "2021-05-15"

  strings: 
 	$num_azz = { 02 00 00 80 }
	$baa = /Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows/ nocase ascii wide 
	$bab = /Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows/ nocase ascii wide 
	$bac = /AppInit_DLLs/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_set_registry_value

	or $num_azz  )  ) 
	and  (  ( 	$baa 
	or 	$bab  )  ) 
	and 	$bac  ) 
}

rule capa_persist_via_Run_registry_key { 
  meta: 
 	description = "persist via Run registry key (converted from capa rule)"
	namespace = "persistence/registry/run"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]"
	hash = "Practical Malware Analysis Lab 06-03.exe_:0x401130"
	hash = "b87e9dd18a5533a09d3e48a7a1efbcf6"
	hash = "9ff8e68343cc29c1036650fc153e69f7"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/run/persist-via-run-registry-key.yml"
	date = "2021-05-15"

  strings: 
 	$num_bae = { 01 00 00 80 }
	$num_baf = { 02 00 00 80 }
	$bag = /Software\\Microsoft\\Windows\\CurrentVersion/ nocase ascii wide 
	$bah = /Run/ nocase ascii wide 
	$bai = /Explorer\\Shell Folders/ nocase ascii wide 
	$baj = /User Shell Folders/ nocase ascii wide 
	$bak = /RunServices/ nocase ascii wide 
	$bal = /Policies\\Explorer\\Run/ nocase ascii wide 
	$bam = /Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load/ nocase ascii wide 
	$ban = /System\\CurrentControlSet\\Control\\Session Manager\\BootExecute/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_set_registry_value

	or $num_bae 
	or $num_baf  )  ) 
	and  (  (  (  ( 	$bag 
	and  (  ( 	$bah 
	or 	$bai 
	or 	$baj 
	or 	$bak 
	or 	$bal  )  )  )  ) 
	or 	$bam 
	or 	$ban  )  )  ) 
}

rule capa_persist_via_Winlogon_Helper_DLL_registry_key { 
  meta: 
 	description = "persist via Winlogon Helper DLL registry key (converted from capa rule)"
	namespace = "persistence/registry/winlogon-helper"
	author = "0x534a@mailbox.org"
	scope = "function"
	attack = "Persistence::Boot or Logon Autostart Execution::Winlogon Helper DLL [T1547.004]"
	hash = "9ff8e68343cc29c1036650fc153e69f7"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/winlogon-helper/persist-via-winlogon-helper-dll-registry-key.yml"
	date = "2021-05-15"

  strings: 
 	$num_bao = { 01 00 00 80 }
	$num_bap = { 02 00 00 80 }
	$baq = /Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon/ nocase ascii wide 
	$bar = /Notify/ nocase ascii wide 
	$bas = /Userinit/ nocase ascii wide 
	$bat = /Shell/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_set_registry_value

	or $num_bao 
	or $num_bap  )  ) 
	and 	$baq 
	and  (  ( 	$bar 
	or 	$bas 
	or 	$bat  )  )  ) 
}

rule capa_compiled_to_the__NET_platform { 
  meta: 
 	description = "compiled to the .NET platform (converted from capa rule)"
	namespace = "runtime/dotnet"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	hash = "b9f5bd514485fb06da39beff051b9fdc"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/runtime/dotnet/compiled-to-the-net-platform.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/mscoree/i, /_CorExeMain/) 
	or 	pe.imports(/mscoree/i, /_corexemain/) 
	or 	pe.imports(/mscoree/i, /_CorDllMain/) 
	or 	pe.imports(/mscoree/i, /_cordllmain/)  ) 
}

rule capa_get_COMSPEC_environment_variable { 
  meta: 
 	description = "get COMSPEC environment variable (converted from capa rule)"
	namespace = "host-interaction/environment-variable"
	author = "matthew.williams@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-comspec-environment-variable.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bau = "COMSPEC" ascii wide
	$str_bav = "%COMSPEC%" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_query_environment_variable

	and  (  ( 	$str_bau 
	or 	$str_bav  )  )  ) 
}

rule capa_packed_with_MaskPE { 
  meta: 
 	description = "packed with MaskPE (converted from capa rule)"
	namespace = "anti-analysis/packer/maskpe"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-maskpe.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any baw in pe.sections : ( baw.name == ".MaskPE" )  ) 
}

rule capa_add_file_to_cabinet_file { 
  meta: 
 	description = "add file to cabinet file (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	references = "https://docs.microsoft.com/en-us/windows/win32/msi/cabinet-files"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/add-file-to-cabinet-file.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/cabinet/i, /FCIAddFile/)  ) 
}

rule capa_reference_Quad9_DNS_server { 
  meta: 
 	description = "reference Quad9 DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.techradar.com/news/best-dns-server"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-quad9-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bax = "9.9.9.9" ascii wide
	$str_bay = "149.112.112.112" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bax 
	or 	$str_bay  ) 
}

rule capa_run_PowerShell_expression { 
  meta: 
 	description = "run PowerShell expression (converted from capa rule)"
	namespace = "load-code/powershell/"
	author = "anamaria.martinezgom@fireeye.com"
	scope = "function"
	attack = "Execution::Command and Scripting Interpreter::PowerShell [T1059.001]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/run-powershell-expression.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$baz = / iex\(/ nocase ascii wide 
	$bba = / iex / nocase ascii wide 
	$bbb = /Invoke-Expression/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$baz 
	or 	$bba 
	or 	$bbb  )  )  ) 
}

rule capa_get_file_size { 
  meta: 
 	description = "get file size (converted from capa rule)"
	namespace = "host-interaction/file-system/meta"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::File and Directory Discovery [T1083]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-file-size.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /GetFileSize/) 
	or 	pe.imports(/kernel32/i, /GetFileSizeEx/)  ) 
}

rule capa_open_cabinet_file { 
  meta: 
 	description = "open cabinet file (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	references = "https://docs.microsoft.com/en-us/windows/win32/msi/cabinet-files"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/open-cabinet-file.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/cabinet/i, /FCICreate/)  ) 
}

rule capa_packed_with_Dragon_Armor { 
  meta: 
 	description = "packed with Dragon Armor (converted from capa rule)"
	namespace = "anti-analysis/packer/dragon-armor"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-dragon-armor.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bbc in pe.sections : ( bbc.name == "DAStub" )  ) 
}

rule capa_hooked_by_API_Override { 
  meta: 
 	description = "hooked by API Override (converted from capa rule)"
	namespace = "executable/hooked/api-override"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
	references = "http://jacquelin.potier.free.fr/winapioverride32/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/hooked-by-api-override.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bbd in pe.sections : ( bbd.name == ".winapi" )  ) 
}

rule capa_get_service_handle { 
  meta: 
 	description = "get service handle (converted from capa rule)"
	author = "moritz.raabe@fireeye.com"
	lib = "True"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-service-handle.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /CreateService/) 
	or 	pe.imports(/advapi32/i, /OpenService/)  ) 
}

rule capa_packed_with_Neolite { 
  meta: 
 	description = "packed with Neolite (converted from capa rule)"
	namespace = "anti-analysis/packer/neolite"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-neolite.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bbe in pe.sections : ( bbe.name == ".neolite" ) 
	or 	for any bbf in pe.sections : ( bbf.name == ".neolit" )  ) 
}

rule capa_encrypt_data_using_Salsa20_or_ChaCha { 
  meta: 
 	description = "encrypt data using Salsa20 or ChaCha (converted from capa rule)"
	namespace = "data-manipulation/encryption/salsa20"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	references = "http://cr.yp.to/snuffle/ecrypt.c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/encrypt-data-using-salsa20-or-chacha.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bbg = "expand 32-byte k = sigma" ascii wide
	$str_bbh = "expand 16-byte k = tau" ascii wide
	$str_bbi = "expand 32-byte kexpand 16-byte k" ascii wide
	$str_bbj = "expa" ascii wide
	$str_bbk = "nd 3" ascii wide
	$str_bbl = "2-by" ascii wide
	$str_bbm = "te k" ascii wide
	$num_bbn = { 65 78 70 61 }
	$num_bbo = { 6E 64 20 33 }
	$num_bbp = { 32 2D 62 79 }
	$num_bbq = { 74 65 20 6B }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bbg 
	or 	$str_bbh 
	or 	$str_bbi 
	or  (  ( 	$str_bbj 
	and 	$str_bbk 
	and 	$str_bbl 
	and 	$str_bbm  )  ) 
	or  (  ( $num_bbn 
	and $num_bbo 
	and $num_bbp 
	and $num_bbq  )  )  ) 
}

rule capa_create_container { 
  meta: 
 	description = "create container (converted from capa rule)"
	namespace = "host-interaction/container/docker"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Execution::Deploy Container [T1610]"
	references = "https://docs.docker.com/engine/api/v1.24/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/create-container.yml"
	capa_nursery = "True"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  strings: 
 	$bbr = /\bdocker(\.exe)? create/ ascii wide 
	$bbs = /\bdocker(\.exe)? start/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bbr 
	or 	$bbs 
  ) 
}

rule capa_listen_for_remote_procedure_calls { 
  meta: 
 	description = "listen for remote procedure calls (converted from capa rule)"
	namespace = "communication/rpc/server"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/listen-for-remote-procedure-calls.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/rpcrt4/i, /RpcServerListen/)  ) 
}

rule capa_enumerate_internet_cache { 
  meta: 
 	description = "enumerate internet cache (converted from capa rule)"
	namespace = "host-interaction/internet/cache"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/enumerate-internet-cache.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/wininet/i, /FindFirstUrlCacheEntry/)  ) 
}

rule capa_reference_Verisign_DNS_server { 
  meta: 
 	description = "reference Verisign DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.techradar.com/news/best-dns-server"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-verisign-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bbt = "64.6.64.6" ascii wide
	$str_bbu = "64.6.65.6" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bbt 
	or 	$str_bbu  ) 
}

rule capa_packaged_as_a_NSIS_installer { 
  meta: 
 	description = "packaged as a NSIS installer (converted from capa rule)"
	namespace = "executable/installer/nsis"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	references = "https://nsis.sourceforge.io/Main_Page"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-nsis-installer.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$bbv = /http:\/\/nsis\.sf\.net/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bbv  ) 
}

rule capa_reference_AliDNS_DNS_server { 
  meta: 
 	description = "reference AliDNS DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.alidns.com/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-alidns-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bbw = "223.5.5.5" ascii wide
	$str_bbx = "223.6.6.6" ascii wide
	$str_bby = "2400:3200::1" ascii wide
	$str_bbz = "2400:3200:baba::1" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bbw 
	or 	$str_bbx 
	or 	$str_bby 
	or 	$str_bbz  ) 
}

rule capa_get_networking_parameters { 
  meta: 
 	description = "get networking parameters (converted from capa rule)"
	namespace = "host-interaction/network"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-networking-parameters.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/iphlpapi/i, /GetNetworkParams/)  ) 
}

rule capa_packed_with_TSULoader { 
  meta: 
 	description = "packed with TSULoader (converted from capa rule)"
	namespace = "anti-analysis/packer/tsuloader"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-tsuloader.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bce in pe.sections : ( bce.name == ".tsuarch" ) 
	or 	for any bcf in pe.sections : ( bcf.name == ".tsustub" )  ) 
}

rule capa_packaged_as_a_WinZip_self_extracting_archive { 
  meta: 
 	description = "packaged as a WinZip self-extracting archive (converted from capa rule)"
	namespace = "executable/installer/winzip"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-winzip-self-extracting-archive.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bcg in pe.sections : ( bcg.name == "_winzip_" )  ) 
}

rule capa_list_containers { 
  meta: 
 	description = "list containers (converted from capa rule)"
	namespace = "host-interaction/container/docker"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Discovery::Container and Resource Discovery [T1609]"
	references = "https://docs.docker.com/engine/api/v1.24/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/list-containers.yml"
	capa_nursery = "True"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  strings: 
 	$bch = /\bdocker(\.exe)? ps/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bch 
  ) 
}

rule capa_get_file_version_info { 
  meta: 
 	description = "get file version info (converted from capa rule)"
	namespace = "host-interaction/file-system/meta"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::File and Directory Discovery [T1083]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-file-version-info.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/version/i, /GetFileVersionInfo/) 
	or 	pe.imports(/version/i, /GetFileVersionInfoEx/)  )  )  ) 
}

rule capa_packed_with_RPCrypt { 
  meta: 
 	description = "packed with RPCrypt (converted from capa rule)"
	namespace = "anti-analysis/packer/rpcrypt"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-rpcrypt.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bck in pe.sections : ( bck.name == "RCryptor" ) 
	or 	for any bcl in pe.sections : ( bcl.name == ".RCrypt" )  ) 
}

rule capa_get_proxy { 
  meta: 
 	description = "get proxy (converted from capa rule)"
	namespace = "host-interaction/network/proxy"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-proxy.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bcm = "ProxyServer" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_create_or_open_registry_key

	and 	$str_bcm  ) 
}

rule capa_reference_DNS_over_HTTPS_endpoints { 
  meta: 
 	description = "reference DNS over HTTPS endpoints (converted from capa rule)"
	namespace = "communication/dns"
	author = "markus.neis@swisscom.com / @markus_neis"
	scope = "file"
	references = "https://github.com/curl/curl/wiki/DNS-over-HTTPS"
	hash = "749e7becf00fccc6dff324a83976dc0d"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-dns-over-https-endpoints.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$bcn = /https:\/\/doh.seby.io:8443\/dns-query.{,1000}/ nocase ascii wide 
	$bco = /https:\/\/family.cloudflare-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$bcp = /https:\/\/free.bravedns.com\/dns-query.{,1000}/ nocase ascii wide 
	$bcq = /https:\/\/doh.familyshield.opendns.com\/dns-query.{,1000}/ nocase ascii wide 
	$bcr = /https:\/\/doh-de.blahdns.com\/dns-query.{,1000}/ nocase ascii wide 
	$bcs = /https:\/\/adblock.mydns.network\/dns-query.{,1000}/ nocase ascii wide 
	$bct = /https:\/\/bravedns.com\/configure.{,1000}/ nocase ascii wide 
	$bcu = /https:\/\/cloudflare-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$bcv = /https:\/\/commons.host.{,1000}/ nocase ascii wide 
	$bcw = /https:\/\/dns.aa.net.uk\/dns-query.{,1000}/ nocase ascii wide 
	$bcx = /https:\/\/dns.alidns.com\/dns-query.{,1000}/ nocase ascii wide 
	$bcy = /https:\/\/dns-asia.wugui.zone\/dns-query.{,1000}/ nocase ascii wide 
	$bcz = /https:\/\/dns.containerpi.com\/dns-query.{,1000}/ nocase ascii wide 
	$bda = /https:\/\/dns.containerpi.com\/doh\/family-filter\/.{,1000}/ nocase ascii wide 
	$bdb = /https:\/\/dns.containerpi.com\/doh\/secure-filter\/.{,1000}/ nocase ascii wide 
	$bdc = /https:\/\/dns.digitale-gesellschaft.ch\/dns-query.{,1000}/ nocase ascii wide 
	$bdd = /https:\/\/dns.dnshome.de\/dns-query.{,1000}/ nocase ascii wide 
	$bde = /https:\/\/dns.dns-over-https.com\/dns-query.{,1000}/ nocase ascii wide 
	$bdf = /https:\/\/dns.dnsoverhttps.net\/dns-query.{,1000}/ nocase ascii wide 
	$bdg = /https:\/\/dns.flatuslifir.is\/dns-query.{,1000}/ nocase ascii wide 
	$bdh = /https:\/\/dnsforge.de\/dns-query.{,1000}/ nocase ascii wide 
	$bdi = /https:\/\/dns.google\/dns-query.{,1000}/ nocase ascii wide 
	$bdj = /https:\/\/dns.nextdns.io\/<config_id>.{,1000}/ nocase ascii wide 
	$bdk = /https:\/\/dns.rubyfish.cn\/dns-query.{,1000}/ nocase ascii wide 
	$bdl = /https:\/\/dns.switch.ch\/dns-query.{,1000}/ nocase ascii wide 
	$bdm = /https:\/\/dns.twnic.tw\/dns-query.{,1000}/ nocase ascii wide 
	$bdn = /https:\/\/dns.wugui.zone\/dns-query.{,1000}/ nocase ascii wide 
	$bdo = /https:\/\/doh-2.seby.io\/dns-query.{,1000}/ nocase ascii wide 
	$bdp = /https:\/\/doh.42l.fr\/dns-query.{,1000}/ nocase ascii wide 
	$bdq = /https:\/\/doh.applied-privacy.net\/query.{,1000}/ nocase ascii wide 
	$bdr = /https:\/\/doh.armadillodns.net\/dns-query.{,1000}/ nocase ascii wide 
	$bds = /https:\/\/doh.captnemo.in\/dns-query.{,1000}/ nocase ascii wide 
	$bdt = /https:\/\/doh.centraleu.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$bdu = /https:\/\/doh.cleanbrowsing.org\/doh\/family-filter\/.{,1000}/ nocase ascii wide 
	$bdv = /https:\/\/doh.crypto.sx\/dns-query.{,1000}/ nocase ascii wide 
	$bdw = /https:\/\/doh.dnslify.com\/dns-query.{,1000}/ nocase ascii wide 
	$bdx = /https:\/\/doh.dns.sb\/dns-query.{,1000}/ nocase ascii wide 
	$bdy = /https:\/\/dohdot.coxlab.net\/dns-query.{,1000}/ nocase ascii wide 
	$bdz = /https:\/\/doh.eastas.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$bea = /https:\/\/doh.eastau.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$beb = /https:\/\/doh.eastus.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$bec = /https:\/\/doh.ffmuc.net\/dns-query.{,1000}/ nocase ascii wide 
	$bed = /https:\/\/doh.libredns.gr\/dns-query.{,1000}/ nocase ascii wide 
	$bee = /https:\/\/doh.li\/dns-query.{,1000}/ nocase ascii wide 
	$bef = /https:\/\/doh.northeu.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$beg = /https:\/\/doh.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$beh = /https:\/\/doh.powerdns.org.{,1000}/ nocase ascii wide 
	$bei = /https:\/\/doh.tiarap.org\/dns-query.{,1000}/ nocase ascii wide 
	$bej = /https:\/\/doh.tiar.app\/dns-query.{,1000}/ nocase ascii wide 
	$bek = /https:\/\/doh.westus.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$bel = /https:\/\/doh.xfinity.com\/dns-query.{,1000}/ nocase ascii wide 
	$bem = /https:\/\/example.doh.blockerdns.com\/dns-query.{,1000}/ nocase ascii wide 
	$ben = /https:\/\/fi.doh.dns.snopyta.org\/dns-query.{,1000}/ nocase ascii wide 
	$beo = /https:\/\/ibksturm.synology.me\/dns-query.{,1000}/ nocase ascii wide 
	$bep = /https:\/\/ibuki.cgnat.net\/dns-query.{,1000}/ nocase ascii wide 
	$beq = /https:\/\/jcdns.fun\/dns-query.{,1000}/ nocase ascii wide 
	$ber = /https:\/\/jp.tiarap.org\/dns-query.{,1000}/ nocase ascii wide 
	$bes = /https:\/\/jp.tiar.app\/dns-query.{,1000}/ nocase ascii wide 
	$bet = /https:\/\/odvr.nic.cz\/doh.{,1000}/ nocase ascii wide 
	$beu = /https:\/\/ordns.he.net\/dns-query.{,1000}/ nocase ascii wide 
	$bev = /https:\/\/rdns.faelix.net\/.{,1000}/ nocase ascii wide 
	$bew = /https:\/\/resolver-eu.lelux.fi\/dns-query.{,1000}/ nocase ascii wide 
	$bex = /https:\/\/doh-jp.blahdns.com\/dns-query.{,1000}/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bcn 
	or 	$bco 
	or 	$bcp 
	or 	$bcq 
	or 	$bcr 
	or 	$bcs 
	or 	$bct 
	or 	$bcu 
	or 	$bcv 
	or 	$bcw 
	or 	$bcx 
	or 	$bcy 
	or 	$bcz 
	or 	$bda 
	or 	$bdb 
	or 	$bdc 
	or 	$bdd 
	or 	$bde 
	or 	$bdf 
	or 	$bdg 
	or 	$bdh 
	or 	$bdi 
	or 	$bdj 
	or 	$bdk 
	or 	$bdl 
	or 	$bdm 
	or 	$bdn 
	or 	$bdo 
	or 	$bdp 
	or 	$bdq 
	or 	$bdr 
	or 	$bds 
	or 	$bdt 
	or 	$bdu 
	or 	$bdv 
	or 	$bdw 
	or 	$bdx 
	or 	$bdy 
	or 	$bdz 
	or 	$bea 
	or 	$beb 
	or 	$bec 
	or 	$bed 
	or 	$bee 
	or 	$bef 
	or 	$beg 
	or 	$beh 
	or 	$bei 
	or 	$bej 
	or 	$bek 
	or 	$bel 
	or 	$bem 
	or 	$ben 
	or 	$beo 
	or 	$bep 
	or 	$beq 
	or 	$ber 
	or 	$bes 
	or 	$bet 
	or 	$beu 
	or 	$bev 
	or 	$bew 
	or 	$bex  ) 
}

rule capa_packed_with_Crunch { 
  meta: 
 	description = "packed with Crunch (converted from capa rule)"
	namespace = "anti-analysis/packer/crunch"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-crunch.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bey in pe.sections : ( bey.name == "BitArts" )  ) 
}

rule capa_delete_registry_key_via_offline_registry_library { 
  meta: 
 	description = "delete registry key via offline registry library (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "johnk3r"
	scope = "function"
	attack = "Defense Evasion::Modify Registry [T1112]"
	mbc = "Operating System::Registry::Delete Registry Key [C0036.002]"
	mbc = "Operating System::Registry::Delete Registry Value [C0036.007]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/delete-registry-key-via-offline-registry-library.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$api_bez = "ORDeleteKey" ascii wide
	$api_bfa = "ORDeleteValue" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_bez 
	or 	$api_bfa  ) 
}

rule capa_get_token_membership { 
  meta: 
 	description = "get token membership (converted from capa rule)"
	namespace = "host-interaction/session"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Owner/User Discovery [T1033]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-token-membership.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /CheckTokenMembership/)  ) 
}

rule capa_packed_with_PECompact { 
  meta: 
 	description = "packed with PECompact (converted from capa rule)"
	namespace = "anti-analysis/packer/pecompact"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-pecompact.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bfb in pe.sections : ( bfb.name == "PEC2TO" ) 
	or 	for any bfc in pe.sections : ( bfc.name == "PEC2" ) 
	or 	for any bfd in pe.sections : ( bfd.name == "pec" ) 
	or 	for any bfe in pe.sections : ( bfe.name == "pec1" ) 
	or 	for any bff in pe.sections : ( bff.name == "pec2" ) 
	or 	for any bfg in pe.sections : ( bfg.name == "pec3" ) 
	or 	for any bfh in pe.sections : ( bfh.name == "pec4" ) 
	or 	for any bfi in pe.sections : ( bfi.name == "pec5" ) 
	or 	for any bfj in pe.sections : ( bfj.name == "pec6" ) 
	or 	for any bfk in pe.sections : ( bfk.name == "PEC2MO" )  ) 
}

rule capa_packaged_as_a_CreateInstall_installer { 
  meta: 
 	description = "packaged as a CreateInstall installer (converted from capa rule)"
	namespace = "executable/installer/createinstall"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.createinstall.com/"
	references = "https://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-createinstall-installer.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bfm in pe.sections : ( bfm.name == ".gentee" )  ) 
}

rule capa_packed_with_Pepack { 
  meta: 
 	description = "packed with Pepack (converted from capa rule)"
	namespace = "anti-analysis/packer/pepack"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-pepack.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bfn in pe.sections : ( bfn.name == "PEPACK!!" )  ) 
}

rule capa_reference_Google_Public_DNS_server { 
  meta: 
 	description = "reference Google Public DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.techradar.com/news/best-dns-server"
	references = "https://developers.google.com/speed/public-dns/docs/using"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-google-public-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bfs = "8.8.8.8" ascii wide
	$str_bft = "8.8.4.4" ascii wide
	$str_bfu = "2001:4860:4860::8888" ascii wide
	$str_bfv = "2001:4860:4860::8844" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bfs 
	or 	$str_bft 
	or 	$str_bfu 
	or 	$str_bfv  ) 
}

rule capa_linked_against_C___regex_library { 
  meta: 
 	description = "linked against C++ regex library (converted from capa rule)"
	namespace = "linking/static/cppregex"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-c-regex-library.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bfw = "regex_error(error_syntax)" ascii wide
	$str_bfx = "regex_error(error_collate): The expression contained an invalid collating element name." ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bfw 
	or 	$str_bfx  ) 
}

rule capa_packed_with_MEW { 
  meta: 
 	description = "packed with MEW (converted from capa rule)"
	namespace = "anti-analysis/packer/mew"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-mew.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bgc in pe.sections : ( bgc.name == "MEW" )  ) 
}

rule capa_reference_114DNS_DNS_server { 
  meta: 
 	description = "reference 114DNS DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.114dns.com/"
	references = "https://www.amazon.com/ask/questions/Tx27CUHKMM403NP"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-114dns-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bgd = "114.114.114.114" ascii wide
	$str_bge = "114.114.115.115" ascii wide
	$str_bgf = "114.114.114.119" ascii wide
	$str_bgg = "114.114.115.119" ascii wide
	$str_bgh = "114.114.114.110" ascii wide
	$str_bgi = "114.114.115.110" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bgd 
	or 	$str_bge 
	or 	$str_bgf 
	or 	$str_bgg 
	or 	$str_bgh 
	or 	$str_bgi  ) 
}

rule capa_migrate_process_to_active_window_station { 
  meta: 
 	description = "migrate process to active window station (converted from capa rule)"
	namespace = "host-interaction/gui/window-station"
	author = "william.ballenthin@fireeye.com"
	description = "set process to the active window station so it can receive GUI events. commonly seen in keyloggers."
	scope = "function"
	references = "https://www.installsetupconfig.com/win32programming/windowstationsdesktops13_1.html"
	references = "https://brianbondy.com/blog/100/understanding-windows-at-a-deeper-level-sessions-window-stations-and-desktops"
	references = "https://cboard.cprogramming.com/windows-programming/144588-[win7]-setwindowshookex-windows-service-setthreaddesktop.html"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/migrate-process-to-active-window-station.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$api_bgk = "OpenWindowStation" ascii wide
	$str_bgl = "winsta0" ascii wide
	$str_bgm = "WinSta0" ascii wide
	$api_bgn = "SetProcessWindowStation" ascii wide
	$api_bgo = "OpenInputDesktop" ascii wide
	$api_bgp = "SetThreadDesktop" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_bgk 
	and  (  ( 	$str_bgl 
	or 	$str_bgm  )  ) 
	and 	$api_bgn 
	and 	$api_bgo 
	and 	$api_bgp  ) 
}

rule capa_packed_with_Epack { 
  meta: 
 	description = "packed with Epack (converted from capa rule)"
	namespace = "anti-analysis/packer/epack"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-epack.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bgq in pe.sections : ( bgq.name == "!Epack" )  ) 
}

rule capa_packaged_as_a_Pintool { 
  meta: 
 	description = "packaged as a Pintool (converted from capa rule)"
	namespace = "executable/pintool"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://software.intel.com/content/www/us/en/develop/articles/pin-a-dynamic-binary-instrumentation-tool.html"
	references = "https://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
	references = "https://www.blackhat.com/docs/asia-16/materials/asia-16-Sun-Break-Out-Of-The-Truman-Show-Active-Detection-And-Escape-Of-Dynamic-Binary-Instrumentation.pdf"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-pintool.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bgr in pe.sections : ( bgr.name == ".charmve" ) 
	or 	for any bgs in pe.sections : ( bgs.name == ".pinclie" )  ) 
}

rule capa_get_thread_local_storage_value { 
  meta: 
 	description = "get thread local storage value (converted from capa rule)"
	namespace = "host-interaction/process"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-thread-local-storage-value.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /TlsGetValue/)  ) 
}

rule capa_rebuilt_by_ImpRec { 
  meta: 
 	description = "rebuilt by ImpRec (converted from capa rule)"
	namespace = "executable/imprec"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/rebuilt-by-imprec.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bgu in pe.sections : ( bgu.name == ".mackt" )  ) 
}

rule capa_enumerate_threads { 
  meta: 
 	description = "enumerate threads (converted from capa rule)"
	namespace = "host-interaction/thread/list"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/enumerate-threads.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /Thread32First/) 
	and 	pe.imports(/kernel32/i, /Thread32Next/)  ) 
}

rule capa_reference_Comodo_Secure_DNS_server { 
  meta: 
 	description = "reference Comodo Secure DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.techradar.com/news/best-dns-server"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-comodo-secure-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bgv = "8.26.56.26" ascii wide
	$str_bgw = "8.20.247.20" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bgv 
	or 	$str_bgw  ) 
}

rule capa_build_Docker_image { 
  meta: 
 	description = "build Docker image (converted from capa rule)"
	namespace = "host-interaction/container/docker"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Build Image on Host [T1612]"
	references = "https://docs.docker.com/engine/api/v1.24/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/build-docker-image.yml"
	capa_nursery = "True"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  strings: 
 	$bgx = /\bdocker(\.exe)? build/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bgx 
  ) 
}

rule capa_decrypt_data_via_SSPI { 
  meta: 
 	description = "decrypt data via SSPI (converted from capa rule)"
	namespace = "data-manipulation/encryption"
	author = "matthew.williams@fireeye.com"
	scope = "basic block"
	attack = "Defense Evasion::Deobfuscate/Decode Files or Information [T1140]"
	references = "https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-decryptmessage"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/decrypt-data-via-sspi.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/secur32/i, /DecryptMessage/)  ) 
}

rule capa_reference_L3_DNS_server { 
  meta: 
 	description = "reference L3 DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.quora.com/What-is-a-4-2-2-1-DNS-server"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-l3-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bgy = "4.2.2.1" ascii wide
	$str_bgz = "4.2.2.2" ascii wide
	$str_bha = "4.2.2.3" ascii wide
	$str_bhb = "4.2.2.4" ascii wide
	$str_bhc = "4.2.2.5" ascii wide
	$str_bhd = "4.2.2.6" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bgy 
	or 	$str_bgz 
	or 	$str_bha 
	or 	$str_bhb 
	or 	$str_bhc 
	or 	$str_bhd  ) 
}

rule capa_packaged_as_a_Wise_installer { 
  meta: 
 	description = "packaged as a Wise installer (converted from capa rule)"
	namespace = "executable/installer/wiseinstall"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-wise-installer.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bhe = "WiseMain" ascii wide
	$bhf = /Wise Installation Wizard/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bhe 
	or 	$bhf  ) 
}

rule capa_run_in_container { 
  meta: 
 	description = "run in container (converted from capa rule)"
	namespace = "host-interaction/container/docker"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Execution::Container Administration Command [T1609]"
	references = "https://docs.docker.com/engine/api/v1.24/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/run-in-container.yml"
	capa_nursery = "True"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  strings: 
 	$bhg = /\bdocker(\.exe)? exec/ ascii wide 
	$bhh = /\bkubectl(\.exe)? exec/ ascii wide 
	$bhi = /\bkubectl(\.exe)? run/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bhg 
	or 	$bhh 
	or 	$bhi 
  ) 
}

rule capa_acquire_debug_privileges { 
  meta: 
 	description = "acquire debug privileges (converted from capa rule)"
	namespace = "host-interaction/process/modify"
	author = "william.ballenthin@fireeye.com"
	scope = "basic block"
	attack = "Privilege Escalation::Access Token Manipulation [T1134]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/acquire-debug-privileges.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bhj = "SeDebugPrivilege" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bhj  ) 
}

rule capa_empty_the_recycle_bin { 
  meta: 
 	description = "empty the recycle bin (converted from capa rule)"
	namespace = "host-interaction/recycle-bin"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/empty-the-recycle-bin.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$api_bhk = "SHEmptyRecycleBin" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_bhk  ) 
}

rule capa_compare_security_identifiers { 
  meta: 
 	description = "compare security identifiers (converted from capa rule)"
	namespace = "host-interaction/sid"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/compare-security-identifiers.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /EqualSid/)  ) 
}

rule capa_query_remote_server_for_available_data { 
  meta: 
 	description = "query remote server for available data (converted from capa rule)"
	namespace = "communication"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/query-remote-server-for-available-data.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/wininet/i, /InternetQueryDataAvailable/)  ) 
}

rule capa_packed_with_enigma { 
  meta: 
 	description = "packed with enigma (converted from capa rule)"
	namespace = "anti-analysis/packer/enigma"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-enigma.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bhl in pe.sections : ( bhl.name == ".enigma1" ) 
	or 	for any bhm in pe.sections : ( bhm.name == ".enigma2" )  ) 
}

rule capa_initialize_hashing_via_WinCrypt { 
  meta: 
 	description = "initialize hashing via WinCrypt (converted from capa rule)"
	namespace = "data-manipulation/hashing"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/initialize-hashing-via-wincrypt.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /CryptCreateHash/)  ) 
}

rule capa_packed_with_StarForce { 
  meta: 
 	description = "packed with StarForce (converted from capa rule)"
	namespace = "anti-analysis/packer/starforce"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-starforce.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bhn in pe.sections : ( bhn.name == ".sforce3" )  ) 
}

rule capa_encrypt_data_via_SSPI { 
  meta: 
 	description = "encrypt data via SSPI (converted from capa rule)"
	namespace = "data-manipulation/encryption"
	author = "matthew.williams@fireeye.com"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	references = "https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-encryptmessage"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/encrypt-data-via-sspi.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/secur32/i, /EncryptMessage/)  ) 
}

rule capa_packed_with_ProCrypt { 
  meta: 
 	description = "packed with ProCrypt (converted from capa rule)"
	namespace = "anti-analysis/packer/procrypt"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-procrypt.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bho in pe.sections : ( bho.name == "ProCrypt" )  ) 
}

rule capa_packed_with_WWPACK { 
  meta: 
 	description = "packed with WWPACK (converted from capa rule)"
	namespace = "anti-analysis/packer/wwpack"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-wwpack.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bhp in pe.sections : ( bhp.name == ".WWPACK" ) 
	or 	for any bhq in pe.sections : ( bhq.name == ".WWP32" )  ) 
}

rule capa_reference_Cloudflare_DNS_server { 
  meta: 
 	description = "reference Cloudflare DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.techradar.com/news/best-dns-server"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-cloudflare-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bhr = "1.1.1.1" ascii wide
	$str_bhs = "1.0.0.1" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bhr 
	or 	$str_bhs  ) 
}

rule capa_get_system_firmware_table { 
  meta: 
 	description = "get system firmware table (converted from capa rule)"
	namespace = "host-interaction/hardware/firmware"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/Shared/Utils.cpp#L854"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-system-firmware-table.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /GetSystemFirmwareTable/)  ) 
}

rule capa_get_socket_information { 
  meta: 
 	description = "get socket information (converted from capa rule)"
	namespace = "communication/socket"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-socket-information.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ws2_32/i, /getsockname/)  ) 
}

rule capa_check_license_value { 
  meta: 
 	description = "check license value (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Generic.cpp#L1224"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/check-license-value.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$api_bht = "NtQueryLicenseValue" ascii wide
	$str_bhu = "Kernel-VMDetection-Private" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_bht 
	and 	$str_bhu  ) 
}

rule capa_bypass_UAC_via_ICMLuaUtil { 
  meta: 
 	description = "bypass UAC via ICMLuaUtil (converted from capa rule)"
	namespace = "host-interaction/uac/bypass"
	author = "anamaria.martinezgom@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Abuse Elevation Control Mechanism::Bypass User Access Control [T1548.002]"
	references = "https://gist.github.com/hfiref0x/196af729106b780db1c73428b5a5d68d"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/bypass-uac-via-icmluautil.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bhv = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide
	$bhw = { F9 C7 5F 3E 51 9A 67 43 90 63 A1 20 24 4F BE C7 }
	$str_bhx = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_bhv 
	or 	$bhw  )  ) 
	and 	$str_bhx  ) 
}

rule capa_reference_screen_saver_executable { 
  meta: 
 	description = "reference screen saver executable (converted from capa rule)"
	namespace = "persistence/screensaver"
	author = "michael.hunhoff@fireeye.com"
	description = "SCRNSAVE.EXE registry value specifies the name of the screen saver executable file"
	scope = "function"
	attack = "Persistence::Event Triggered Execution::Screensaver [T1546.002]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-screen-saver-executable.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bhy = "SCRNSAVE.EXE" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bhy  ) 
}

rule capa_create_Restart_Manager_session { 
  meta: 
 	description = "create Restart Manager session (converted from capa rule)"
	namespace = "host-interaction/process"
	author = "michael.hunhoff@fireeye.com"
	description = "Windows Restart Manager can be used to close/unlock specific files, often abused by Ransomware"
	scope = "function"
	references = "https://www.carbonblack.com/blog/tau-threat-discovery-conti-ransomware/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/create-restart-manager-session.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/rstrtmgr/i, /RmStartSession/)  ) 
}

rule capa_reference_kornet_DNS_server { 
  meta: 
 	description = "reference kornet DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://whatismyipaddress.com/ip/168.126.63.1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-kornet-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bhz = "168.126.63.1" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bhz  ) 
}

rule capa_packed_with_Themida { 
  meta: 
 	description = "packed with Themida (converted from capa rule)"
	namespace = "anti-analysis/packer/themida"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-themida.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bia in pe.sections : ( bia.name == "Themida" ) 
	or 	for any bib in pe.sections : ( bib.name == ".Themida" ) 
	or 	for any bic in pe.sections : ( bic.name == "WinLicen" )  ) 
}

rule capa_impersonate_user { 
  meta: 
 	description = "impersonate user (converted from capa rule)"
	namespace = "host-interaction/user"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Privilege Escalation::Access Token Manipulation::Token Impersonation/Theft [T1134.001]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/impersonate-user.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /LogonUser/) 
	or  (  ( 	pe.imports(/userenv/i, /LoadUserProfile/)  )  )  ) 
}

rule capa_get_user_security_identifier { 
  meta: 
 	description = "get user security identifier (converted from capa rule)"
	namespace = "host-interaction/sid"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	attack = "Discovery::Account Discovery [T1087]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-user-security-identifier.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/advapi32/i, /LookupAccountName/) 
	or 	pe.imports(/advapi32/i, /LsaLookupNames/) 
	or 	pe.imports(/advapi32/i, /LsaLookupNames2/)  ) 
}

rule capa_read_raw_disk_data { 
  meta: 
 	description = "read raw disk data (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/read-raw-disk-data.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bid = "\\\\.\\PhysicalDrive0" ascii wide
	$str_bie = "\\\\.\\C:" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bid 
	or 	$str_bie  ) 
}

rule capa_bypass_UAC_via_scheduled_task_environment_variable { 
  meta: 
 	description = "bypass UAC via scheduled task environment variable (converted from capa rule)"
	namespace = "host-interaction/uac/bypass"
	author = "anamaria.martinezgom@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Abuse Elevation Control Mechanism::Bypass User Access Control [T1548.002]"
	references = "https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.html"
	references = "https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/bypass-uac-via-scheduled-task-environment-variable.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bif = "schtasks.exe" ascii wide
	$big = /Microsoft\\Windows\\DiskCleanup\\SilentCleanup/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bif 
	and 	$big 
	and 	capa_create_process
 ) 
}

rule capa_reference_AES_constants { 
  meta: 
 	description = "reference AES constants (converted from capa rule)"
	namespace = "data-manipulation/encryption/aes"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-aes-constants.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$bil = { 50 A7 F4 51 53 65 41 7E }
	$bim = { 63 7C 77 7B F2 6B 6F C5 }
	$bin = { 52 09 6A D5 30 36 A5 38 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bil 
	or 	$bim 
	or 	$bin  ) 
}

rule capa_compiled_with_Nim { 
  meta: 
 	description = "compiled with Nim (converted from capa rule)"
	namespace = "compiler/nim"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/compiled-with-nim.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$bio = /NimMain/ ascii wide 
	$bip = /NimMainModule/ ascii wide 
	$biq = /NimMainInner/ ascii wide 
	$bir = /io.nim$/ ascii wide 
	$bis = /fatal.nim$/ ascii wide 
	$bit = /system.nim$/ ascii wide 
	$biu = /alloc.nim$/ ascii wide 
	$biv = /osalloc.nim$/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bio 
	or 	$bip 
	or 	$biq 
	or 	$bir 
	or 	$bis 
	or 	$bit 
	or 	$biu 
	or 	$biv  ) 
}

rule capa_hook_routines_via_microsoft_detours { 
  meta: 
 	description = "hook routines via microsoft detours (converted from capa rule)"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/Flare-On%202017/Challenge7.pdf"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/hook-routines-via-microsoft-detours.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$num_biw = { 64 74 72 52 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( $num_biw  ) 
}

rule capa_packed_with_SVKP { 
  meta: 
 	description = "packed with SVKP (converted from capa rule)"
	namespace = "anti-analysis/packer/svkp"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-svkp.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bix in pe.sections : ( bix.name == ".svkp" )  ) 
}

rule capa_flush_cabinet_file { 
  meta: 
 	description = "flush cabinet file (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	references = "https://docs.microsoft.com/en-us/windows/win32/msi/cabinet-files"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/flush-cabinet-file.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/cabinet/i, /FCIFlushFolder/) 
	or 	pe.imports(/cabinet/i, /FCIFlushCabinet/)  ) 
}

rule capa_enumerate_system_firmware_tables { 
  meta: 
 	description = "enumerate system firmware tables (converted from capa rule)"
	namespace = "host-interaction/hardware/firmware"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/Shared/Utils.cpp#L843"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/enumerate-system-firmware-tables.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /EnumSystemFirmwareTables/)  ) 
}

rule capa_reference_startup_folder { 
  meta: 
 	description = "reference startup folder (converted from capa rule)"
	namespace = "persistence/startup-folder"
	author = "matthew.williams@fireeye.com"
	scope = "file"
	attack = "Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-startup-folder.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$biy = /Start Menu\\Programs\\Startup/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$biy  ) 
}

rule capa_encrypt_or_decrypt_data_via_BCrypt { 
  meta: 
 	description = "encrypt or decrypt data via BCrypt (converted from capa rule)"
	namespace = "data-manipulation/encryption"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Cryptography::Decrypt Data [C0031]"
	mbc = "Cryptography::Encrypt Data [C0027]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/encrypt-or-decrypt-data-via-bcrypt.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$api_biz = "BCryptDecrypt" ascii wide
	$api_bja = "BCryptEncrypt" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$api_biz 
	or 	$api_bja  )  )  ) 
}

rule capa_connect_network_resource { 
  meta: 
 	description = "connect network resource (converted from capa rule)"
	namespace = "communication/http"
	author = "michael.hunhoff@fireeye.com"
	description = "connect to disk or print resource"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/connect-network-resource.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/mpr/i, /WNetAddConnection/) 
	or 	pe.imports(/mpr/i, /WNetAddConnection2/) 
	or 	pe.imports(/mpr/i, /WNetAddConnection3/)  )  )  ) 
}

rule capa_packed_with_Shrinker { 
  meta: 
 	description = "packed with Shrinker (converted from capa rule)"
	namespace = "anti-analysis/packer/shrinker"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-shrinker.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bjc in pe.sections : ( bjc.name == ".shrink1" ) 
	or 	for any bjd in pe.sections : ( bjd.name == ".shrink2" ) 
	or 	for any bje in pe.sections : ( bje.name == ".shrink3" )  ) 
}

rule capa_packed_with_VProtect { 
  meta: 
 	description = "packed with VProtect (converted from capa rule)"
	namespace = "anti-analysis/packer/vprotect"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-vprotect.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bjf in pe.sections : ( bjf.name == "VProtect" )  ) 
}

rule capa_packed_with_CCG { 
  meta: 
 	description = "packed with CCG (converted from capa rule)"
	namespace = "anti-analysis/packer/ccg"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-ccg.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bjg in pe.sections : ( bjg.name == ".ccg" )  ) 
}

rule capa_set_console_window_title { 
  meta: 
 	description = "set console window title (converted from capa rule)"
	namespace = "host-interaction/gui/console"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/set-console-window-title.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /SetConsoleTitle/)  ) 
}

rule capa_get_routing_table { 
  meta: 
 	description = "get routing table (converted from capa rule)"
	namespace = "host-interaction/network/routing-table"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-routing-table.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/iphlpapi/i, /GetIpForwardTable/) 
	or 	pe.imports(/iphlpapi/i, /GetIpForwardTable2/)  ) 
}

rule capa_reference_Hurricane_Electric_DNS_server { 
  meta: 
 	description = "reference Hurricane Electric DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://dns.he.net/"
	references = "https://dnslytics.com/ip/216.66.1.2"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-hurricane-electric-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bjh = "216.218.130.2" ascii wide
	$str_bji = "216.218.131.2" ascii wide
	$str_bjj = "216.218.132.2" ascii wide
	$str_bjk = "216.66.1.2" ascii wide
	$str_bjl = "216.66.80.18" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bjh 
	or 	$str_bji 
	or 	$str_bjj 
	or 	$str_bjk 
	or 	$str_bjl  ) 
}

rule capa_packed_with_Mpress { 
  meta: 
 	description = "packed with Mpress (converted from capa rule)"
	namespace = "anti-analysis/packer/mpress"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-mpress.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bjm in pe.sections : ( bjm.name == ".MPRESS1" ) 
	or 	for any bjn in pe.sections : ( bjn.name == ".MPRESS2" )  ) 
}

rule capa_packaged_as_an_InstallShield_installer { 
  meta: 
 	description = "packaged as an InstallShield installer (converted from capa rule)"
	namespace = "executable/installer/installshield"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-an-installshield-installer.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bjo = "InstallShield" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bjo  ) 
}

rule capa_mine_cryptocurrency { 
  meta: 
 	description = "mine cryptocurrency (converted from capa rule)"
	namespace = "impact/cryptocurrency"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	attack = "Impact::Resource Hijacking [T1496]"
	references = "https://github.com/ctxis/CAPE/blob/master/modules/signatures/cryptomining.py"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/mine-cryptocurrency.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bjp = "stratum+tcp://" ascii wide
	$str_bjq = "xmrig" ascii wide
	$str_bjr = "xmr-stak" ascii wide
	$str_bjs = "supportxmr.com:" ascii wide
	$str_bjt = "dwarfpool.com:" ascii wide
	$str_bju = "minergate" ascii wide
	$str_bjv = "xmr." ascii wide
	$str_bjw = "monero." ascii wide
	$str_bjx = "Bitcoin" ascii wide
	$str_bjy = "Bitcoin" ascii wide
	$str_bjz = "BitcoinGold" ascii wide
	$str_bka = "BtcCash" ascii wide
	$str_bkb = "Ethereum" ascii wide
	$str_bkc = "BlackCoin" ascii wide
	$str_bkd = "ByteCoin" ascii wide
	$str_bke = "EmerCoin" ascii wide
	$str_bkf = "ReddCoin" ascii wide
	$str_bkg = "Peercoin" ascii wide
	$str_bkh = "Ripple" ascii wide
	$str_bki = "Miota" ascii wide
	$str_bkj = "Cardano" ascii wide
	$str_bkk = "Lisk" ascii wide
	$str_bkl = "Stratis" ascii wide
	$str_bkm = "Waves" ascii wide
	$str_bkn = "Qtum" ascii wide
	$str_bko = "Stellar" ascii wide
	$str_bkp = "ViaCoin" ascii wide
	$str_bkq = "Electroneum" ascii wide
	$str_bkr = "Dash" ascii wide
	$str_bks = "Doge" ascii wide
	$str_bkt = "Monero" ascii wide
	$str_bku = "Graft" ascii wide
	$str_bkv = "Zcash" ascii wide
	$str_bkw = "Ya.money" ascii wide
	$str_bkx = "Ya.disc" ascii wide
	$str_bky = "Steam" ascii wide
	$str_bkz = "vk.cc" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bjp 
	or 	$str_bjq 
	or 	$str_bjr 
	or 	$str_bjs 
	or 	$str_bjt 
	or 	$str_bju 
	or 	$str_bjv 
	or 	$str_bjw 
	or 	$str_bjx 
	or 	$str_bjy 
	or 	$str_bjz 
	or 	$str_bka 
	or 	$str_bkb 
	or 	$str_bkc 
	or 	$str_bkd 
	or 	$str_bke 
	or 	$str_bkf 
	or 	$str_bkg 
	or 	$str_bkh 
	or 	$str_bki 
	or 	$str_bkj 
	or 	$str_bkk 
	or 	$str_bkl 
	or 	$str_bkm 
	or 	$str_bkn 
	or 	$str_bko 
	or 	$str_bkp 
	or 	$str_bkq 
	or 	$str_bkr 
	or 	$str_bks 
	or 	$str_bkt 
	or 	$str_bku 
	or 	$str_bkv 
	or 	$str_bkw 
	or 	$str_bkx 
	or 	$str_bky 
	or 	$str_bkz  ) 
}

rule capa_packed_with_SeauSFX { 
  meta: 
 	description = "packed with SeauSFX (converted from capa rule)"
	namespace = "anti-analysis/packer/seausfx"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-seausfx.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bla in pe.sections : ( bla.name == ".seau" )  ) 
}

rule capa_debug_build { 
  meta: 
 	description = "debug build (converted from capa rule)"
	namespace = "executable/pe/debug"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/debug-build.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_blb = "Assertion failed!" ascii wide
	$str_blc = "Assertion failed:" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_blb 
	or 	$str_blc  ) 
}

rule capa_packed_with_Simple_Pack { 
  meta: 
 	description = "packed with Simple Pack (converted from capa rule)"
	namespace = "anti-analysis/packer/simple-pack"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-simple-pack.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bld in pe.sections : ( bld.name == ".spack" )  ) 
}

rule capa_resolve_function_by_hash { 
  meta: 
 	description = "resolve function by hash (converted from capa rule)"
	namespace = "linking/runtime-linking"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information::Indicator Removal from Tools [T1027.005]"
	references = "https://www.fireeye.com/blog/threat-research/2012/11/precalculated-string-hashes-reverse-engineering-shellcode.html"
	references = "https://pastebin.com/ci5XYW4P"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/resolve-function-by-hash.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$num_ble = { 5B BC 4A 6A }
	$num_blf = { 5D 68 FA 3C }
	$num_blg = { 8E 4E 0E EC }
	$num_blh = { AA FC 0D 7C }
	$num_bli = { 54 CA AF 91 }
	$num_blj = { B8 0A 4C 53 }
	$num_blk = { 1A 06 7F FF }
	$num_bll = { EF CE E0 60 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( $num_ble 
	or $num_blf 
	or $num_blg 
	or $num_blh 
	or $num_bli 
	or $num_blj 
	or $num_blk 
	or $num_bll  ) 
}

rule capa_hash_data_via_BCrypt { 
  meta: 
 	description = "hash data via BCrypt (converted from capa rule)"
	namespace = "data-manipulation/hashing"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Cryptography::Cryptographic Hash [C0029]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/hash-data-via-bcrypt.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$api_blm = "BCryptHash" ascii wide
	$api_bln = "BCryptHashData" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$api_blm 
	or  (  ( 	$api_bln  )  )  )  )  ) 
}

rule capa_delete_internet_cache { 
  meta: 
 	description = "delete internet cache (converted from capa rule)"
	namespace = "host-interaction/internet/cache"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/delete-internet-cache.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_enumerate_internet_cache

	and 	pe.imports(/wininet/i, /DeleteUrlCacheEntry/)  ) 
}

rule capa_reference_OpenDNS_DNS_server { 
  meta: 
 	description = "reference OpenDNS DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.techradar.com/news/best-dns-server"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-opendns-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_blp = "208.67.222.222" ascii wide
	$str_blq = "208.67.220.220" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_blp 
	or 	$str_blq  ) 
}

rule capa_read_process_memory { 
  meta: 
 	description = "read process memory (converted from capa rule)"
	namespace = "host-interaction/process"
	author = "matthew.williams@fireeye.com"
	author = "@_re_fox"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/read-process-memory.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /ReadProcessMemory/)  ) 
}

rule capa_linked_against_XZip { 
  meta: 
 	description = "linked against XZip (converted from capa rule)"
	namespace = "linking/static/xzip"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	mbc = "Data::Compression Library [C0060]"
	references = "https://github.com/ValveSoftware/source-sdk-2013/blob/master/sp/src/public/XZip.cpp"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-xzip.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_blr = "ct_init: length != 256" ascii wide
	$str_bls = "ct_init: dist != 256" ascii wide
	$str_blt = "ct_init: 256+dist != 512" ascii wide
	$str_blu = "bit length overflow" ascii wide
	$str_blv = "code %d bits %d->%d" ascii wide
	$str_blw = "inconsistent bit counts" ascii wide
	$str_blx = "gen_codes: max_code %d " ascii wide
	$str_bly = "dyn trees: dyn %ld, stat %ld" ascii wide
	$str_blz = "bad pack level" ascii wide
	$str_bma = "Code too clever" ascii wide
	$str_bmb = "unknown zip result code" ascii wide
	$str_bmc = "Culdn't duplicate handle" ascii wide
	$str_bmd = "File not found in the zipfile" ascii wide
	$str_bme = "Still more data to unzip" ascii wide
	$str_bmf = "Caller: the file had already been partially unzipped" ascii wide
	$str_bmg = "Caller: can only get memory of a memory zipfile" ascii wide
	$str_bmh = "Zip-bug: internal initialisation not completed" ascii wide
	$str_bmi = "Zip-bug: an internal error during flation" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_blr 
	or 	$str_bls 
	or 	$str_blt 
	or 	$str_blu 
	or 	$str_blv 
	or 	$str_blw 
	or 	$str_blx 
	or 	$str_bly 
	or 	$str_blz 
	or 	$str_bma 
	or 	$str_bmb 
	or 	$str_bmc 
	or 	$str_bmd 
	or 	$str_bme 
	or 	$str_bmf 
	or 	$str_bmg 
	or 	$str_bmh 
	or 	$str_bmi  ) 
}

rule capa_compiled_from_EPL { 
  meta: 
 	description = "compiled from EPL (converted from capa rule)"
	namespace = "compiler/epl"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.hexacorn.com/blog/2019/02/13/pe-files-and-the-easy-programming-language-epl/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/compiled-from-epl.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bmj = "GetNewSock" ascii wide
	$str_bmk = "Software\\FlySky\\E\\Install" ascii wide
	$str_bml = "Not found the kernel library or the kernel library is invalid!" ascii wide
	$str_bmm = "Failed to allocate memory!" ascii wide
	$str_bmn = "/ MADE BY E COMPILER – WUTAO" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bmj 
	or 	$str_bmk 
	or 	$str_bml 
	or 	$str_bmm 
	or 	$str_bmn 
	or 	for any bmo in pe.sections : ( bmo.name == ".ecode" ) 
	or 	for any bmp in pe.sections : ( bmp.name == ".edata" ) 
	or 	pe.imports(/krnln/i, /fne/) 
	or 	pe.imports(/krnln/i, /fnr/) 
	or 	pe.imports(/eAPI/i, /fne/) 
	or 	pe.imports(/RegEx/i, /fnr/)  ) 
}

rule capa_get_session_information { 
  meta: 
 	description = "get session information (converted from capa rule)"
	namespace = "host-interaction/session"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Owner/User Discovery [T1033]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-session-information.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/wtsapi32/i, /WTSQuerySessionInformation/)  ) 
}

rule capa_packed_with_Perplex { 
  meta: 
 	description = "packed with Perplex (converted from capa rule)"
	namespace = "anti-analysis/packer/perplex"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-perplex.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bmq in pe.sections : ( bmq.name == ".perplex" )  ) 
}

rule capa_compiled_with_Go { 
  meta: 
 	description = "compiled with Go (converted from capa rule)"
	namespace = "compiler/go"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	hash = "49a34cfbeed733c24392c9217ef46bb6"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/go/compiled-with-go.yml"
	date = "2021-05-15"

  strings: 
 	$str_bmr = "Go build ID:" ascii wide
	$str_bms = "go.buildid" ascii wide
	$str_bmt = "Go buildinf:" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bmr 
	or 	$str_bms 
	or 	$str_bmt  ) 
}

rule capa_compiled_with_ps2exe { 
  meta: 
 	description = "compiled with ps2exe (converted from capa rule)"
	namespace = "compiler/ps2exe"
	author = "@_re_fox"
	scope = "file"
	references = "https://github.com/ikarstein/ps2exe"
	hash = "8775ed26068788279726e08ff9665aab"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/ps2exe/compiled-with-ps2exe.yml"
	date = "2021-05-15"

  strings: 
 	$str_bmu = "PS2EXEApp" ascii wide
	$str_bmv = "PS2EXE" ascii wide
	$str_bmw = "PS2EXE_Host" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_compiled_to_the__NET_platform

	and 	$str_bmu 
	and 	$str_bmv 
	and 	$str_bmw  ) 
}

rule capa_compiled_with_MinGW_for_Windows { 
  meta: 
 	description = "compiled with MinGW for Windows (converted from capa rule)"
	namespace = "compiler/mingw"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	hash = "5b3968b47eb16a1cb88525e3b565eab1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/mingw/compiled-with-mingw-for-windows.yml"
	date = "2021-05-15"

  strings: 
 	$str_bmx = "Mingw runtime failure:" ascii wide
	$str_bmy = "_Jv_RegisterClasses" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bmx 
	and 	$str_bmy  ) 
}

rule capa_compiled_from_Visual_Basic { 
  meta: 
 	description = "compiled from Visual Basic (converted from capa rule)"
	namespace = "compiler/vb"
	author = "@williballenthin"
	scope = "file"
	hash = "9bca6b99e7981208af4c7925b96fb9cf"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/vb/compiled-from-visual-basic.yml"
	date = "2021-05-15"

  strings: 
 	$bmz = /VB5!.{,1000}/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bmz 
	and 	pe.imports(/msvbvm60/i, /ThunRTMain/)  ) 
}

rule capa_compiled_with_pyarmor { 
  meta: 
 	description = "compiled with pyarmor (converted from capa rule)"
	namespace = "compiler/pyarmor"
	author = "@stvemillertime, @itreallynick"
	scope = "file"
	attack = "Execution::Command and Scripting Interpreter::Python [T1059.006]"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [1027.002]"
	references = "https://twitter.com/stvemillertime/status/1349032548580483073"
	hash = "a0fb20bc9aa944c3a0a6c4545c195818"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/pyarmor/compiled-with-pyarmor.yml"
	date = "2021-05-15"

  strings: 
 	$str_bnd = "pyarmor_runtimesh" ascii wide
	$str_bne = "PYARMOR" ascii wide
	$str_bnf = "__pyarmor__" ascii wide
	$str_bng = "PYARMOR_SIGNATURE" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bnd 
	or 	$str_bne 
	or 	$str_bnf 
	or 	$str_bng  ) 
}

rule capa_compiled_with_exe4j { 
  meta: 
 	description = "compiled with exe4j (converted from capa rule)"
	namespace = "compiler/exe4j"
	author = "johnk3r"
	scope = "file"
	hash = "6b25f1e754ef486bbb28a66d46bababe"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/exe4j/compiled-with-exe4j.yml"
	date = "2021-05-15"

  strings: 
 	$str_bnh = "exe4j_log" ascii wide
	$str_bni = "install4j_log" ascii wide
	$str_bnj = "exe4j_java_home" ascii wide
	$str_bnk = "install4j" ascii wide
	$str_bnl = "exe4j.isinstall4j" ascii wide
	$bnm = /com\/exe4j\/runtime\/exe4jcontroller/ nocase ascii wide 
	$bnn = /com\/exe4j\/runtime\/winlauncher/ nocase ascii wide 
	$str_bno = "EXE4J_LOG" ascii wide
	$str_bnp = "INSTALL4J_LOG" ascii wide
	$str_bnq = "EXE4J_JAVA_HOME" ascii wide
	$str_bnr = "INSTALL4J" ascii wide
	$str_bns = "EXE4J.ISINSTALL4J" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bnh 
	or 	$str_bni 
	or 	$str_bnj 
	or 	$str_bnk 
	or 	$str_bnl 
	or 	$bnm 
	or 	$bnn 
	or 	$str_bno 
	or 	$str_bnp 
	or 	$str_bnq 
	or 	$str_bnr 
	or 	$str_bns  ) 
}

rule capa_compiled_with_AutoIt { 
  meta: 
 	description = "compiled with AutoIt (converted from capa rule)"
	namespace = "compiler/autoit"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Execution::Command and Scripting Interpreter [T1059]"
	hash = "55D77AB16377A8A314982F723FCC6FAE"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/autoit/compiled-with-autoit.yml"
	date = "2021-05-15"

  strings: 
 	$str_bnt = "AutoIt has detected the stack has become corrupt.\n\nStack corruption typically occurs when either the wrong calling convention is used or when the function is called with the wrong number of arguments.\n\nAutoIt supports the __stdcall (WINAPI) and __cdecl calling conventions.  The __stdcall (WINAPI) convention is used by default but __cdecl can be used instead.  See the DllCall() documentation for details on changing the calling convention." ascii wide
	$str_bnu = "AutoIt Error" ascii wide
	$bnv = />>>AUTOIT SCRIPT<<</ ascii wide 
	$str_bnw = ">>>AUTOIT NO CMDEXECUTE<<<" ascii wide
	$str_bnx = "#requireadmin" ascii wide
	$str_bny = "#OnAutoItStartRegister" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bnt 
	or 	$str_bnu 
	or 	$bnv 
	or 	$str_bnw 
	or 	$str_bnx 
	or 	$str_bny  ) 
}

rule capa_compiled_with_Borland_Delphi { 
  meta: 
 	description = "compiled with Borland Delphi (converted from capa rule)"
	namespace = "compiler/delphi"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	hash = "4BDD67FF852C221112337FECD0681EAC"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/delphi/compiled-with-borland-delphi.yml"
	date = "2021-05-15"

  strings: 
 	$str_bnz = "Borland C++ - Copyright 2002 Borland Corporation" ascii wide
	$boa = /SOFTWARE\\Borland\\Delphi\\RTL/ ascii wide 
	$str_bob = "Sysutils::Exception" ascii wide
	$str_boc = "TForm1" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bnz 
	or 	$boa 
	or 	$str_bob 
	or 	$str_boc 
	or 	pe.imports(/BORLNDMM/i, /DLL/)  ) 
}

rule capa_compiled_with_dmd { 
  meta: 
 	description = "compiled with dmd (converted from capa rule)"
	namespace = "compiler/d"
	author = "@_re_fox"
	scope = "file"
	references = "https://github.com/dlang/dmd"
	hash = "321338196a46b600ea330fc5d98d0699"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/d/compiled-with-dmd.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any bod in pe.sections : ( bod.name == "._deh" ) 
	and 	for any boe in pe.sections : ( boe.name == ".tp" ) 
	and 	for any bof in pe.sections : ( bof.name == ".dp" ) 
	and 	for any bog in pe.sections : ( bog.name == ".minfo" )  ) 
}

rule capa_compiled_with_py2exe { 
  meta: 
 	description = "compiled with py2exe (converted from capa rule)"
	namespace = "compiler/py2exe"
	author = "@_re_fox"
	scope = "basic block"
	hash = "ed888dc2f04f5eac83d6d14088d002de"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/py2exe/compiled-with-py2exe.yml"
	date = "2021-05-15"

  strings: 
 	$str_boh = "PY2EXE_VERBOSE" ascii wide
	$api_boi = "getenv" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_boh 
	and 	$api_boi  ) 
}

rule capa_identify_ATM_dispenser_service_provider { 
  meta: 
 	description = "identify ATM dispenser service provider (converted from capa rule)"
	namespace = "targeting/automated-teller-machine"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://doc.axxonsoft.com/confluence/display/atm70en/Configuring+the+connection+to+the+dispenser+service+provider"
	hash = "b2ad4409323147b63e370745e5209996"
	hash = "1f094dd65be477d15d871e72f0fdce5e"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/identify-atm-dispenser-service-provider.yml"
	date = "2021-05-15"

  strings: 
 	$str_boj = "CurrencyDispenser1" ascii wide
	$str_bok = "CDM30" ascii wide
	$str_bol = "DBD_AdvFuncDisp" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_boj 
	or 	$str_bok 
	or 	$str_bol  ) 
}

rule capa_load_NCR_ATM_library { 
  meta: 
 	description = "load NCR ATM library (converted from capa rule)"
	namespace = "targeting/automated-teller-machine/ncr"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.pcworld.com/article/2824572/leaked-programming-manual-may-help-criminals-develop-more-atm-malware.html"
	hash = "971e599e6e707349eccea2fd4c8e5f67"
	hash = "4bdd67ff852c221112337fecd0681eac"
	hash = "32d1f4b9c0cf2bb9512d88d27ca23c07"
	hash = "dc9eb40429d6fa2f15cd34479cb320c8"
	hash = "5b3968b47eb16a1cb88525e3b565eab1"
	hash = "dc4dc746d8a14060fb5fc7edd4ef5282"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/ncr/load-ncr-atm-library.yml"
	date = "2021-05-15"

  strings: 
 	$str_bom = "MSXFS.dll" ascii wide
	$str_bon = "msxfs.dll" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/msxfs/i, /dll/) 
	or 	$str_bom 
	or 	$str_bon  ) 
}

rule capa_reference_NCR_ATM_library_routines { 
  meta: 
 	description = "reference NCR ATM library routines (converted from capa rule)"
	namespace = "targeting/automated-teller-machine/ncr"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.pcworld.com/article/2824572/leaked-programming-manual-may-help-criminals-develop-more-atm-malware.html"
	hash = "84a1212f4a91066babcf594d87a85894"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/ncr/reference-ncr-atm-library-routines.yml"
	date = "2021-05-15"

  strings: 
 	$str_boo = "msxfs.dll" ascii wide
	$str_bop = "WFSCleanUp" ascii wide
	$str_boq = "WFSClose" ascii wide
	$str_bor = "WFSExecute" ascii wide
	$str_bos = "WFSFreeResult" ascii wide
	$str_bot = "WFSGetInfo" ascii wide
	$str_bou = "WFSLock" ascii wide
	$str_bov = "WFSOpen" ascii wide
	$str_bow = "WFSRegister" ascii wide
	$str_box = "WFSStartUp" ascii wide
	$str_boy = "WFSUnlock" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_boo 
	or 	pe.imports(/msxfs/i, /WFSCleanUp/) 
	or 	$str_bop 
	or 	pe.imports(/msxfs/i, /WFSClose/) 
	or 	$str_boq 
	or 	pe.imports(/msxfs/i, /WFSExecute/) 
	or 	$str_bor 
	or 	pe.imports(/msxfs/i, /WFSFreeResult/) 
	or 	$str_bos 
	or 	pe.imports(/msxfs/i, /WFSGetInfo/) 
	or 	$str_bot 
	or 	pe.imports(/msxfs/i, /WFSLock/) 
	or 	$str_bou 
	or 	pe.imports(/msxfs/i, /WFSOpen/) 
	or 	$str_bov 
	or 	pe.imports(/msxfs/i, /WFSRegister/) 
	or 	$str_bow 
	or 	pe.imports(/msxfs/i, /WFSStartUp/) 
	or 	$str_box 
	or 	pe.imports(/msxfs/i, /WFSUnlock/) 
	or 	$str_boy  ) 
}

rule capa_reference_Diebold_ATM_routines { 
  meta: 
 	description = "reference Diebold ATM routines (converted from capa rule)"
	namespace = "targeting/automated-teller-machine/diebold-nixdorf"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.fireeye.com/blog/threat-research/2017/01/new_ploutus_variant.html"
	hash = "b2ad4409323147b63e370745e5209996"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/diebold-nixdorf/reference-diebold-atm-routines.yml"
	date = "2021-05-15"

  strings: 
 	$str_boz = "DBD_AdvFuncDisp" ascii wide
	$str_bpa = "DBD_EPP4" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_boz 
	or 	$str_bpa  ) 
}

rule capa_load_Diebold_Nixdorf_ATM_library { 
  meta: 
 	description = "load Diebold Nixdorf ATM library (converted from capa rule)"
	namespace = "targeting/automated-teller-machine/diebold-nixdorf"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.vkremez.com/2017/12/lets-learn-cutlet-atm-malware-internals.html"
	hash = "658b0502b53f718bd0611a638dfd5969"
	hash = "8683c43f1e22363ce98f0a89ca4ed389"
	hash = "953bc3e68f0a49c6ade30b52a2bfaaab"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/diebold-nixdorf/load-diebold-nixdorf-atm-library.yml"
	date = "2021-05-15"

  strings: 
 	$str_bpb = "CSCWCNG.dll" ascii wide
	$str_bpc = "CscCngStatusWrite" ascii wide
	$str_bpd = "CscCngCasRefInit" ascii wide
	$str_bpe = "CscCngEncryption" ascii wide
	$str_bpf = "CscCngRecovery" ascii wide
	$str_bpg = "CscCngService" ascii wide
	$str_bph = "CscCngOpen" ascii wide
	$str_bpi = "CscCngReset" ascii wide
	$str_bpj = "CscCngClose" ascii wide
	$str_bpk = "CscCngDispense" ascii wide
	$str_bpl = "CscCngTransport" ascii wide
	$str_bpm = "CscCngStatusRead" ascii wide
	$str_bpn = "CscCngInit" ascii wide
	$str_bpo = "CscCngGetRelease" ascii wide
	$str_bpp = "CscCngLock" ascii wide
	$str_bpq = "CscCngUnlock" ascii wide
	$str_bpr = "CscCngShutter" ascii wide
	$str_bps = "CscCngPowerOff" ascii wide
	$str_bpt = "CscCngSelStatus" ascii wide
	$str_bpu = "CscCngBim" ascii wide
	$str_bpv = "CscCngConfigure" ascii wide
	$str_bpw = "CscCngStatistics" ascii wide
	$str_bpx = "CscCngControl" ascii wide
	$str_bpy = "CscCngPsm" ascii wide
	$str_bpz = "CscCngGetTrace" ascii wide
	$str_bqa = "CscCngOptimization" ascii wide
	$str_bqb = "CscCngSelftest" ascii wide
	$str_bqc = "CscCngEco" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/cscwcng/i, /dll/) 
	or 	$str_bpb 
	or 	pe.imports(/cscwcng/i, /CscCngStatusWrite/) 
	or 	pe.imports(/cscwcng/i, /CscCngCasRefInit/) 
	or 	pe.imports(/cscwcng/i, /CscCngEncryption/) 
	or 	pe.imports(/cscwcng/i, /CscCngRecovery/) 
	or 	pe.imports(/cscwcng/i, /CscCngService/) 
	or 	pe.imports(/cscwcng/i, /CscCngOpen/) 
	or 	pe.imports(/cscwcng/i, /CscCngReset/) 
	or 	pe.imports(/cscwcng/i, /CscCngClose/) 
	or 	pe.imports(/cscwcng/i, /CscCngDispense/) 
	or 	pe.imports(/cscwcng/i, /CscCngTransport/) 
	or 	pe.imports(/cscwcng/i, /CscCngStatusRead/) 
	or 	pe.imports(/cscwcng/i, /CscCngInit/) 
	or 	pe.imports(/cscwcng/i, /CscCngGetRelease/) 
	or 	pe.imports(/cscwcng/i, /CscCngLock/) 
	or 	pe.imports(/cscwcng/i, /CscCngUnlock/) 
	or 	pe.imports(/cscwcng/i, /CscCngShutter/) 
	or 	pe.imports(/cscwcng/i, /CscCngPowerOff/) 
	or 	pe.imports(/cscwcng/i, /CscCngSelStatus/) 
	or 	pe.imports(/cscwcng/i, /CscCngBim/) 
	or 	pe.imports(/cscwcng/i, /CscCngConfigure/) 
	or 	pe.imports(/cscwcng/i, /CscCngStatistics/) 
	or 	pe.imports(/cscwcng/i, /CscCngControl/) 
	or 	pe.imports(/cscwcng/i, /CscCngPsm/) 
	or 	pe.imports(/cscwcng/i, /CscCngGetTrace/) 
	or 	pe.imports(/cscwcng/i, /CscCngOptimization/) 
	or 	pe.imports(/cscwcng/i, /CscCngSelftest/) 
	or 	pe.imports(/cscwcng/i, /CscCngEco/) 
	or 	$str_bpc 
	or 	$str_bpd 
	or 	$str_bpe 
	or 	$str_bpf 
	or 	$str_bpg 
	or 	$str_bph 
	or 	$str_bpi 
	or 	$str_bpj 
	or 	$str_bpk 
	or 	$str_bpl 
	or 	$str_bpm 
	or 	$str_bpn 
	or 	$str_bpo 
	or 	$str_bpp 
	or 	$str_bpq 
	or 	$str_bpr 
	or 	$str_bps 
	or 	$str_bpt 
	or 	$str_bpu 
	or 	$str_bpv 
	or 	$str_bpw 
	or 	$str_bpx 
	or 	$str_bpy 
	or 	$str_bpz 
	or 	$str_bqa 
	or 	$str_bqb 
	or 	$str_bqc  ) 
}

rule capa_initialize_WinHTTP_library { 
  meta: 
 	description = "initialize WinHTTP library (converted from capa rule)"
	namespace = "communication/http"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::WinHTTP [C0002.008]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/initialize-winhttp-library.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/winhttp/i, /WinHttpOpen/)  ) 
}

rule capa_set_HTTP_header { 
  meta: 
 	description = "set HTTP header (converted from capa rule)"
	namespace = "communication/http"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Set Header [C0002.013]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/set-http-header.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/winhttp/i, /WinHttpAddRequestHeaders/)  ) 
}

rule capa_initialize_IWebBrowser2 { 
  meta: 
 	description = "initialize IWebBrowser2 (converted from capa rule)"
	namespace = "communication/http"
	author = "matthew.williams@fireeye.com"
	scope = "basic block"
	mbc = "Communication::HTTP Communication::IWebBrowser [C0002.010]"
	hash = "395EB0DDD99D2C9E37B6D0B73485EE9C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/initialize-iwebbrowser2.yml"
	date = "2021-05-15"

  strings: 
 	$bqd = { 01 DF 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
	$bqe = { 61 16 0C D3 AF CD D0 11 8A 3E 00 C0 4F C9 E2 6E }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ole32/i, /CoCreateInstance/) 
	and 	$bqd 
	and 	$bqe  ) 
}

rule capa_read_HTTP_header { 
  meta: 
 	description = "read HTTP header (converted from capa rule)"
	namespace = "communication/http"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Read Header [C0002.014]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/read-http-header.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/winhttp/i, /WinHttpQueryHeaders/)  ) 
}

rule capa_send_HTTP_response { 
  meta: 
 	description = "send HTTP response (converted from capa rule)"
	namespace = "communication/http/server"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Send Response [C0002.016]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/server/send-http-response.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/httpapi/i, /HttpSendHttpResponse/)  ) 
}

rule capa_start_HTTP_server { 
  meta: 
 	description = "start HTTP server (converted from capa rule)"
	namespace = "communication/http/server"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Start Server [C0002.018]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/server/start-http-server.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/httpapi/i, /HttpInitialize/)  ) 
}

rule capa_receive_HTTP_response { 
  meta: 
 	description = "receive HTTP response (converted from capa rule)"
	namespace = "communication/http/client"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Get Response [C0002.017]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/receive-http-response.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/winhttp/i, /WinHttpReceiveResponse/) 
	or  (  ( 	pe.imports(/winhttp/i, /WinHttpReadData/)  )  )  ) 
}

rule capa_create_HTTP_request { 
  meta: 
 	description = "create HTTP request (converted from capa rule)"
	namespace = "communication/http/client"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Create Request [C0002.012]"
	hash = "6f99a2c8944cb02ff28c6f9ced59b161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/create-http-request.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/wininet/i, /InternetOpen/)  ) 
}

rule capa_connect_to_URL { 
  meta: 
 	description = "connect to URL (converted from capa rule)"
	namespace = "communication/http/client"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Open URL [C0002.004]"
	hash = "6f99a2c8944cb02ff28c6f9ced59b161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/connect-to-url.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/wininet/i, /InternetOpenUrl/)  ) 
}

rule capa_send_file_via_HTTP { 
  meta: 
 	description = "send file via HTTP (converted from capa rule)"
	namespace = "communication/http/client"
	author = "matthew.williams@fireeye.com"
	scope = "basic block"
	mbc = "Communication::HTTP Communication::Send Data [C0002.005]"
	hash = "EAAD7DFC78304B977D3844CC63577152"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/send-file-via-http.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/wininet/i, /InternetWriteFile/)  ) 
}

rule capa_download_URL_to_file { 
  meta: 
 	description = "download URL to file (converted from capa rule)"
	namespace = "communication/http/client"
	author = "matthew.williams@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Download URL [C0002.006]"
	hash = "F5C93AC768C8206E87544DDD76B3277C"
	hash = "Practical Malware Analysis Lab 20-01.exe_:0x401040"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/download-url-to-file.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/urlmon/i, /URLDownloadToFile/) 
	or 	pe.imports(/urlmon/i, /URLDownloadToCacheFile/)  ) 
}

rule capa_send_HTTP_request { 
  meta: 
 	description = "send HTTP request (converted from capa rule)"
	namespace = "communication/http/client"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Send Request [C0002.003]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/send-http-request.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  (  (  ( 	pe.imports(/wininet/i, /HttpOpenRequest/) 
	or 	pe.imports(/wininet/i, /InternetConnect/)  )  ) 
	and  (  ( 	pe.imports(/wininet/i, /HttpSendRequest/) 
	or 	pe.imports(/wininet/i, /HttpSendRequestEx/)  )  )  )  ) 
	or  (  ( 	pe.imports(/winhttp/i, /WinHttpSendRequest/) 
	and 	pe.imports(/winhttp/i, /WinHttpWriteData/)  )  ) 
  ) 
}

rule capa_prepare_HTTP_request { 
  meta: 
 	description = "prepare HTTP request (converted from capa rule)"
	namespace = "communication/http/client"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Create Request [C0002.012]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/prepare-http-request.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/winhttp/i, /WinHttpOpenRequest/)  ) 
}

rule capa_read_data_from_Internet { 
  meta: 
 	description = "read data from Internet (converted from capa rule)"
	namespace = "communication/http/client"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Get Response [C0002.017]"
	hash = "6f99a2c8944cb02ff28c6f9ced59b161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/read-data-from-internet.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/wininet/i, /InternetReadFile/) 
	or 	pe.imports(/wininet/i, /InternetReadFileEx/)  )  )  ) 
}

rule capa_connect_to_HTTP_server { 
  meta: 
 	description = "connect to HTTP server (converted from capa rule)"
	namespace = "communication/http/client"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Connect to Server [C0002.009]"
	hash = "6f99a2c8944cb02ff28c6f9ced59b161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/connect-to-http-server.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/wininet/i, /InternetConnect/)  ) 
}

rule capa_send_file_using_FTP_via_wininet { 
  meta: 
 	description = "send file using FTP via wininet (converted from capa rule)"
	namespace = "communication/ftp/send"
	author = "michael.hunhof@fireeye.com"
	scope = "function"
	mbc = "Communication::FTP Communication::Send File [C0004.001]"
	mbc = "Communication::FTP Communication::WinINet [C0004.002]"
	hash = "Practical Malware Analysis Lab 20-02.exe_:0x401380"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/ftp/send/send-file-using-ftp-via-wininet.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/wininet/i, /FtpPutFile/)  ) 
}

rule capa_send_ICMP_echo_request { 
  meta: 
 	description = "send ICMP echo request (converted from capa rule)"
	namespace = "communication/icmp"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::ICMP Communication::Echo Request [C0014.002]"
	references = "https://docs.microsoft.com/en-us/windows/win32/api/icmpapi/"
	hash = "al-khaser_x86.exe_:0x449510"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/icmp/send-icmp-echo-request.yml"
	date = "2021-05-15"

  strings: 
 	$api_bqh = "IcmpSendEcho" ascii wide
	$api_bqi = "IcmpSendEcho2" ascii wide
	$api_bqj = "IcmpSendEcho2Ex" ascii wide
	$api_bqk = "Icmp6SendEcho2" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$api_bqh 
	or 	$api_bqi 
	or 	$api_bqj 
	or 	$api_bqk  )  )  ) 
}

rule capa_initialize_Winsock_library { 
  meta: 
 	description = "initialize Winsock library (converted from capa rule)"
	namespace = "communication/socket"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::Socket Communication::Initialize Winsock Library [C0001.009]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/socket/initialize-winsock-library.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ws2_32/i, /WSAStartup/)  ) 
}

rule capa_get_socket_status { 
  meta: 
 	description = "get socket status (converted from capa rule)"
	namespace = "communication/socket"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	mbc = "Communication::Socket Communication::Get Socket Status [C0001.012]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/socket/get-socket-status.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ws2_32/i, /select/)  ) 
}

rule capa_set_socket_configuration { 
  meta: 
 	description = "set socket configuration (converted from capa rule)"
	namespace = "communication/socket"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::Socket Communication::Set Socket Config [C0001.001]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/socket/set-socket-configuration.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ws2_32/i, /setsockopt/) 
	or 	pe.imports(/ws2_32/i, /ioctlsocket/)  ) 
}

rule capa_receive_data_on_socket { 
  meta: 
 	description = "receive data on socket (converted from capa rule)"
	namespace = "communication/socket/receive"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Communication::Socket Communication::Receive Data [C0001.006]"
	hash = "Practical Malware Analysis Lab 01-01.dll_:0x10001010"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/socket/receive/receive-data-on-socket.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ws2_32/i, /recv/) 
	or 	pe.imports(/ws2_32/i, /recvfrom/) 
	or 	pe.imports(/ws2_32/i, /WSARecv/) 
	or 	pe.imports(/ws2_32/i, /WSARecvDisconnect/) 
	or 	pe.imports(/ws2_32/i, /WSARecvEx/) 
	or 	pe.imports(/ws2_32/i, /WSARecvFrom/) 
	or 	pe.imports(/ws2_32/i, /WSARecvMsg/)  ) 
}

rule capa_send_data_on_socket { 
  meta: 
 	description = "send data on socket (converted from capa rule)"
	namespace = "communication/socket/send"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Communication::Socket Communication::Send Data [C0001.007]"
	hash = "Practical Malware Analysis Lab 01-01.dll_:0x10001010"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/socket/send/send-data-on-socket.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ws2_32/i, /send/) 
	or 	pe.imports(/ws2_32/i, /sendto/) 
	or 	pe.imports(/ws2_32/i, /WSASend/) 
	or 	pe.imports(/ws2_32/i, /WSASendMsg/) 
	or 	pe.imports(/ws2_32/i, /WSASendTo/)  ) 
}

rule capa_create_pipe { 
  meta: 
 	description = "create pipe (converted from capa rule)"
	namespace = "communication/named-pipe/create"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Communication::Interprocess Communication::Create Pipe [C0003.001]"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x10003a13"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/named-pipe/create/create-pipe.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /CreatePipe/) 
	or 	pe.imports(/kernel32/i, /CreateNamedPipe/)  ) 
}

rule capa_write_pipe { 
  meta: 
 	description = "write pipe (converted from capa rule)"
	namespace = "communication/named-pipe/write"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::Interprocess Communication::Write Pipe [C0003.004]"
	hash = "C91887D861D9BD4A5872249B641BC9F9"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/named-pipe/write/write-pipe.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /TransactNamedPipe/) 
	or 	pe.imports(/kernel32/i, /CallNamedPipe/)  ) 
}

rule capa_connect_pipe { 
  meta: 
 	description = "connect pipe (converted from capa rule)"
	namespace = "communication/named-pipe/connect"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::Interprocess Communication::Connect Pipe [C0003.002]"
	hash = "152d4c9f63efb332ccb134c6953c0104"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/named-pipe/connect/connect-pipe.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /ConnectNamedPipe/) 
	or 	pe.imports(/kernel32/i, /CallNamedPipe/)  ) 
}

rule capa_read_pipe { 
  meta: 
 	description = "read pipe (converted from capa rule)"
	namespace = "communication/named-pipe/read"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	description = "PeekNamedPipe isn't required to read from a pipe; however, pipes are often utilized to capture the output of a cmd.exe process. In a multi-thread instance, a new thread is created that calls PeekNamedPipe and ReadFile to obtain the command output."
	scope = "function"
	mbc = "Communication::Interprocess Communication::Read Pipe [C0003.003]"
	hash = "Practical Malware Analysis Lab 14-02.exe_:0x4014C0"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/named-pipe/read/read-pipe.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/kernel32/i, /PeekNamedPipe/) 
	and 	pe.imports(/kernel32/i, /ReadFile/)  )  ) 
	or 	pe.imports(/kernel32/i, /TransactNamedPipe/) 
	or 	pe.imports(/kernel32/i, /CallNamedPipe/)  ) 
}

rule capa_access_PE_header { 
  meta: 
 	description = "access PE header (converted from capa rule)"
	namespace = "load-code/pe"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Execution::Shared Modules [T1129]"
	hash = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/load-code/pe/access-pe-header.yml"
	date = "2021-05-15"

  strings: 
 	$api_bql = "RtlImageNtHeader" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_bql 
	or 	pe.imports(/ntdll/i, /RtlImageNtHeaderEx/)  ) 
}

rule capa_acquire_credentials_from_Windows_Credential_Manager { 
  meta: 
 	description = "acquire credentials from Windows Credential Manager (converted from capa rule)"
	namespace = "collection"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores::Windows Credential Manager [T1555.004]"
	hash = "c56af5561e3f20bed435fb4355cffc29"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/acquire-credentials-from-windows-credential-manager.yml"
	date = "2021-05-15"

  strings: 
 	$str_bqm = ".vcrd" ascii wide
	$str_bqn = "*.vcrd" ascii wide
	$str_bqo = "Policy.vpol" ascii wide
	$bqp = /AppData\\Local\\Microsoft\\(Vault|Credentials)/ ascii wide 
	$api_bqq = "CredEnumerate" ascii wide
	$bqr = /vaultcmd(\.exe)?/ ascii wide 
	$bqs = /\/listcreds:/ ascii wide 
	$bqt = /"Windows Credentials"/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bqm 
	or 	$str_bqn 
	or 	$str_bqo 
	or 	$bqp 
	or 	$api_bqq 
	or  (  (  (  ( 	$bqr 
	or 	$bqs 
	or 	$bqt  )  )  )  )  ) 
}

rule capa_get_geographical_location { 
  meta: 
 	description = "get geographical location (converted from capa rule)"
	namespace = "collection"
	author = "moritz.raabe"
	scope = "function"
	attack = "Discovery::System Location Discovery [T1614]"
	hash = "9879D201DC5ACA863F357184CD1F170E"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/get-geographical-location.yml"
	date = "2021-05-15"

  strings: 
 	$api_bqu = "GetLocaleInfo" ascii wide
	$api_bqv = "GetLocaleInfoEx" ascii wide
	$bqw = /geolocation/ nocase ascii wide 
	$bqx = /geo-location/ nocase ascii wide 
	$bqy = /\bcity/ nocase ascii wide 
	$bqz = /region_code/ nocase ascii wide 
	$bra = /region_name/ nocase ascii wide 
	$brb = /\bcountry/ nocase ascii wide 
	$brc = /country_code/ nocase ascii wide 
	$brd = /countrycode/ nocase ascii wide 
	$bre = /country_name/ nocase ascii wide 
	$brf = /continent_code/ nocase ascii wide 
	$brg = /continent_name/ nocase ascii wide 
	$brh = /\blatitude/ nocase ascii wide 
	$bri = /\blongitude/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_bqu 
	or 	$api_bqv 
	or 	$bqw 
	or 	$bqx 
	or 	$bqy 
	or 	$bqz 
	or 	$bra 
	or 	$brb 
	or 	$brc 
	or 	$brd 
	or 	$bre 
	or 	$brf 
	or 	$brg 
	or 	$brh 
	or 	$bri  ) 
}

rule capa_log_keystrokes_via_polling { 
  meta: 
 	description = "log keystrokes via polling (converted from capa rule)"
	namespace = "collection/keylog"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Collection::Input Capture::Keylogging [T1056.001]"
	mbc = "Collection::Keylogging::Polling [F0002.002]"
	hash = "Practical Malware Analysis Lab 11-03.dll_:0x10001030"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/keylog/log-keystrokes-via-polling.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/user32/i, /GetAsyncKeyState/) 
	or 	pe.imports(/user32/i, /GetKeyState/) 
	or 	pe.imports(/user32/i, /GetKeyboardState/) 
	or 	pe.imports(/user32/i, /VkKeyScan/) 
	or 	pe.imports(/user32/i, /VkKeyScanEx/) 
	or 	pe.imports(/user32/i, /GetKeyNameText/)  ) 
}

rule capa_log_keystrokes { 
  meta: 
 	description = "log keystrokes (converted from capa rule)"
	namespace = "collection/keylog"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Collection::Input Capture::Keylogging [T1056.001]"
	hash = "C91887D861D9BD4A5872249B641BC9F9"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/keylog/log-keystrokes.yml"
	date = "2021-05-15"

  strings: 
 	$api_brk = "SetWindowsHookEx" ascii wide
	$api_brl = "GetKeyState" ascii wide
	$api_brm = "RegisterHotKey" ascii wide
	$api_brn = "UnregisterHotKey" ascii wide
	$api_bro = "CallNextHookEx" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$api_brk 
	and 	$api_brl  )  ) 
	or  (  ( 	$api_brm 
	and 	pe.imports(/user32/i, /keybd_event/) 
	and 	$api_brn  )  ) 
	or  (  ( 	$api_bro 
	and 	pe.imports(/user32/i, /GetKeyNameText/) 
	and 	pe.imports(/user32/i, /GetAsyncKeyState/) 
	and 	pe.imports(/user32/i, /GetForgroundWindow/)  )  ) 
	or 	pe.imports(/user32/i, /AttachThreadInput/) 
	or 	pe.imports(/user32/i, /MapVirtualKey/)  ) 
}

rule capa_capture_microphone_audio { 
  meta: 
 	description = "capture microphone audio (converted from capa rule)"
	namespace = "collection/microphone"
	author = "@_re_fox"
	scope = "function"
	attack = "Collection::Audio Capture [T1123]"
	hash = "a70052c45e907820187c7e6bcdc7ecca"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/microphone/capture-microphone-audio.yml"
	date = "2021-05-15"

  strings: 
 	$api_brp = "mciSendString" ascii wide
	$brq = /\bopen/ nocase ascii wide 
	$brr = /waveaudio/ nocase ascii wide 
	$brs = /\brecord/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_brp 
	and 	$brq 
	and 	$brr 
	and 	$brs  ) 
}

rule capa_get_domain_trust_relationships { 
  meta: 
 	description = "get domain trust relationships (converted from capa rule)"
	namespace = "collection/network"
	author = "johnk3r"
	scope = "function"
	attack = "Discovery::Domain Trust Discovery  [T1482]"
	hash = "0796f1c1ea0a142fc1eb7109a44c86cb"
	hash = "0731679c5f99e8ee65d8b29a3cabfc6b"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/network/get-domain-trust-relationships.yml"
	date = "2021-05-15"

  strings: 
 	$brt = /nltest/ nocase ascii wide 
	$bru = /\/domain_trusts/ nocase ascii wide 
	$brv = /\/dclist/ nocase ascii wide 
	$brw = /\/all_trusts/ nocase ascii wide 
	$api_brx = "DsEnumerateDomainTrusts" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$brt 
	and  (  ( 	$bru 
	or 	$brv 
	or 	$brw  )  )  )  ) 
	or 	$api_brx  ) 
}

rule capa_capture_network_configuration_via_ipconfig { 
  meta: 
 	description = "capture network configuration via ipconfig (converted from capa rule)"
	namespace = "collection/network"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	hash = "7204e3efc2434012e13ca939db0d0b02"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/network/capture-network-configuration-via-ipconfig.yml"
	date = "2021-05-15"

  strings: 
 	$bry = /ipconfig(\.exe)?/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bry 
	and 	pe.imports(/msvcr100/i, /system/)  ) 
}

rule capa_capture_public_ip { 
  meta: 
 	description = "capture public ip (converted from capa rule)"
	namespace = "collection/network"
	author = "@_re_fox"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	hash = "84f1b049fa8962b215a77f51af6714b3"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/network/capture-public-ip.yml"
	date = "2021-05-15"

  strings: 
 	$api_brz = "InternetOpen" ascii wide
	$api_bsa = "InternetOpenUrl" ascii wide
	$api_bsb = "InternetReadFile" ascii wide
	$bsc = /bot\.whatismyipaddress\.com/ ascii wide 
	$bsd = /ipinfo\.io\/ip/ ascii wide 
	$bse = /checkip\.dyndns\.org/ ascii wide 
	$bsf = /ifconfig\.me/ ascii wide 
	$bsg = /ipecho\.net\/plain/ ascii wide 
	$bsh = /api\.ipify\.org/ ascii wide 
	$bsi = /checkip\.amazonaws\.com/ ascii wide 
	$bsj = /icanhazip\.com/ ascii wide 
	$bsk = /wtfismyip\.com\/text/ ascii wide 
	$bsl = /api\.myip\.com/ ascii wide 
	$bsm = /ip\-api\.com\/line/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$api_brz 
	and 	$api_bsa 
	and 	$api_bsb 
	and  (  ( 	$bsc 
	or 	$bsd 
	or 	$bse 
	or 	$bsf 
	or 	$bsg 
	or 	$bsh 
	or 	$bsi 
	or 	$bsj 
	or 	$bsk 
	or 	$bsl 
	or 	$bsm  )  )  ) 
}

rule capa_gather_cuteftp_information { 
  meta: 
 	description = "gather cuteftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://en.wikipedia.org/wiki/CuteFTP"
	references = "https://www.globalscape.com/cuteftp"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-cuteftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$bsn = /\\sm\.dat/ ascii wide 
	$bso = /\\GlobalSCAPE\\CuteFTP/ nocase ascii wide 
	$bsp = /\\GlobalSCAPE\\CuteFTP Pro/ nocase ascii wide 
	$bsq = /\\CuteFTP/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bsn 
	and  (  ( 	$bso 
	or 	$bsp 
	or 	$bsq  )  )  ) 
}

rule capa_gather_ftprush_information { 
  meta: 
 	description = "gather ftprush information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.wftpserver.com/ftprush.htm"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftprush-information.yml"
	date = "2021-05-15"

  strings: 
 	$bsr = /\\FTPRush/ ascii wide 
	$bss = /RushSite\.xml/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bsr 
	and 	$bss  ) 
}

rule capa_gather_smart_ftp_information { 
  meta: 
 	description = "gather smart-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.smartftp.com/en-us/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-smart-ftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$bst = /\\SmartFTP/ ascii wide 
	$str_bsu = ".xml" ascii wide
	$bsv = /Favorites\.dat/ nocase ascii wide 
	$bsw = /History\.dat/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$bst 
	and 	$str_bsu 
	and 	$bsv 
	and 	$bsw  )  )  ) 
}

rule capa_gather_cyberduck_information { 
  meta: 
 	description = "gather cyberduck information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://cyberduck.io/ftp/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-cyberduck-information.yml"
	date = "2021-05-15"

  strings: 
 	$bsx = /\\Cyberduck/ ascii wide 
	$str_bsy = "user.config" ascii wide
	$str_bsz = ".duck" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bsx 
	and  (  ( 	$str_bsy 
	or 	$str_bsz  )  )  ) 
}

rule capa_gather_ws_ftp_information { 
  meta: 
 	description = "gather ws-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.ipswitch.com/ftp-server"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ws-ftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$bta = /\\Ipswitch\\WS_FTP/ ascii wide 
	$btb = /\\win\.ini/ ascii wide 
	$btc = /WS_FTP/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bta 
	and 	$btb 
	and 	$btc  ) 
}

rule capa_gather_fling_ftp_information { 
  meta: 
 	description = "gather fling-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.nchsoftware.com/fling/index.html"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-fling-ftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$btd = /SOFTWARE\\NCH Software\\Fling\\Accounts/ ascii wide 
	$str_bte = "FtpPassword" ascii wide
	$str_btf = "_FtpPassword" ascii wide
	$str_btg = "FtpServer" ascii wide
	$str_bth = "FtpUserName" ascii wide
	$str_bti = "FtpDirectory" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$btd 
	or  (  ( 	$str_bte 
	and 	$str_btf 
	and 	$str_btg 
	and 	$str_bth 
	and 	$str_bti  )  )  ) 
}

rule capa_gather_directory_opus_information { 
  meta: 
 	description = "gather directory-opus information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.gpsoft.com.au/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-directory-opus-information.yml"
	date = "2021-05-15"

  strings: 
 	$btj = /\\GPSoftware\\Directory Opus/ ascii wide 
	$str_btk = ".oxc" ascii wide
	$str_btl = ".oll" ascii wide
	$str_btm = "ftplast.osd" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$btj 
	and 	$str_btk 
	and 	$str_btl 
	and 	$str_btm  ) 
}

rule capa_gather_coreftp_information { 
  meta: 
 	description = "gather coreftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www.coreftp.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-coreftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$btn = /Software\\FTPWare\\COREFTP\\Sites/ ascii wide 
	$str_bto = "Host" ascii wide
	$str_btp = "User" ascii wide
	$str_btq = "Port" ascii wide
	$str_btr = "PthR" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$btn 
	or  (  ( 	$str_bto 
	and 	$str_btp 
	and 	$str_btq 
	and 	$str_btr  )  )  ) 
}

rule capa_gather_wise_ftp_information { 
  meta: 
 	description = "gather wise-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.wise-ftp.de/en/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-wise-ftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bts = "wiseftpsrvs.ini" ascii wide
	$str_btt = "wiseftp.ini" ascii wide
	$str_btu = "wiseftpsrvs.bin" ascii wide
	$str_btv = "wiseftpsrvs.bin" ascii wide
	$btw = /\\AceBIT/ ascii wide 
	$btx = /Software\\AceBIT/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_bts 
	and 	$str_btt 
	and 	$str_btu  )  ) 
	or  (  ( 	$str_btv 
	and  (  ( 	$btw 
	or 	$btx  )  )  )  )  ) 
}

rule capa_gather_winzip_information { 
  meta: 
 	description = "gather winzip information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.winzip.com/win/en/pages/old-brands/nico-mak-computing/index.html"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-winzip-information.yml"
	date = "2021-05-15"

  strings: 
 	$bty = /Software\\Nico Mak Computing\\WinZip\\FTP/ ascii wide 
	$btz = /Software\\Nico Mak Computing\\WinZip\\mru\\jobs/ ascii wide 
	$str_bua = "Site" ascii wide
	$str_bub = "UserID" ascii wide
	$str_buc = "xflags" ascii wide
	$str_bud = "Port" ascii wide
	$str_bue = "Folder" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$bty 
	and 	$btz  )  ) 
	or  (  ( 	$str_bua 
	and 	$str_bub 
	and 	$str_buc 
	and 	$str_bud 
	and 	$str_bue  )  )  ) 
}

rule capa_gather_southriver_webdrive_information { 
  meta: 
 	description = "gather southriver-webdrive information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://southrivertech.com/products/webdriveclient/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-southriver-webdrive-information.yml"
	date = "2021-05-15"

  strings: 
 	$buf = /Software\\South River Technologies\\WebDrive\\Connections/ ascii wide 
	$str_bug = "PassWord" ascii wide
	$str_buh = "UserName" ascii wide
	$str_bui = "RootDirectory" ascii wide
	$str_buj = "Port" ascii wide
	$str_buk = "ServerType" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$buf 
	or  (  ( 	$str_bug 
	and 	$str_buh 
	and 	$str_bui 
	and 	$str_buj 
	and 	$str_buk  )  )  ) 
}

rule capa_gather_freshftp_information { 
  meta: 
 	description = "gather freshftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-freshftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bul = "FreshFTP" ascii wide
	$str_bum = ".SMF" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bul 
	and 	$str_bum  ) 
}

rule capa_gather_fasttrack_ftp_information { 
  meta: 
 	description = "gather fasttrack-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www.fasttracksoft.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-fasttrack-ftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bun = "FastTrack" ascii wide
	$str_buo = "ftplist.txt" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_bun 
	and 	$str_buo  )  )  ) 
}

rule capa_gather_classicftp_information { 
  meta: 
 	description = "gather classicftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.nchsoftware.com/classic/index.html"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-classicftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$bup = /Software\\NCH Software\\ClassicFTP\\FTPAccounts/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bup  ) 
}

rule capa_gather_softx_ftp_information { 
  meta: 
 	description = "gather softx-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www.softx.org/ftp.html"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-softx-ftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$buq = /Software\\FTPClient\\Sites/ ascii wide 
	$bur = /Software\\SoftX.org\\FTPClient\\Sites/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$buq 
	or 	$bur  ) 
}

rule capa_gather_ffftp_information { 
  meta: 
 	description = "gather ffftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www2.biglobe.ne.jp/sota/ffftp-e.html"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ffftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$bus = /Software\\Sota\\FFFTP\\Options/ ascii wide 
	$but = /Software\\Sota\\FFFTP/ ascii wide 
	$buu = /CredentialSalt/ ascii wide 
	$buv = /CredentialCheck/ ascii wide 
	$str_buw = "Password" ascii wide
	$str_bux = "UserName" ascii wide
	$str_buy = "HostAdrs" ascii wide
	$str_buz = "RemoteDir" ascii wide
	$str_bva = "Port" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  (  (  ( 	$bus 
	or 	$but  )  ) 
	and  (  ( 	$buu 
	or 	$buv  )  )  )  ) 
	or  (  ( 	$str_buw 
	and 	$str_bux 
	and 	$str_buy 
	and 	$str_buz 
	and 	$str_bva  )  )  ) 
}

rule capa_gather_ftpshell_information { 
  meta: 
 	description = "gather ftpshell information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.ftpshell.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftpshell-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bvb = "FTPShell" ascii wide
	$str_bvc = "ftpshell.fsi" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bvb 
	and 	$str_bvc  ) 
}

rule capa_gather_winscp_information { 
  meta: 
 	description = "gather winscp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://winscp.net/eng/download.php"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-winscp-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bvd = "Password" ascii wide
	$str_bve = "HostName" ascii wide
	$str_bvf = "UserName" ascii wide
	$str_bvg = "RemoteDirectory" ascii wide
	$str_bvh = "PortNumber" ascii wide
	$str_bvi = "FSProtocol" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bvd 
	and 	$str_bve 
	and 	$str_bvf 
	and 	$str_bvg 
	and 	$str_bvh 
	and 	$str_bvi  ) 
}

rule capa_gather_frigate3_information { 
  meta: 
 	description = "gather frigate3 information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www.frigate3.com/index.php"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-frigate3-information.yml"
	date = "2021-05-15"

  strings: 
 	$bvj = /FtpSite\.xml/ ascii wide 
	$bvk = /\\Frigate3/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bvj 
	and 	$bvk  ) 
}

rule capa_gather_staff_ftp_information { 
  meta: 
 	description = "gather staff-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.gsa-online.de/product/staffftp/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-staff-ftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bvl = "Staff-FTP" ascii wide
	$str_bvm = "sites.ini" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bvl 
	and 	$str_bvm  ) 
}

rule capa_gather_xftp_information { 
  meta: 
 	description = "gather xftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.netsarang.com/en/xftp-download/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-xftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bvn = ".xfp" ascii wide
	$bvo = /\\NetSarang/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bvn 
	and 	$bvo  ) 
}

rule capa_gather_leapftp_information { 
  meta: 
 	description = "gather leapftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-leapftp-information.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  strings: 
 	$str_bvp = "InstallPath" ascii wide
	$str_bvq = "DataDir" ascii wide
	$str_bvr = "sites.dat" ascii wide
	$str_bvs = "sites.ini" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_bvp 
	and 	$str_bvq 
	and 	$str_bvr 
	and 	$str_bvs  )  ) 
  ) 
}

rule capa_gather_ftpnow_information { 
  meta: 
 	description = "gather ftpnow information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftpnow-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bvv = "FTPNow" ascii wide
	$str_bvw = "FTP Now" ascii wide
	$str_bvx = "sites.xml" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bvv 
	and 	$str_bvw 
	and 	$str_bvx  ) 
}

rule capa_gather_ftpgetter_information { 
  meta: 
 	description = "gather ftpgetter information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.ftpgetter.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftpgetter-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bvy = "servers.xml" ascii wide
	$bvz = /\\FTPGetter/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bvy 
	and 	$bvz  ) 
}

rule capa_gather_nova_ftp_information { 
  meta: 
 	description = "gather nova-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-nova-ftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bwa = "NovaFTP.db" ascii wide
	$bwb = /\\INSoftware\\NovaFTP/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_bwa 
	and 	$bwb  )  )  ) 
}

rule capa_gather_ftp_explorer_information { 
  meta: 
 	description = "gather ftp-explorer information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www.ftpx.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftp-explorer-information.yml"
	date = "2021-05-15"

  strings: 
 	$bwc = /profiles\.xml/ ascii wide 
	$bwd = /Software\\FTP Explorer\\FTP Explorer\\Workspace\\MFCToolBar-224/ ascii wide 
	$bwe = /Software\\FTP Explorer\\Profiles/ ascii wide 
	$bwf = /\\FTP Explorer/ ascii wide 
	$str_bwg = "Password" ascii wide
	$str_bwh = "Host" ascii wide
	$str_bwi = "Login" ascii wide
	$str_bwj = "InitialPath" ascii wide
	$str_bwk = "PasswordType" ascii wide
	$str_bwl = "Port" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$bwc 
	and  (  ( 	$bwd 
	or 	$bwe 
	or 	$bwf  )  )  )  ) 
	or  (  ( 	$str_bwg 
	and 	$str_bwh 
	and 	$str_bwi 
	and 	$str_bwj 
	and 	$str_bwk 
	and 	$str_bwl  )  )  ) 
}

rule capa_gather_bitkinex_information { 
  meta: 
 	description = "gather bitkinex information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www.bitkinex.com/ftp/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-bitkinex-information.yml"
	date = "2021-05-15"

  strings: 
 	$bwm = /bitkinex\.ds/ ascii wide 
	$bwn = /\\BitKinex/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bwm 
	and 	$bwn  ) 
}

rule capa_gather_turbo_ftp_information { 
  meta: 
 	description = "gather turbo-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.tbsoftinc.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-turbo-ftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bwo = "addrbk.dat" ascii wide
	$str_bwp = "quick.dat" ascii wide
	$bwq = /installpath/ ascii wide 
	$bwr = /Software\\TurboFTP/ ascii wide 
	$bws = /\\TurboFTP/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_bwo 
	and 	$str_bwp  )  ) 
	or  (  ( 	$bwq 
	and  (  ( 	$bwr 
	or 	$bws  )  )  )  )  ) 
}

rule capa_gather_nexusfile_information { 
  meta: 
 	description = "gather nexusfile information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.xiles.app/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-nexusfile-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bwt = "NexusFile" ascii wide
	$str_bwu = "ftpsite.ini" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bwt 
	and 	$str_bwu  ) 
}

rule capa_gather_ftp_voyager_information { 
  meta: 
 	description = "gather ftp-voyager information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.serv-u.com/free-tools/ftp-voyager-ftp-client-for-windows"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftp-voyager-information.yml"
	date = "2021-05-15"

  strings: 
 	$bwv = /\\RhinoSoft.com/ ascii wide 
	$str_bww = "FTPVoyager.ftp" ascii wide
	$str_bwx = "FTPVoyager.qc" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bwv 
	and 	$str_bww 
	and 	$str_bwx  ) 
}

rule capa_gather_blazeftp_information { 
  meta: 
 	description = "gather blazeftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.slimjet.com/blazeftp/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-blazeftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bwy = "BlazeFtp" ascii wide
	$str_bwz = "site.dat" ascii wide
	$str_bxa = "LastPassword" ascii wide
	$str_bxb = "LastAddress" ascii wide
	$str_bxc = "LastUser" ascii wide
	$str_bxd = "LastPort" ascii wide
	$bxe = /Software\\FlashPeak\\BlazeFtp\\Settings/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bwy 
	and 	$str_bwz 
	and  (  ( 	$str_bxa 
	or 	$str_bxb 
	or 	$str_bxc 
	or 	$str_bxd 
	or 	$bxe  )  )  ) 
}

rule capa_gather_ftp_commander_information { 
  meta: 
 	description = "gather ftp-commander information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.ftpcommander.com/free.htm"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftp-commander-information.yml"
	date = "2021-05-15"

  strings: 
 	$bxf = /FTP Navigator/ ascii wide 
	$bxg = /FTP Commander/ ascii wide 
	$str_bxh = "ftplist.txt" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$bxf 
	or 	$bxg  )  ) 
	and  (  ( 	$str_bxh  )  )  ) 
}

rule capa_gather_global_downloader_information { 
  meta: 
 	description = "gather global-downloader information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www.actysoft.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-global-downloader-information.yml"
	date = "2021-05-15"

  strings: 
 	$bxo = /\\Global Downloader/ ascii wide 
	$str_bxp = "SM.arch" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bxo 
	and 	$str_bxp  ) 
}

rule capa_gather_faststone_browser_information { 
  meta: 
 	description = "gather faststone-browser information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.faststone.org/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-faststone-browser-information.yml"
	date = "2021-05-15"

  strings: 
 	$bxx = /FastStone Browser/ ascii wide 
	$str_bxy = "FTPList.db" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bxx 
	and 	$str_bxy  ) 
}

rule capa_gather_ultrafxp_information { 
  meta: 
 	description = "gather ultrafxp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ultrafxp-information.yml"
	date = "2021-05-15"

  strings: 
 	$bxz = /UltraFXP/ ascii wide 
	$bya = /\\sites\.xml/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bxz 
	and 	$bya  ) 
}

rule capa_gather_netdrive_information { 
  meta: 
 	description = "gather netdrive information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.netdrive.net/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-netdrive-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_byb = "NDSites.ini" ascii wide
	$byc = /\\NetDrive/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_byb 
	and 	$byc  ) 
}

rule capa_gather_total_commander_information { 
  meta: 
 	description = "gather total-commander information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.ghisler.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-total-commander-information.yml"
	date = "2021-05-15"

  strings: 
 	$byd = /Software\\Ghisler\\Total Commander/ ascii wide 
	$bye = /Software\\Ghisler\\Windows Commander/ ascii wide 
	$str_byf = "FtpIniName" ascii wide
	$str_byg = "wcx_ftp.ini" ascii wide
	$byh = /\\GHISLER/ ascii wide 
	$str_byi = "InstallDir" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$byd 
	or 	$bye  )  ) 
	and  (  ( 	$str_byf 
	or 	$str_byg 
	or 	$byh 
	or 	$str_byi  )  )  ) 
}

rule capa_gather_ftpinfo_information { 
  meta: 
 	description = "gather ftpinfo information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.ftpinfo.ru/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftpinfo-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_byj = "ServerList.xml" ascii wide
	$str_byk = "DataDir" ascii wide
	$byl = /Software\\MAS-Soft\\FTPInfo\\Setup/ ascii wide 
	$bym = /FTPInfo/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_byj 
	and 	$str_byk 
	and  (  ( 	$byl 
	or 	$bym  )  )  ) 
}

rule capa_gather_flashfxp_information { 
  meta: 
 	description = "gather flashfxp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.flashfxp.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-flashfxp-information.yml"
	date = "2021-05-15"

  strings: 
 	$byn = /Software\\FlashFXP/ ascii wide 
	$byo = /DataFolder/ ascii wide 
	$byp = /Install Path/ ascii wide 
	$byq = /\\Sites.dat/ ascii wide 
	$byr = /\\Quick.dat/ ascii wide 
	$bys = /\\History.dat/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$byn 
	and 	$byo 
	and 	$byp  )  ) 
	or  (  ( 	$byq 
	and 	$byr 
	and 	$bys  )  )  ) 
}

rule capa_gather_securefx_information { 
  meta: 
 	description = "gather securefx information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.vandyke.com/products/securefx/index.html"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-securefx-information.yml"
	date = "2021-05-15"

  strings: 
 	$byt = /\\Sessions/ ascii wide 
	$str_byu = ".ini" ascii wide
	$byv = /Config Path/ ascii wide 
	$byw = /_VanDyke\\Config\\Sessions/ ascii wide 
	$byx = /Software\\VanDyke\\SecureFX/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$byt 
	and 	$str_byu 
	and 	$byv 
	and  (  ( 	$byw 
	or 	$byx  )  )  ) 
}

rule capa_gather_robo_ftp_information { 
  meta: 
 	description = "gather robo-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.robo-ftp.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-robo-ftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$byy = /SOFTWARE\\Robo-FTP/ ascii wide 
	$byz = /\\FTPServers/ ascii wide 
	$bza = /FTP File/ ascii wide 
	$str_bzb = "FTP Count" ascii wide
	$str_bzc = "Password" ascii wide
	$str_bzd = "ServerName" ascii wide
	$str_bze = "UserID" ascii wide
	$str_bzf = "PortNumber" ascii wide
	$str_bzg = "InitialDirectory" ascii wide
	$str_bzh = "ServerType" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$byy 
	and  (  ( 	$byz 
	or 	$bza 
	or 	$str_bzb  )  )  )  ) 
	or  (  ( 	$str_bzc 
	and 	$str_bzd 
	and 	$str_bze 
	and 	$str_bzf 
	and 	$str_bzg 
	and 	$str_bzh  )  )  ) 
}

rule capa_gather_bulletproof_ftp_information { 
  meta: 
 	description = "gather bulletproof-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://bpftp.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-bulletproof-ftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bzi = ".dat" ascii wide
	$str_bzj = ".bps" ascii wide
	$bzk = /Software\\BPFTP\\Bullet Proof FTP\\Main/ ascii wide 
	$bzl = /Software\\BulletProof Software\\BulletProof FTP Client\\Main/ ascii wide 
	$bzm = /Software\\BulletProof Software\\BulletProof FTP Client\\Options/ ascii wide 
	$bzn = /Software\\BPFTP\\Bullet Proof FTP\\Options/ ascii wide 
	$bzo = /Software\\BPFTP/ ascii wide 
	$str_bzp = "LastSessionFile" ascii wide
	$str_bzq = "SitesDir" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_bzi 
	and 	$str_bzj  )  ) 
	or  (  (  (  ( 	$bzk 
	or 	$bzl 
	or 	$bzm 
	or 	$bzn 
	or 	$bzo  )  ) 
	and  (  ( 	$str_bzp 
	or 	$str_bzq  )  )  )  )  ) 
}

rule capa_gather_alftp_information { 
  meta: 
 	description = "gather alftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://en.wikipedia.org/wiki/ALFTP"
	references = "https://www.altools.co.kr/Main/Default.aspx"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-alftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bzr = "ESTdb2.dat" ascii wide
	$str_bzs = "QData.dat" ascii wide
	$bzt = /\\Estsoft\\ALFTP/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bzr 
	and 	$str_bzs 
	and 	$bzt  ) 
}

rule capa_gather_expandrive_information { 
  meta: 
 	description = "gather expandrive information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.expandrive.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-expandrive-information.yml"
	date = "2021-05-15"

  strings: 
 	$bzu = /Software\\ExpanDrive\\Sessions/ ascii wide 
	$bzv = /Software\\ExpanDrive/ ascii wide 
	$bzw = /ExpanDrive_Home/ ascii wide 
	$bzx = /\\drives\.js/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$bzu 
	or 	$bzv  )  ) 
	and  (  ( 	$bzw 
	or 	$bzx  )  )  ) 
}

rule capa_gather_goftp_information { 
  meta: 
 	description = "gather goftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.goftp.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-goftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_bzy = "GoFTP" ascii wide
	$str_bzz = "Connections.txt" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bzy 
	and 	$str_bzz  ) 
}

rule capa_gather_3d_ftp_information { 
  meta: 
 	description = "gather 3d-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.3dftp.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-3d-ftp-information.yml"
	date = "2021-05-15"

  strings: 
 	$str_caa = "3D-FTP" ascii wide
	$str_cab = "sites.ini" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_caa 
	and 	$str_cab  ) 
}

rule capa_reference_SQL_statements { 
  meta: 
 	description = "reference SQL statements (converted from capa rule)"
	namespace = "collection/database/sql"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Collection::Data from Information Repositories [T1213]"
	hash = "5F66B82558CA92E54E77F216EF4C066C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/database/sql/reference-sql-statements.yml"
	date = "2021-05-15"

  strings: 
 	$cah = /SELECT.{,1000}FROM.{,1000}WHERE/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$cah  ) 
}

rule capa_reference_WMI_statements { 
  meta: 
 	description = "reference WMI statements (converted from capa rule)"
	namespace = "collection/database/wmi"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Collection::Data from Information Repositories [T1213]"
	hash = "al-khaser_x86.exe_:0x433490"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/database/wmi/reference-wmi-statements.yml"
	date = "2021-05-15"

  strings: 
 	$cai = /SELECT\s+\*\s+FROM\s+CIM_./ ascii wide 
	$caj = /SELECT\s+\*\s+FROM\s+Win32_./ ascii wide 
	$cak = /SELECT\s+\*\s+FROM\s+MSAcpi_./ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$cai 
	or 	$caj 
	or 	$cak  ) 
}

rule capa_create_reverse_shell { 
  meta: 
 	description = "create reverse shell (converted from capa rule)"
	namespace = "c2/shell"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Execution::Command and Scripting Interpreter::Windows Command Shell [T1059.003]"
	mbc = "Impact::Remote Access::Reverse Shell [B0022.001]"
	hash = "C91887D861D9BD4A5872249B641BC9F9"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/c2/shell/create-reverse-shell.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported featre and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_create_pipe

	and 	pe.imports(/kernel32/i, /PeekNamedPipe/) 
	and 	pe.imports(/kernel32/i, /CreateProcess/) 
	and 	pe.imports(/kernel32/i, /ReadFile/) 
	and 	pe.imports(/kernel32/i, /WriteFile/)  )  ) 
	or  (  ( 	capa_create_process

	and 	capa_read_pipe

	and 	capa_write_pipe
 )  ) 
  ) 
}

rule capa_write_and_execute_a_file { 
  meta: 
 	description = "write and execute a file (converted from capa rule)"
	namespace = "c2/file-transfer"
	maec_malware_category = "launcher"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Execution::Install Additional Program [B0023]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	hash = "Practical Malware Analysis Lab 01-04.exe_:0x4011FC"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/c2/file-transfer/write-and-execute-a-file.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_write_file

	and 	capa_create_process
 ) 
}

rule capa_self_delete_via_COMSPEC_environment_variable { 
  meta: 
 	description = "self delete via COMSPEC environment variable (converted from capa rule)"
	namespace = "anti-analysis/anti-forensic/self-deletion"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Indicator Removal on Host::File Deletion [T1070.004]"
	mbc = "Defense Evasion::Self Deletion::COMSPEC Environment Variable [F0007.001]"
	hash = "Practical Malware Analysis Lab 14-02.exe_:0x401880"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-forensic/self-deletion/self-delete-via-comspec-environment-variable.yml"
	date = "2021-05-15"

  strings: 
 	$cam = /\/c\s*del\s*/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_get_COMSPEC_environment_variable

	and 	capa_create_process

	and 	$cam  ) 
}

rule capa_check_for_windows_sandbox_via_process_name { 
  meta: 
 	description = "check for windows sandbox via process name (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "@_re_fox"
	scope = "function"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LloydLabs/wsb-detect"
	hash = "773290480d5445f11d3dc1b800728966"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-windows-sandbox-via-process-name.yml"
	date = "2021-05-15"

  strings: 
 	$str_cap = "CExecSvc.exe" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_enumerate_processes

	and 	$str_cap  ) 
}

rule capa_get_CPU_information { 
  meta: 
 	description = "get CPU information (converted from capa rule)"
	namespace = "host-interaction/hardware/cpu"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/cpu/get-cpu-information.yml"
	date = "2021-05-15"

  strings: 
 	$cbe = /Hardware\\Description\\System\\CentralProcessor/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_query_or_enumerate_registry_value

	and 	$cbe  ) 
}

rule capa_disable_code_signing { 
  meta: 
 	description = "disable code signing (converted from capa rule)"
	namespace = "host-interaction/bootloader"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Subvert Trust Controls::Code Signing Policy Modification [T1553.006]"
	hash = "0596C4EA5AA8DEF47F22C85D75AACA95"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/bootloader/disable-code-signing.yml"
	date = "2021-05-15"

  strings: 
 	$cbf = /\bbcdedit(\.exe)? -set TESTSIGNING ON/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_create_process

	and 	$cbf  ) 
}

rule capa_find_taskbar { 
  meta: 
 	description = "find taskbar (converted from capa rule)"
	namespace = "host-interaction/gui/taskbar/find"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Discovery::Taskbar Discovery [B0043]"
	hash = "B7841B9D5DC1F511A93CC7576672EC0C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/taskbar/find/find-taskbar.yml"
	date = "2021-05-15"

  strings: 
 	$str_cbg = "Shell_TrayWnd" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_cbg 
	and 	capa_find_graphical_window
 ) 
}

rule capa_check_mutex { 
  meta: 
 	description = "check mutex (converted from capa rule)"
	namespace = "host-interaction/mutex"
	author = "moritz.raabem@fireeye.com"
	scope = "basic block"
	mbc = "Process::Check Mutex [C0043]"
	hash = "Practical Malware Analysis Lab 01-01.dll_:0x10001010"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/mutex/check-mutex.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/kernel32/i, /OpenMutex/) 
	or 	capa_create_mutex
 )  )  ) 
}

rule capa_linked_against_Go_process_enumeration_library { 
  meta: 
 	description = "linked against Go process enumeration library (converted from capa rule)"
	namespace = "host-interaction/process/list"
	author = "joakim@intezer.com"
	description = "Enumerating processes using a Go library"
	scope = "file"
	attack = "Discovery::Process Discovery [T1057]"
	attack = "Discovery::Software Discovery [T1518]"
	references = "https://pkg.go.dev/github.com/mitchellh/go-ps"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-go-process-enumeration-library.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_ccq = "github.com/mitchellh/go-ps.FindProcess" ascii wide
	$str_ccr = "github.com/mitchellh/go-ps.Processes" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_compiled_with_Go

	and  (  (  (  ( 	$str_ccq 
	or 	$str_ccr  )  )  )  )  ) 
}

rule capa_linked_against_Go_WMI_library { 
  meta: 
 	description = "linked against Go WMI library (converted from capa rule)"
	namespace = "collection/database/wmi"
	author = "joakim@intezer.com"
	description = "StackExchange's WMI library is used to interact with WMI."
	scope = "file"
	attack = "Collection::Data from Information Repositories [T1213]"
	references = "https://github.com/StackExchange/wmi"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-go-wmi-library.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_cdd = "github.com/StackExchange/wmi.CreateQuery" ascii wide
	$str_cde = "github.com/StackExchange/wmi.Query" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_compiled_with_Go

	and  (  (  (  ( 	$str_cdd 
	or 	$str_cde  )  )  )  )  ) 
}

rule capa_send_HTTP_request_with_Host_header { 
  meta: 
 	description = "send HTTP request with Host header (converted from capa rule)"
	namespace = "communication/http"
	author = "anamaria.martinezgom@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/send-http-request-with-host-header.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$cdf = /Host:/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_send_HTTP_request

	and 	$cdf  ) 
}

rule capa_check_for_windows_sandbox_via_mutex { 
  meta: 
 	description = "check for windows sandbox via mutex (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "@_re_fox"
	scope = "function"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LloydLabs/wsb-detect"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/check-for-windows-sandbox-via-mutex.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_cdg = "WindowsSandboxMutex" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_check_mutex

	and 	$str_cdg  ) 
}

rule capa_linked_against_Go_registry_library { 
  meta: 
 	description = "linked against Go registry library (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "joakim@intezer.com"
	description = "Uses a Go library for interacting with the Windows registry."
	scope = "file"
	references = "https://github.com/golang/sys"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-go-registry-library.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_cdh = "golang.org/x/sys/windows/registry.Key.Close" ascii wide
	$str_cdi = "github.com/golang/sys/windows/registry.Key.Close" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_compiled_with_Go

	and  (  ( 	$str_cdh 
	or 	$str_cdi  )  )  ) 
}

rule capa_capture_screenshot_in_Go { 
  meta: 
 	description = "capture screenshot in Go (converted from capa rule)"
	namespace = "collection/screenshot"
	author = "joakim@intezer.com"
	description = "Detects screenshot capability via WinAPI for Go files."
	scope = "file"
	attack = "Collection::Screen Capture [T1113]"
	mbc = "Collection::Screen Capture::WinAPI [E1113.m01]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/capture-screenshot-in-go.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_cdn = "syscall.NewLazyDLL" ascii wide
	$cdo = /user32.dll/ ascii wide 
	$cdp = /GetWindowDC/ ascii wide 
	$cdq = /GetDC/ ascii wide 
	$cdr = /gdi32.dll/ ascii wide 
	$cds = /BitBlt/ ascii wide 
	$cdt = /GetDIBits/ ascii wide 
	$cdu = /CreateCompatibleDC/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_compiled_with_Go

	and  (  (  (  ( 	$str_cdn 
	and  (  (  (  ( 	$cdo 
	and  (  ( 	$cdp 
	or 	$cdq  )  )  )  ) 
	or  (  ( 	$cdr 
	and  (  ( 	$cds 
	or 	$cdt  )  )  )  )  )  ) 
	and 	$cdu  )  )  )  )  ) 
}

rule capa_linked_against_Go_static_asset_library { 
  meta: 
 	description = "linked against Go static asset library (converted from capa rule)"
	namespace = "executable/resource"
	author = "joakim@intezer.com"
	description = "Detects if the Go file includes an static assets."
	scope = "file"
	references = "https://github.com/rakyll/statik"
	references = "https://github.com/gobuffalo/packr"
	references = "https://github.com/GeertJohan/go.rice"
	references = "https://github.com/kevinburke/go-bindata"
	references = "https://github.com/lu4p/binclude"
	references = "https://github.com/omeid/go-resources"
	references = "https://github.com/pyros2097/go-embed"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-go-static-asset-library.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_cdw = "github.com/rakyll/statik/fs.IsDefaultNamespace" ascii wide
	$str_cdx = "github.com/rakyll/statik/fs.RegisterWithNamespace" ascii wide
	$str_cdy = "github.com/rakyll/statik/fs.NewWithNamespace" ascii wide
	$str_cdz = "github.com/rakyll/statik/fs.Register" ascii wide
	$str_cea = "github.com/gobuffalo/packr.NewBox" ascii wide
	$str_ceb = "github.com/markbates/pkger.Open" ascii wide
	$str_cec = "github.com/markbates/pkger.Include" ascii wide
	$str_ced = "github.com/markbates/pkger.Parse" ascii wide
	$str_cee = "github.com/GeertJohan/go.rice.FindBox" ascii wide
	$str_cef = "github.com/GeertJohan/go.rice.MustFindBox" ascii wide
	$ceg = /\/bindata\.go/ ascii wide 
	$ceh = /\.Asset/ ascii wide 
	$str_cei = "github.com/lu4p/binclude.Include" ascii wide
	$str_cej = "github.com/omeid/go-resources" ascii wide
	$str_cek = "github.com/pyros2097/go-embed" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_compiled_with_Go

	and  (  (  (  ( 	$str_cdw 
	or 	$str_cdx 
	or 	$str_cdy 
	or 	$str_cdz  )  ) 
	or  (  ( 	$str_cea  )  ) 
	or  (  ( 	$str_ceb 
	or 	$str_cec 
	or 	$str_ced  )  ) 
	or  (  ( 	$str_cee 
	or 	$str_cef  )  ) 
	or  (  ( 	$ceg 
	and 	$ceh  )  ) 
	or  (  ( 	$str_cei  )  ) 
	or  (  ( 	$str_cej  )  ) 
	or  (  ( 	$str_cek  )  )  )  )  ) 
}

rule capa_make_an_HTTP_request_with_a_Cookie { 
  meta: 
 	description = "make an HTTP request with a Cookie (converted from capa rule)"
	namespace = "communication/http/client"
	author = "anamaria.martinezgom@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/make-an-http-request-with-a-cookie.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$cel = /Cookie:/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_send_HTTP_request

	and 	$cel  ) 
}

rule capa_receive_data { 
  meta: 
 	description = "receive data (converted from capa rule)"
	namespace = "communication"
	author = "william.ballenthin@fireeye.com"
	description = "all known techniques for receiving data from a potential C2 server"
	scope = "function"
	mbc = "Command and Control::C2 Communication::Receive Data [B0030.002]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/receive-data.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_receive_data_on_socket

	or 	capa_read_data_from_Internet

	or 	capa_download_URL_to_file
 ) 
}

rule capa_send_data { 
  meta: 
 	description = "send data (converted from capa rule)"
	namespace = "communication"
	author = "william.ballenthin@fireeye.com"
	description = "all known techniques for sending data to a potential C2 server"
	scope = "function"
	mbc = "Command and Control::C2 Communication::Send Data [B0030.001]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/send-data.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_send_HTTP_request

	or 	capa_send_data_on_socket

	or 	capa_send_file_via_HTTP
 ) 
}

rule capa_download_and_write_a_file { 
  meta: 
 	description = "download and write a file (converted from capa rule)"
	namespace = "c2/file-transfer"
	maec_malware_category = "downloader"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Command and Control::Ingress Tool Transfer [T1105]"
	mbc = "Command and Control::C2 Communication::Server to Client File Transfer [B0030.003]"
	hash = "5D7C34B6854D48D3DA4F96B71550A221"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/c2/file-transfer/download-and-write-a-file.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_receive_data

	and 	capa_write_file
 ) 
}

rule capa_read_and_send_data_from_client_to_server { 
  meta: 
 	description = "read and send data from client to server (converted from capa rule)"
	namespace = "c2/file-transfer"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/read-and-send-data-from-client-to-server.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_read_file

	and 	capa_send_data
 ) 
}

rule capa_receive_and_write_data_from_server_to_client { 
  meta: 
 	description = "receive and write data from server to client (converted from capa rule)"
	namespace = "c2/file-transfer"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/receive-and-write-data-from-server-to-client.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_receive_data

	and 	capa_write_file
 ) 
}

// done, converted rules: 390
// done, unconverted rules: 155

