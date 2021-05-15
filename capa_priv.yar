//POC: rules from https://github.com/fireeye/capa-rules converted to YARA using capa2yara.py by Arnim Rupp (not published yet)

//Beware: This has less rules than capa (because not all fit into YARA) and is less precise because e.g. capas function scopes are applied to the whole file

//Beware: Some rules are incomplete because an optional branch was not supported by yara. These rules are marked in a comment in meta: (search for incomplete)


import "pe"


private rule capa_create_or_open_file { 
  meta: 
 	description = "create or open file (converted from capa rule)"
	author = "michael.hunhoff@fireeye.com"
	lib = "True"
	scope = "basic block"
	mbc = "File System::Create File [C0016]"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/create-or-open-file.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /CreateFile/) 
	or 	pe.imports(/.{1,30}/i, /CreateFileEx/) 
	or 	pe.imports(/.{1,30}/i, /IoCreateFile/) 
	or 	pe.imports(/.{1,30}/i, /IoCreateFileEx/) 
	or 	pe.imports(/.{1,30}/i, /ZwOpenFile/) 
	or 	pe.imports(/.{1,30}/i, /ZwCreateFile/) 
	or 	pe.imports(/.{1,30}/i, /NtOpenFile/) 
	or 	pe.imports(/.{1,30}/i, /NtCreateFile/)  ) 
}

private rule capa_open_thread { 
  meta: 
 	description = "open thread (converted from capa rule)"
	author = "0x534a@mailbox.org"
	lib = "True"
	scope = "basic block"
	hash = "787cbc8a6d1bc58ea169e51e1ad029a637f22560660cc129ab8a099a745bd50e:00502F4C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/open-thread.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /OpenThread/) 
	or 	pe.imports(/.{1,30}/i, /NtOpenThread/) 
	or 	pe.imports(/.{1,30}/i, /ZwOpenThread/)  ) 
}

private rule capa_allocate_memory { 
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
	or 	pe.imports(/.{1,30}/i, /NtAllocateVirtualMemory/) 
	or 	pe.imports(/.{1,30}/i, /ZwAllocateVirtualMemory/) 
	or 	pe.imports(/.{1,30}/i, /NtMapViewOfSection/) 
	or 	pe.imports(/.{1,30}/i, /ZwMapViewOfSection/)  ) 
}

private rule capa_delay_execution { 
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
	or 	pe.imports(/.{1,30}/i, /WaitOnAddress/) 
	or 	pe.imports(/user32/i, /MsgWaitForMultipleObjects/) 
	or 	pe.imports(/user32/i, /MsgWaitForMultipleObjectsEx/) 
	or 	pe.imports(/.{1,30}/i, /NtDelayExecution/) 
	or 	pe.imports(/.{1,30}/i, /KeWaitForSingleObject/) 
	or 	pe.imports(/.{1,30}/i, /KeDelayExecutionThread/)  ) 
}

private rule capa_write_process_memory { 
  meta: 
 	description = "write process memory (converted from capa rule)"
	author = "moritz.raabe@fireeye.com"
	lib = "True"
	scope = "function"
	attack = "Defense Evasion::Process Injection [T1055]"
	hash = "2D3EDC218A90F03089CC01715A9F047F"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/write-process-memory.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /WriteProcessMemory/) 
	or 	pe.imports(/ntdll/i, /NtWriteVirtualMemory/) 
	or 	pe.imports(/ntdll/i, /ZwWriteVirtualMemory/) 
	or 	pe.imports(/.{1,30}/i, /NtWow64WriteVirtualMemory64/)  ) 
}

private rule capa_open_process { 
  meta: 
 	description = "open process (converted from capa rule)"
	author = "0x534a@mailbox.org"
	lib = "True"
	scope = "basic block"
	hash = "Practical Malware Analysis Lab 17-02.dll_:0x1000D10D"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/open-process.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /OpenProcess/) 
	or 	pe.imports(/.{1,30}/i, /NtOpenProcess/) 
	or 	pe.imports(/.{1,30}/i, /ZwOpenProcess/)  ) 
}

private rule capa_delete_volume_shadow_copies { 
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
 	$aab = /vssadmin.{,1000} delete shadows/ nocase ascii wide 
	$aac = /vssadmin.{,1000} resize shadowstorage/ nocase ascii wide 
	$aad = /wmic.{,1000} shadowcopy delete/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aab 
	or 	$aac 
	or 	$aad  ) 
}

private rule capa_reference_analysis_tools_strings { 
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
 	$aae = /ollydbg.exe/ nocase ascii wide 
	$aaf = /ProcessHacker.exe/ nocase ascii wide 
	$aag = /tcpview.exe/ nocase ascii wide 
	$aah = /autoruns.exe/ nocase ascii wide 
	$aai = /autorunsc.exe/ nocase ascii wide 
	$aaj = /filemon.exe/ nocase ascii wide 
	$aak = /procmon.exe/ nocase ascii wide 
	$aal = /regmon.exe/ nocase ascii wide 
	$aam = /procexp.exe/ nocase ascii wide 
	$aan = /idaq.exe/ nocase ascii wide 
	$aao = /idaq64.exe/ nocase ascii wide 
	$aap = /ImmunityDebugger.exe/ nocase ascii wide 
	$aaq = /Wireshark.exe/ nocase ascii wide 
	$aar = /dumpcap.exe/ nocase ascii wide 
	$aas = /HookExplorer.exe/ nocase ascii wide 
	$aat = /ImportREC.exe/ nocase ascii wide 
	$aau = /PETools.exe/ nocase ascii wide 
	$aav = /LordPE.exe/ nocase ascii wide 
	$aaw = /SysInspector.exe/ nocase ascii wide 
	$aax = /proc_analyzer.exe/ nocase ascii wide 
	$aay = /sysAnalyzer.exe/ nocase ascii wide 
	$aaz = /sniff_hit.exe/ nocase ascii wide 
	$aba = /windbg.exe/ nocase ascii wide 
	$abb = /joeboxcontrol.exe/ nocase ascii wide 
	$abc = /joeboxserver.exe/ nocase ascii wide 
	$abd = /ResourceHacker.exe/ nocase ascii wide 
	$abe = /x32dbg.exe/ nocase ascii wide 
	$abf = /x64dbg.exe/ nocase ascii wide 
	$abg = /Fiddler.exe/ nocase ascii wide 
	$abh = /httpdebugger.exe/ nocase ascii wide 
	$abi = /fakenet.exe/ nocase ascii wide 
	$abj = /netmon.exe/ nocase ascii wide 
	$abk = /WPE PRO.exe/ nocase ascii wide 
	$abl = /decompile.exe/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aae 
	or 	$aaf 
	or 	$aag 
	or 	$aah 
	or 	$aai 
	or 	$aaj 
	or 	$aak 
	or 	$aal 
	or 	$aam 
	or 	$aan 
	or 	$aao 
	or 	$aap 
	or 	$aaq 
	or 	$aar 
	or 	$aas 
	or 	$aat 
	or 	$aau 
	or 	$aav 
	or 	$aaw 
	or 	$aax 
	or 	$aay 
	or 	$aaz 
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
	or 	$abl  ) 
}

private rule capa_timestomp_file { 
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

private rule capa_clear_the_Windows_event_log { 
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

private rule capa_check_for_sandbox_and_av_modules { 
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
 	$abm = /avghook(x|a)\.dll/ nocase ascii wide 
	$abn = /snxhk\.dll/ nocase ascii wide 
	$abo = /sf2\.dll/ nocase ascii wide 
	$abp = /sbiedll\.dll/ nocase ascii wide 
	$abq = /dbghelp\.dll/ nocase ascii wide 
	$abr = /api_log\.dll/ nocase ascii wide 
	$abs = /dir_watch\.dll/ ascii wide 
	$abt = /pstorec\.dll/ nocase ascii wide 
	$abu = /vmcheck\.dll/ nocase ascii wide 
	$abv = /wpespy\.dll/ nocase ascii wide 
	$abw = /cmdvrt(64|32).dll/ nocase ascii wide 
	$abx = /sxin.dll/ nocase ascii wide 
	$aby = /dbghelp\.dll/ nocase ascii wide 
	$abz = /printfhelp\.dll/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /GetModuleHandle/) 
	and  (  ( 	$abm 
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
	or 	$abz  )  )  ) 
}

private rule capa_packed_with_pebundle { 
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
 ( 	for any aca in pe.sections : ( aca.name == "pebundle" ) 
	or 	for any acb in pe.sections : ( acb.name == "PEBundle" )  ) 
}

private rule capa_packed_with_ASPack { 
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
 	$str_acg = "The procedure entry point %s could not be located in the dynamic link library %s" ascii wide
	$str_ach = "The ordinal %u could not be located in the dynamic link library %s" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any acc in pe.sections : ( acc.name == ".aspack" ) 
	or 	for any acd in pe.sections : ( acd.name == ".adata" ) 
	or 	for any ace in pe.sections : ( ace.name == ".ASPack" ) 
	or 	for any acf in pe.sections : ( acf.name == "ASPack" ) 
	or 	$str_acg 
	or 	$str_ach  ) 
}

private rule capa_packed_with_nspack { 
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
 ( 	for any aci in pe.sections : ( aci.name == ".nsp0" ) 
	or 	for any acj in pe.sections : ( acj.name == ".nsp1" ) 
	or 	for any ack in pe.sections : ( ack.name == ".nsp2" )  ) 
}

private rule capa_packed_with_kkrunchy { 
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
 ( 	for any acl in pe.sections : ( acl.name == "kkrunchy" )  ) 
}

private rule capa_packed_with_petite { 
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
 ( 	for any acm in pe.sections : ( acm.name == ".petite" )  ) 
}

private rule capa_packed_with_pelocknt { 
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
 ( 	for any acn in pe.sections : ( acn.name == "PELOCKnt" )  ) 
}

private rule capa_packed_with_upack { 
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
 	$str_acq = "UpackByDwing@" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any aco in pe.sections : ( aco.name == ".Upack" ) 
	or 	for any acp in pe.sections : ( acp.name == ".ByDwing" ) 
	or 	$str_acq  ) 
}

private rule capa_packed_with_y0da_crypter { 
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
 ( 	for any acr in pe.sections : ( acr.name == ".y0da" ) 
	or 	for any acs in pe.sections : ( acs.name == ".y0da_1" ) 
	or 	for any act in pe.sections : ( act.name == ".yP" )  ) 
}

private rule capa_packed_with_Confuser { 
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
 	$str_acu = "ConfusedByAttribute" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_acu  ) 
}

private rule capa_packed_with_amber { 
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
 	$str_acv = "Amber - Reflective PE Packer" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_acv  ) 
}

private rule capa_packed_with_VMProtect { 
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
 	$str_acw = "A debugger has been found running in your system." ascii wide
	$str_acx = "Please, unload it from memory and restart your program." ascii wide
	$str_acy = "File corrupted!. This program has been manipulated and maybe" ascii wide
	$str_acz = "it's infected by a Virus or cracked. This file won't work anymore." ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_acw 
	or 	$str_acx 
	or 	$str_acy 
	or 	$str_acz 
	or 	for any ada in pe.sections : ( ada.name == ".vmp0" ) 
	or 	for any adb in pe.sections : ( adb.name == ".vmp1" ) 
	or 	for any adc in pe.sections : ( adc.name == ".vmp2" )  ) 
}

private rule capa_packed_with_rlpack { 
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
 ( 	for any add in pe.sections : ( add.name == ".RLPack" ) 
	or 	for any ade in pe.sections : ( ade.name == ".packed" )  ) 
}

private rule capa_packed_with_UPX { 
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
 ( 	for any adf in pe.sections : ( adf.name == "UPX0" ) 
	or 	for any adg in pe.sections : ( adg.name == "UPX1" )  ) 
}

private rule capa_packed_with_peshield { 
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
 	$adj = / PE-SHiELD v[0-9]\.[0-9]/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	for any adh in pe.sections : ( adh.name == "PESHiELD" ) 
	or 	for any adi in pe.sections : ( adi.name == "PESHiELD_1" ) 
	or 	$adj  ) 
}

private rule capa_reference_anti_VM_strings_targeting_VMWare { 
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
 	$adl = /VMWare/ nocase ascii wide 
	$adm = /VMTools/ nocase ascii wide 
	$adn = /SOFTWARE\\VMware, Inc\.\\VMware Tools/ nocase ascii wide 
	$ado = /vmnet.sys/ nocase ascii wide 
	$adp = /vmmouse.sys/ nocase ascii wide 
	$adq = /vmusb.sys/ nocase ascii wide 
	$adr = /vm3dmp.sys/ nocase ascii wide 
	$ads = /vmci.sys/ nocase ascii wide 
	$adt = /vmhgfs.sys/ nocase ascii wide 
	$adu = /vmmemctl.sys/ nocase ascii wide 
	$adv = /vmx86.sys/ nocase ascii wide 
	$adw = /vmrawdsk.sys/ nocase ascii wide 
	$adx = /vmusbmouse.sys/ nocase ascii wide 
	$ady = /vmkdb.sys/ nocase ascii wide 
	$adz = /vmnetuserif.sys/ nocase ascii wide 
	$aea = /vmnetadapter.sys/ nocase ascii wide 
	$aeb = /\\\\.\\HGFS/ nocase ascii wide 
	$aec = /\\\\.\\vmci/ nocase ascii wide 
	$aed = /vmtoolsd.exe/ nocase ascii wide 
	$aee = /vmwaretray.exe/ nocase ascii wide 
	$aef = /vmwareuser.exe/ nocase ascii wide 
	$aeg = /VGAuthService.exe/ nocase ascii wide 
	$aeh = /vmacthlp.exe/ nocase ascii wide 
	$aei = /vmci/ nocase ascii wide 
	$aej = /vmhgfs/ nocase ascii wide 
	$aek = /vmmouse/ nocase ascii wide 
	$ael = /vmmemctl/ nocase ascii wide 
	$aem = /vmusb/ nocase ascii wide 
	$aen = /vmusbmouse/ nocase ascii wide 
	$aeo = /vmx_svga/ nocase ascii wide 
	$aep = /vmxnet/ nocase ascii wide 
	$aeq = /vmx86/ nocase ascii wide 
	$aer = /VMwareVMware/ nocase ascii wide 
	$aes = /vmGuestLib.dll/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$adl 
	or 	$adm 
	or 	$adn 
	or 	$ado 
	or 	$adp 
	or 	$adq 
	or 	$adr 
	or 	$ads 
	or 	$adt 
	or 	$adu 
	or 	$adv 
	or 	$adw 
	or 	$adx 
	or 	$ady 
	or 	$adz 
	or 	$aea 
	or 	$aeb 
	or 	$aec 
	or 	$aed 
	or 	$aee 
	or 	$aef 
	or 	$aeg 
	or 	$aeh 
	or 	$aei 
	or 	$aej 
	or 	$aek 
	or 	$ael 
	or 	$aem 
	or 	$aen 
	or 	$aeo 
	or 	$aep 
	or 	$aeq 
	or 	$aer 
	or 	$aes  ) 
}

private rule capa_check_for_windows_sandbox_via_device { 
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
 	$str_aet = "\\\\.\\GLOBALROOT\\device\\vmsmb" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /CreateFile/) 
	and 	$str_aet  ) 
}

private rule capa_check_for_microsoft_office_emulation { 
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
 	$aeu = /OfficePackagesForWDAG/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aeu 
	and 	pe.imports(/.{1,30}/i, /GetWindowsDirectory/)  ) 
}

private rule capa_check_for_sandbox_username { 
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
 	$aev = /MALTEST/ nocase ascii wide 
	$aew = /TEQUILABOOMBOOM/ nocase ascii wide 
	$aex = /SANDBOX/ nocase ascii wide 
	$aey = /^VIRUS/ nocase ascii wide 
	$aez = /MALWARE/ nocase ascii wide 
	$afa = /SAND\sBOX/ nocase ascii wide 
	$afb = /Test\sUser/ nocase ascii wide 
	$afc = /CurrentUser/ nocase ascii wide 
	$afd = /7SILVIA/ nocase ascii wide 
	$afe = /FORTINET/ nocase ascii wide 
	$aff = /John\sDoe/ nocase ascii wide 
	$afg = /Emily/ nocase ascii wide 
	$afh = /HANSPETER\-PC/ nocase ascii wide 
	$afi = /HAPUBWS/ nocase ascii wide 
	$afj = /Hong\sLee/ nocase ascii wide 
	$afk = /IT\-ADMIN/ nocase ascii wide 
	$afl = /JOHN\-PC/ nocase ascii wide 
	$afm = /Johnson/ nocase ascii wide 
	$afn = /Miller/ nocase ascii wide 
	$afo = /MUELLER\-PC/ nocase ascii wide 
	$afp = /Peter\sWilson/ nocase ascii wide 
	$afq = /SystemIT/ nocase ascii wide 
	$afr = /Timmy/ nocase ascii wide 
	$afs = /WIN7\-TRAPS/ nocase ascii wide 
	$aft = /WDAGUtilityAccount/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /GetUserName/) 
	and  (  ( 	$aev 
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
	or 	$afp 
	or 	$afq 
	or 	$afr 
	or 	$afs 
	or 	$aft  )  )  ) 
}

private rule capa_reference_anti_VM_strings_targeting_Parallels { 
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
 	$afu = /Parallels/ nocase ascii wide 
	$afv = /prl_cc.exe/ nocase ascii wide 
	$afw = /prl_tools.exe/ nocase ascii wide 
	$afx = /prl hyperv/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$afu 
	or 	$afv 
	or 	$afw 
	or 	$afx  ) 
}

private rule capa_reference_anti_VM_strings_targeting_VirtualBox { 
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
 	$afy = /VBOX/ nocase ascii wide 
	$afz = /VEN_VBOX/ nocase ascii wide 
	$aga = /VirtualBox/ nocase ascii wide 
	$agb = /06\/23\/99/ nocase ascii wide 
	$agc = /HARDWARE\\ACPI\\DSDT\\VBOX__/ nocase ascii wide 
	$agd = /HARDWARE\\ACPI\\FADT\\VBOX__/ nocase ascii wide 
	$age = /HARDWARE\\ACPI\\RSDT\\VBOX__/ nocase ascii wide 
	$agf = /SOFTWARE\\Oracle\\VirtualBox Guest Additions/ nocase ascii wide 
	$agg = /SYSTEM\\ControlSet001\\Services\\VBoxGuest/ nocase ascii wide 
	$agh = /SYSTEM\\ControlSet001\\Services\\VBoxMouse/ nocase ascii wide 
	$agi = /SYSTEM\\ControlSet001\\Services\\VBoxService/ nocase ascii wide 
	$agj = /SYSTEM\\ControlSet001\\Services\\VBoxSF/ nocase ascii wide 
	$agk = /SYSTEM\\ControlSet001\\Services\\VBoxVideo/ nocase ascii wide 
	$agl = /VBoxMouse.sys/ nocase ascii wide 
	$agm = /VBoxGuest.sys/ nocase ascii wide 
	$agn = /VBoxSF.sys/ nocase ascii wide 
	$ago = /VBoxVideo.sys/ nocase ascii wide 
	$agp = /vboxdisp.dll/ nocase ascii wide 
	$agq = /vboxhook.dll/ nocase ascii wide 
	$agr = /vboxmrxnp.dll/ nocase ascii wide 
	$ags = /vboxogl.dll/ nocase ascii wide 
	$agt = /vboxoglarrayspu.dll/ nocase ascii wide 
	$agu = /vboxoglcrutil.dll/ nocase ascii wide 
	$agv = /vboxoglerrorspu.dll/ nocase ascii wide 
	$agw = /vboxoglfeedbackspu.dll/ nocase ascii wide 
	$agx = /vboxoglpackspu.dll/ nocase ascii wide 
	$agy = /vboxoglpassthroughspu.dll/ nocase ascii wide 
	$agz = /vboxservice.exe/ nocase ascii wide 
	$aha = /vboxtray.exe/ nocase ascii wide 
	$ahb = /VBoxControl.exe/ nocase ascii wide 
	$ahc = /oracle\\virtualbox guest additions\\/ nocase ascii wide 
	$ahd = /\\\\.\\VBoxMiniRdrDN/ nocase ascii wide 
	$ahe = /\\\\.\\VBoxGuest/ nocase ascii wide 
	$ahf = /\\\\.\\pipe\\VBoxMiniRdDN/ nocase ascii wide 
	$ahg = /\\\\.\\VBoxTrayIPC/ nocase ascii wide 
	$ahh = /\\\\.\\pipe\\VBoxTrayIPC/ nocase ascii wide 
	$ahi = /VBoxTrayToolWndClass/ nocase ascii wide 
	$ahj = /VBoxTrayToolWnd/ nocase ascii wide 
	$ahk = /vboxservice.exe/ nocase ascii wide 
	$ahl = /vboxtray.exe/ nocase ascii wide 
	$ahm = /vboxvideo/ nocase ascii wide 
	$ahn = /VBoxVideoW8/ nocase ascii wide 
	$aho = /VBoxWddm/ nocase ascii wide 
	$ahp = /PCI\\VEN_80EE&DEV_CAFE/ nocase ascii wide 
	$ahq = /82801FB/ nocase ascii wide 
	$ahr = /82441FX/ nocase ascii wide 
	$ahs = /82371SB/ nocase ascii wide 
	$aht = /OpenHCD/ nocase ascii wide 
	$ahu = /ACPIBus_BUS_0/ nocase ascii wide 
	$ahv = /PCI_BUS_0/ nocase ascii wide 
	$ahw = /PNP_BUS_0/ nocase ascii wide 
	$ahx = /Oracle Corporation/ nocase ascii wide 
	$ahy = /VBoxWdd/ nocase ascii wide 
	$ahz = /VBoxS/ nocase ascii wide 
	$aia = /VBoxMouse/ nocase ascii wide 
	$aib = /VBoxGuest/ nocase ascii wide 
	$aic = /VBoxVBoxVBox/ nocase ascii wide 
	$aid = /innotek GmbH/ nocase ascii wide 
	$aie = /drivers\\vboxdrv/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$afy 
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
	or 	$agt 
	or 	$agu 
	or 	$agv 
	or 	$agw 
	or 	$agx 
	or 	$agy 
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
	or 	$aie  ) 
}

private rule capa_check_for_windows_sandbox_via_registry { 
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
 	$aif = /\\Microsoft\\Windows\\CurrentVersion\\RunOnce/ ascii wide 
	$aig = /wmic useraccount where \"name='WDAGUtilityAccount'\"/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /RegOpenKeyEx/) 
	and 	pe.imports(/.{1,30}/i, /RegEnumValue/) 
	and 	$aif 
	and 	$aig  ) 
}

private rule capa_reference_anti_VM_strings_targeting_Xen { 
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
 	$aih = /^Xen/ nocase ascii wide 
	$aii = /XenVMMXenVMM/ nocase ascii wide 
	$aij = /xenservice.exe/ nocase ascii wide 
	$aik = /XenVMMXenVMM/ nocase ascii wide 
	$ail = /HVM domU/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aih 
	or 	$aii 
	or 	$aij 
	or 	$aik 
	or 	$ail  ) 
}

private rule capa_reference_anti_VM_strings { 
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
 	$aim = /HARDWARE\\ACPI\\(DSDT|FADT|RSDT)\\BOCHS/ nocase ascii wide 
	$ain = /HARDWARE\\DESCRIPTION\\System\\(SystemBiosVersion|VideoBiosVersion)/ nocase ascii wide 
	$aio = /HARDWARE\\DESCRIPTION\\System\\CentralProcessor/ nocase ascii wide 
	$aip = /HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0/ nocase ascii wide 
	$aiq = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Enum\\IDE/ nocase ascii wide 
	$air = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Services\\Disk\\Enum\\/ nocase ascii wide 
	$ais = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Control\\SystemInformation\\SystemManufacturer/ nocase ascii wide 
	$ait = /A M I/ nocase ascii wide 
	$aiu = /Hyper-V/ nocase ascii wide 
	$aiv = /Kernel-VMDetection-Private/ nocase ascii wide 
	$aiw = /KVMKVMKVM/ nocase ascii wide 
	$aix = /Microsoft Hv/ nocase ascii wide 
	$aiy = /avghookx.dll/ nocase ascii wide 
	$aiz = /avghooka.dll/ nocase ascii wide 
	$aja = /snxhk.dll/ nocase ascii wide 
	$ajb = /pstorec.dll/ nocase ascii wide 
	$ajc = /vmcheck.dll/ nocase ascii wide 
	$ajd = /wpespy.dll/ nocase ascii wide 
	$aje = /cmdvrt64.dll/ nocase ascii wide 
	$ajf = /cmdvrt32.dll/ nocase ascii wide 
	$ajg = /sample.exe/ nocase ascii wide 
	$ajh = /bot.exe/ nocase ascii wide 
	$aji = /sandbox.exe/ nocase ascii wide 
	$ajj = /malware.exe/ nocase ascii wide 
	$ajk = /test.exe/ nocase ascii wide 
	$ajl = /klavme.exe/ nocase ascii wide 
	$ajm = /myapp.exe/ nocase ascii wide 
	$ajn = /testapp.exe/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aim 
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
	or 	$aje 
	or 	$ajf 
	or 	$ajg 
	or 	$ajh 
	or 	$aji 
	or 	$ajj 
	or 	$ajk 
	or 	$ajl 
	or 	$ajm 
	or 	$ajn  ) 
}

private rule capa_reference_anti_VM_strings_targeting_Qemu { 
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
 	$ajo = /Qemu/ nocase ascii wide 
	$ajp = /qemu-ga.exe/ nocase ascii wide 
	$ajq = /BOCHS/ nocase ascii wide 
	$ajr = /BXPC/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$ajo 
	or 	$ajp 
	or 	$ajq 
	or 	$ajr  ) 
}

private rule capa_reference_anti_VM_strings_targeting_VirtualPC { 
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
 	$ajs = /VirtualPC/ nocase ascii wide 
	$ajt = /VMSrvc.exe/ nocase ascii wide 
	$aju = /VMUSrvc.exe/ nocase ascii wide 
	$ajv = /SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$ajs 
	or 	$ajt 
	or 	$aju 
	or 	$ajv  ) 
}

private rule capa_check_if_process_is_running_under_wine { 
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
 	$ajw = /SOFTWARE\\Wine/ nocase ascii wide 
	$str_ajx = "wine_get_unix_file_name" ascii wide
	$str_ajy = "kernel32.dll" ascii wide
	$str_ajz = "ntdll.dll" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$ajw 
	or  (  ( 	pe.imports(/.{1,30}/i, /GetModuleHandle/) 
	and 	pe.imports(/.{1,30}/i, /GetProcAddress/) 
	and 	$str_ajx 
	and  (  ( 	$str_ajy 
	or 	$str_ajz  )  )  )  )  ) 
}

private rule capa_check_for_debugger_via_API { 
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

private rule capa_check_for_OutputDebugString_error { 
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

private rule capa_contains_PDB_path { 
  meta: 
 	description = "contains PDB path (converted from capa rule)"
	namespace = "executable/pe/pdb"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	hash = "464EF2CA59782CE697BC329713698CCC"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/executable/pe/pdb/contains-pdb-path.yml"
	date = "2021-05-15"

  strings: 
 	$akb = /:\\.{,1000}\.pdb/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
	$akb 
}

private rule capa_contain_a_resource___rsrc__section { 
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
	for any akc in pe.sections : ( akc.name == ".rsrc" ) 
}

private rule capa_contain_a_thread_local_storage___tls__section { 
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
	for any akd in pe.sections : ( akd.name == ".tls" ) 
}

private rule capa_extract_resource_via_kernel32_functions { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  (  (  ( 	pe.imports(/kernel32/i, /LoadResource/) 
	or 	pe.imports(/kernel32/i, /LockResource/) 
	or 	pe.imports(/.{1,30}/i, /LdrAccessResource/)  )  )  )  ) 
	or 	pe.imports(/user32/i, /LoadString/)  ) 
}

private rule capa_packaged_as_an_IExpress_self_extracting_archive { 
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
 	$str_ake = "wextract_cleanup%d" ascii wide
	$str_akf = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
	$str_akg = "  <description>IExpress extraction tool</description>" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_ake 
	and 	$str_akf  )  ) 
	or 	$str_akg  ) 
}

private rule capa_create_thread { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /CreateThread/) 
	or 	pe.imports(/.{1,30}/i, /_beginthread/) 
	or 	pe.imports(/.{1,30}/i, /_beginthreadex/) 
	or 	pe.imports(/.{1,30}/i, /PsCreateSystemThread/) 
	or 	pe.imports(/.{1,30}/i, /SHCreateThread/) 
	or 	pe.imports(/.{1,30}/i, /SHCreateThreadWithHandle/) 
	or 	pe.imports(/kernel32/i, /CreateRemoteThread/) 
	or 	pe.imports(/kernel32/i, /CreateRemoteThreadEx/) 
	or 	pe.imports(/ntdll/i, /RtlCreateUserThread/) 
	or 	pe.imports(/ntdll/i, /NtCreateThread/) 
	or 	pe.imports(/ntdll/i, /NtCreateThreadEx/) 
	or 	pe.imports(/ntdll/i, /ZwCreateThread/) 
	or 	pe.imports(/ntdll/i, /ZwCreateThreadEx/)  ) 
}

private rule capa_resume_thread { 
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

private rule capa_suspend_thread { 
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

private rule capa_terminate_thread { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /TerminateThread/) 
	or 	pe.imports(/.{1,30}/i, /PsTerminateSystemThread/)  ) 
}

private rule capa_manipulate_console { 
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

private rule capa_access_firewall_settings_via_INetFwMgr { 
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
 	$akh = { 42 E9 4C 30 39 6E D8 40 94 3A B9 13 C4 0C 9C D4 }
	$aki = { F5 8A 89 F7 C4 CA 32 46 A2 EC DA 06 E5 11 1A F2 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ole32/i, /CoCreateInstance/) 
	and 	$akh 
	and 	$aki  ) 
}

private rule capa_start_minifilter_driver { 
  meta: 
 	description = "start minifilter driver (converted from capa rule)"
	namespace = "host-interaction/filter"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	references = "https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/filter/start-minifilter-driver.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /FltStartFiltering/)  ) 
}

private rule capa_register_minifilter_driver { 
  meta: 
 	description = "register minifilter driver (converted from capa rule)"
	namespace = "host-interaction/filter"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	references = "https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/filter/register-minifilter-driver.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /FltRegisterFilter/)  ) 
}

private rule capa_get_common_file_path { 
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
	or 	pe.imports(/.{1,30}/i, /GetAllUsersProfileDirectory/) 
	or 	pe.imports(/.{1,30}/i, /GetAppContainerFolderPath/) 
	or 	pe.imports(/.{1,30}/i, /GetCurrentDirectory/) 
	or 	pe.imports(/.{1,30}/i, /GetDefaultUserProfileDirectory/) 
	or 	pe.imports(/.{1,30}/i, /GetProfilesDirectory/) 
	or 	pe.imports(/.{1,30}/i, /GetUserProfileDirectory/) 
	or 	pe.imports(/.{1,30}/i, /SHGetFolderPathAndSubDir/) 
	or 	pe.imports(/shell32/i, /SHGetFolderPath/) 
	or 	pe.imports(/shell32/i, /SHGetFolderLocation/) 
	or 	pe.imports(/shell32/i, /SHGetSpecialFolderPath/) 
	or 	pe.imports(/shell32/i, /SHGetSpecialFolderLocation/)  ) 
}

private rule capa_bypass_Mark_of_the_Web { 
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
 	$str_akj = ":Zone.Identifier" ascii wide
	$str_akk = "%s:Zone.Identifier" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /DeleteFile/) 
	and  (  ( 	$str_akj 
	or 	$str_akk  )  )  ) 
}

private rule capa_get_file_system_object_information { 
  meta: 
 	description = "get file system object information (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	attack = "Discovery::File and Directory Discovery [T1083]"
	hash = "50D5EE1CE2CA5E30C6B1019EE64EEEC2"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/get-file-system-object-information.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /SHGetFileInfo/)  ) 
}

private rule capa_delete_directory { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /RemoveDirectory/) 
	or 	pe.imports(/.{1,30}/i, /RemoveDirectoryTransacted/) 
	or 	pe.imports(/.{1,30}/i, /_rmdir/) 
	or 	pe.imports(/.{1,30}/i, /_wrmdir/)  ) 
}

private rule capa_create_directory { 
  meta: 
 	description = "create directory (converted from capa rule)"
	namespace = "host-interaction/file-system/create"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "File System::Create Directory [C0046]"
	hash = "Practical Malware Analysis Lab 17-02.dll_:0x10008f62"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/create/create-directory.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /CreateDirectory/) 
	or 	pe.imports(/kernel32/i, /CreateDirectoryEx/) 
	or 	pe.imports(/kernel32/i, /CreateDirectoryTransacted/) 
	or 	pe.imports(/.{1,30}/i, /NtCreateDirectoryObject/) 
	or 	pe.imports(/.{1,30}/i, /ZwCreateDirectoryObject/) 
	or 	pe.imports(/.{1,30}/i, /SHCreateDirectory/) 
	or 	pe.imports(/.{1,30}/i, /SHCreateDirectoryEx/) 
	or 	pe.imports(/.{1,30}/i, /_mkdir/) 
	or 	pe.imports(/.{1,30}/i, /_wmkdir/)  ) 
}

private rule capa_write_file { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/kernel32/i, /WriteFile/) 
	or 	pe.imports(/kernel32/i, /WriteFileEx/) 
	or 	pe.imports(/.{1,30}/i, /NtWriteFile/) 
	or 	pe.imports(/.{1,30}/i, /ZwWriteFile/) 
	or 	pe.imports(/.{1,30}/i, /_fwrite/) 
	or 	pe.imports(/.{1,30}/i, /fwrite/)  )  )  ) 
}

private rule capa_get_file_attributes { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /GetFileAttributes/) 
	or 	pe.imports(/.{1,30}/i, /ZwQueryDirectoryFile/) 
	or 	pe.imports(/.{1,30}/i, /ZwQueryInformationFile/) 
	or 	pe.imports(/.{1,30}/i, /NtQueryDirectoryFile/) 
	or 	pe.imports(/.{1,30}/i, /NtQueryInformationFile/)  ) 
}

private rule capa_set_file_attributes { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /SetFileAttributes/) 
	or 	pe.imports(/.{1,30}/i, /ZwSetInformationFile/) 
	or 	pe.imports(/.{1,30}/i, /NtSetInformationFile/)  ) 
}

private rule capa_read_virtual_disk { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /OpenVirtualDisk/) 
	and 	pe.imports(/.{1,30}/i, /AttachVirtualDisk/) 
	and 	pe.imports(/.{1,30}/i, /GetVirtualDiskPhysicalPath/)  ) 
}

private rule capa_read_file { 
  meta: 
 	description = "read file (converted from capa rule)"
	namespace = "host-interaction/file-system/read"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "File System::Read File [C0051]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/read/read-file.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  (  (  ( 	pe.imports(/kernel32/i, /ReadFile/) 
	or 	pe.imports(/.{1,30}/i, /ReadFileEx/) 
	or 	pe.imports(/.{1,30}/i, /NtReadFile/) 
	or 	pe.imports(/.{1,30}/i, /ZwReadFile/) 
	or 	pe.imports(/.{1,30}/i, /_read/) 
	or 	pe.imports(/.{1,30}/i, /fread/)  )  )  )  )  ) 
}

private rule capa_read__ini_file { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/.{1,30}/i, /GetPrivateProfileInt/) 
	or 	pe.imports(/.{1,30}/i, /GetPrivateProfileString/) 
	or 	pe.imports(/.{1,30}/i, /GetPrivateProfileStruct/) 
	or 	pe.imports(/.{1,30}/i, /GetPrivateProfileSection/) 
	or 	pe.imports(/.{1,30}/i, /GetPrivateProfileSectionNames/)  )  )  ) 
}

private rule capa_enumerate_files_via_kernel32_functions { 
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

private rule capa_shutdown_system { 
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

private rule capa_get_system_information { 
  meta: 
 	description = "get system information (converted from capa rule)"
	namespace = "host-interaction/os/info"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/os/info/get-system-information.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /GetSystemInfo/) 
	or 	pe.imports(/kernel32/i, /GetNativeSystemInfo/) 
	or 	pe.imports(/.{1,30}/i, /NtQuerySystemInformation/) 
	or 	pe.imports(/.{1,30}/i, /NtQuerySystemInformationEx/) 
	or 	pe.imports(/ntdll/i, /RtlGetNativeSystemInformation/) 
	or 	pe.imports(/.{1,30}/i, /ZwQuerySystemInformation/) 
	or 	pe.imports(/.{1,30}/i, /ZwQuerySystemInformationEx/)  ) 
}

private rule capa_get_hostname { 
  meta: 
 	description = "get hostname (converted from capa rule)"
	namespace = "host-interaction/os/hostname"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/os/hostname/get-hostname.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/kernel32/i, /GetComputerName/) 
	or 	pe.imports(/kernel32/i, /GetComputerNameEx/) 
	or 	pe.imports(/.{1,30}/i, /GetComputerObjectName/) 
	or 	pe.imports(/ws2_32/i, /gethostname/)  ) 
}

private rule capa_query_service_status { 
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

private rule capa_delete_service { 
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

private rule capa_enumerate_services { 
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

private rule capa_create_service { 
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

private rule capa_modify_service { 
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

private rule capa_start_service { 
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

private rule capa_get_number_of_processor_cores { 
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
 	$akm = /SELECT\s+\*\s+FROM\s+Win32_Processor/ ascii wide 
	$str_akn = "NumberOfCores" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$akm 
	and 	$str_akn  ) 
}

private rule capa_get_disk_information { 
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

private rule capa_manipulate_CD_ROM_drive { 
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
 	$str_ako = "set cdaudio door closed wait" ascii wide
	$str_akp = "set cdaudio door open" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/winmm/i, /mciSendString/) 
	and  (  ( 	$str_ako 
	or 	$str_akp  )  )  ) 
}

private rule capa_get_memory_capacity { 
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

private rule capa_swap_mouse_buttons { 
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

private rule capa_get_keyboard_layout { 
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

private rule capa_open_clipboard { 
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

private rule capa_write_clipboard_data { 
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

private rule capa_read_clipboard_data { 
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

private rule capa_replace_clipboard_data { 
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

private rule capa_install_driver { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ntdll/i, /NtLoadDriver/) 
	or 	pe.imports(/.{1,30}/i, /ZwLoadDriver/)  ) 
}

private rule capa_disable_driver_code_integrity { 
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
 	$str_akq = "CiInitialize" ascii wide
	$akr = /g_CiEnabled/ ascii wide 
	$aks = /g_CiOptions/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_akq 
	or 	$akr 
	or 	$aks  )  )  ) 
}

private rule capa_interact_with_driver_via_control_codes { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /DeviceIoControl/) 
	or 	pe.imports(/.{1,30}/i, /NtUnloadDriver/) 
	or 	pe.imports(/.{1,30}/i, /ZwUnloadDriver/) 
  ) 
}

private rule capa_manipulate_boot_configuration { 
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
 	$akt = /bcdedit.exe/ nocase ascii wide 
	$aku = /boot.ini/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$akt  )  ) 
	or  (  ( 	$aku  )  )  ) 
}

private rule capa_set_application_hook { 
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

private rule capa_enumerate_gui_resources { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /EnumResourceTypes/) 
	or 	pe.imports(/.{1,30}/i, /EnumWindowStations/) 
	or 	pe.imports(/.{1,30}/i, /EnumDesktops/) 
	or 	pe.imports(/.{1,30}/i, /EnumWindows/)  ) 
}

private rule capa_find_graphical_window { 
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

private rule capa_references_logon_banner { 
  meta: 
 	description = "references logon banner (converted from capa rule)"
	namespace = "host-interaction/gui/logon"
	author = "@_re_fox"
	scope = "basic block"
	hash = "c3341b7dfbb9d43bca8c812e07b4299f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/logon/references-logon-banner.yml"
	date = "2021-05-15"

  strings: 
 	$akw = /\\Microsoft\\Windows\\CurrentVersion\\Policies\\System/ ascii wide 
	$akx = /LegalNoticeCaption/ ascii wide 
	$aky = /LegalNoticeText/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$akw 
	and  (  ( 	$akx 
	or 	$aky  )  )  ) 
}

private rule capa_lock_the_desktop { 
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

private rule capa_resolve_path_using_msvcrt { 
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

private rule capa_accept_command_line_arguments { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /GetCommandLine/) 
	or 	pe.imports(/.{1,30}/i, /CommandLineToArgv/)  ) 
}

private rule capa_set_thread_local_storage_value { 
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

private rule capa_allocate_thread_local_storage { 
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

private rule capa_attach_user_process_memory { 
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

private rule capa_use_process_doppelganging { 
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
 	$akz = /CreateFileTransacted./ ascii wide 
	$str_ala = "ZwCreateSection" ascii wide
	$str_alb = "NtCreateSection" ascii wide
	$str_alc = "RollbackTransaction" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$akz 
	and  (  ( 	$str_ala 
	or 	$str_alb  )  ) 
	and 	$str_alc  ) 
}

private rule capa_inject_APC { 
  meta: 
 	description = "inject APC (converted from capa rule)"
	namespace = "host-interaction/process/inject"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Process Injection::Asynchronous Procedure Call [T1055.004]"
	hash = "al-khaser_x64.exe_:0x140019348"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/inject/inject-apc.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_write_process_memory

	or 	pe.imports(/kernel32/i, /MapViewOfSection/) 
	or 	pe.imports(/.{1,30}/i, /NtMapViewOfSection/) 
	or 	pe.imports(/ntdll/i, /ZwMapViewOfSection/) 
	or 	pe.imports(/kernel32/i, /MapViewOfFile/)  )  ) 
	and  (  ( 	pe.imports(/kernel32/i, /QueueUserAPC/) 
	or 	pe.imports(/ntdll/i, /NtQueueApcThread/)  )  )  ) 
}

private rule capa_enumerate_processes { 
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

private rule capa_enumerate_processes_on_remote_desktop_session_host { 
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

private rule capa_get_Explorer_PID { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /GetShellWindow/) 
	and 	pe.imports(/.{1,30}/i, /GetWindowThreadProcessId/)  ) 
}

private rule capa_find_process_by_PID { 
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

private rule capa_create_process { 
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
	or 	pe.imports(/.{1,30}/i, /ZwCreateProcessEx/) 
	or 	pe.imports(/ntdll/i, /ZwCreateUserProcess/) 
	or 	pe.imports(/ntdll/i, /RtlCreateUserProcess/)  ) 
}

private rule capa_modify_access_privileges { 
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

private rule capa_terminate_process { 
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

private rule capa_enumerate_process_modules { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/kernel32/i, /K32EnumProcessModules/) 
	or 	pe.imports(/kernel32/i, /K32EnumProcessModulesEx/) 
	or 	pe.imports(/kernel32/i, /K32EnumProcesses/) 
	or 	pe.imports(/.{1,30}/i, /EnumProcessModules/) 
	or 	pe.imports(/.{1,30}/i, /EnumProcessModulesEx/) 
	or 	pe.imports(/.{1,30}/i, /EnumProcesses/)  )  )  ) 
}

private rule capa_get_domain_information { 
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

private rule capa_get_networking_interfaces { 
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

private rule capa_register_network_filter_via_WFP_API { 
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

private rule capa_copy_network_traffic { 
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

private rule capa_resolve_DNS { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ws2_32/i, /gethostbyname/) 
	or 	pe.imports(/.{1,30}/i, /DnsQuery_A/) 
	or 	pe.imports(/.{1,30}/i, /DnsQuery_W/) 
	or 	pe.imports(/.{1,30}/i, /DnsQuery_UTF8/) 
	or 	pe.imports(/.{1,30}/i, /DnsQueryEx/) 
	or 	pe.imports(/.{1,30}/i, /getaddrinfo/) 
	or 	pe.imports(/.{1,30}/i, /GetAddrInfo/) 
	or 	pe.imports(/.{1,30}/i, /GetAddrInfoEx/)  ) 
}

private rule capa_check_Internet_connectivity_via_WinINet { 
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

private rule capa_get_local_IPv4_addresses { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/.{1,30}/i, /GetAdaptersAddresses/)  )  )  ) 
}

private rule capa_create_mutex { 
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

private rule capa_bypass_UAC_via_token_manipulation { 
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
 	$str_ald = "wusa.exe" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_ald 
	and 	pe.imports(/.{1,30}/i, /ShellExecuteExW/) 
	and 	pe.imports(/.{1,30}/i, /ImpersonateLoggedOnUser/) 
	and 	pe.imports(/.{1,30}/i, /GetStartupInfoW/) 
	and 	pe.imports(/.{1,30}/i, /CreateProcessWithLogonW/)  ) 
}

private rule capa_bypass_UAC_via_AppInfo_ALPC { 
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
 	$str_ale = "winver.exe" ascii wide
	$str_alf = "WinSta0\\Default" ascii wide
	$str_alg = "taskmgr.exe" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_ale 
	and 	$str_alf 
	and 	$str_alg 
	and 	pe.imports(/.{1,30}/i, /WaitForDebugEvent/) 
	and 	pe.imports(/.{1,30}/i, /ContinueDebugEvent/) 
	and 	pe.imports(/.{1,30}/i, /TerminateProcess/)  ) 
}

private rule capa_access_the_Windows_event_log { 
  meta: 
 	description = "access the Windows event log (converted from capa rule)"
	namespace = "host-interaction/log/winevt/access"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Discovery::File and Directory Discovery::Log File [E1083.m01]"
	hash = "mimikatz.exe_:0x45228B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/log/winevt/access/access-the-windows-event-log.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /OpenEventLog/) 
	or 	pe.imports(/.{1,30}/i, /ClearEventLog/) 
	or 	pe.imports(/.{1,30}/i, /OpenBackupEventLog/) 
	or 	pe.imports(/.{1,30}/i, /ReportEvent/)  ) 
}

private rule capa_print_debug_messages { 
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

private rule capa_set_environment_variable { 
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

private rule capa_query_environment_variable { 
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

private rule capa_open_registry_key_via_offline_registry_library { 
  meta: 
 	description = "open registry key via offline registry library (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "johnk3r"
	scope = "function"
	mbc = "Operating System::Registry::Open Registry Key [C0036.003]"
	hash = "5fbbfeed28b258c42e0cfeb16718b31c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/open-registry-key-via-offline-registry-library.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /OROpenHive/) 
	or 	pe.imports(/.{1,30}/i, /OROpenKey/)  ) 
}

private rule capa_query_or_enumerate_registry_value { 
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
	or 	pe.imports(/.{1,30}/i, /ZwQueryValueKey/) 
	or 	pe.imports(/.{1,30}/i, /ZwEnumerateValueKey/) 
	or 	pe.imports(/.{1,30}/i, /NtQueryValueKey/) 
	or 	pe.imports(/.{1,30}/i, /NtEnumerateValueKey/) 
	or 	pe.imports(/.{1,30}/i, /RtlQueryRegistryValues/) 
	or 	pe.imports(/.{1,30}/i, /SHGetValue/) 
	or 	pe.imports(/.{1,30}/i, /SHEnumValue/) 
	or 	pe.imports(/.{1,30}/i, /SHRegGetInt/) 
	or 	pe.imports(/.{1,30}/i, /SHRegGetPath/) 
	or 	pe.imports(/.{1,30}/i, /SHRegGetValue/) 
	or 	pe.imports(/.{1,30}/i, /SHQueryValueEx/) 
	or 	pe.imports(/.{1,30}/i, /SHRegGetUSValue/) 
	or 	pe.imports(/.{1,30}/i, /SHOpenRegStream/) 
	or 	pe.imports(/.{1,30}/i, /SHRegEnumUSValue/) 
	or 	pe.imports(/.{1,30}/i, /SHOpenRegStream2/) 
	or 	pe.imports(/.{1,30}/i, /SHRegQueryUSValue/) 
	or 	pe.imports(/.{1,30}/i, /SHRegGetBoolUSValue/) 
	or 	pe.imports(/.{1,30}/i, /SHRegGetValueFromHKCUHKLM/) 
	or 	pe.imports(/.{1,30}/i, /SHRegGetBoolValueFromHKCUHKLM/)  )  )  ) 
}

private rule capa_set_registry_key_via_offline_registry_library { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /ORSetValue/)  ) 
}

private rule capa_query_registry_key_via_offline_registry_library { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /ORGetValue/)  ) 
}

private rule capa_query_or_enumerate_registry_key { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/advapi32/i, /RegEnumKey/) 
	or 	pe.imports(/advapi32/i, /RegEnumKeyEx/) 
	or 	pe.imports(/advapi32/i, /RegQueryInfoKeyA/) 
	or 	pe.imports(/.{1,30}/i, /ZwQueryKey/) 
	or 	pe.imports(/.{1,30}/i, /ZwEnumerateKey/) 
	or 	pe.imports(/.{1,30}/i, /NtQueryKey/) 
	or 	pe.imports(/.{1,30}/i, /NtEnumerateKey/) 
	or 	pe.imports(/.{1,30}/i, /RtlCheckRegistryKey/) 
	or 	pe.imports(/.{1,30}/i, /SHEnumKeyEx/) 
	or 	pe.imports(/.{1,30}/i, /SHQueryInfoKey/) 
	or 	pe.imports(/.{1,30}/i, /SHRegEnumUSKey/) 
	or 	pe.imports(/.{1,30}/i, /SHRegQueryInfoUSKey/)  )  )  ) 
}

private rule capa_create_registry_key_via_offline_registry_library { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /ORCreateHive/) 
	or 	pe.imports(/.{1,30}/i, /ORCreateKey/)  ) 
}

private rule capa_create_or_open_registry_key { 
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
	or 	pe.imports(/.{1,30}/i, /ZwOpenKey/) 
	or 	pe.imports(/.{1,30}/i, /ZwOpenKeyEx/) 
	or 	pe.imports(/.{1,30}/i, /ZwCreateKey/) 
	or 	pe.imports(/.{1,30}/i, /ZwOpenKeyTransacted/) 
	or 	pe.imports(/.{1,30}/i, /ZwOpenKeyTransactedEx/) 
	or 	pe.imports(/.{1,30}/i, /ZwCreateKeyTransacted/) 
	or 	pe.imports(/.{1,30}/i, /NtOpenKey/) 
	or 	pe.imports(/.{1,30}/i, /NtCreateKey/) 
	or 	pe.imports(/.{1,30}/i, /SHRegOpenUSKey/) 
	or 	pe.imports(/.{1,30}/i, /SHRegCreateUSKey/) 
	or 	pe.imports(/.{1,30}/i, /RtlCreateRegistryKey/)  ) 
}

private rule capa_delete_registry_key { 
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
	or 	pe.imports(/.{1,30}/i, /ZwDeleteKey/) 
	or 	pe.imports(/.{1,30}/i, /NtDeleteKey/) 
	or 	pe.imports(/.{1,30}/i, /SHDeleteKey/) 
	or 	pe.imports(/.{1,30}/i, /SHDeleteEmptyKey/) 
	or 	pe.imports(/.{1,30}/i, /SHRegDeleteEmptyUSKey/)  )  )  ) 
}

private rule capa_delete_registry_value { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/advapi32/i, /RegDeleteValue/) 
	or 	pe.imports(/advapi32/i, /RegDeleteKeyValue/) 
	or 	pe.imports(/.{1,30}/i, /ZwDeleteValueKey/) 
	or 	pe.imports(/.{1,30}/i, /NtDeleteValueKey/) 
	or 	pe.imports(/.{1,30}/i, /RtlDeleteRegistryValue/) 
	or 	pe.imports(/.{1,30}/i, /SHDeleteValue/) 
	or 	pe.imports(/.{1,30}/i, /SHRegDeleteUSValue/)  )  )  ) 
}

private rule capa_set_registry_value { 
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
 	$alh = /reg(.exe)? add / nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  (  (  ( 	pe.imports(/advapi32/i, /RegSetValue/) 
	or 	pe.imports(/advapi32/i, /RegSetValueEx/) 
	or 	pe.imports(/advapi32/i, /RegSetKeyValue/) 
	or 	pe.imports(/.{1,30}/i, /ZwSetValueKey/) 
	or 	pe.imports(/.{1,30}/i, /NtSetValueKey/) 
	or 	pe.imports(/.{1,30}/i, /RtlWriteRegistryValue/) 
	or 	pe.imports(/.{1,30}/i, /SHSetValue/) 
	or 	pe.imports(/.{1,30}/i, /SHRegSetPath/) 
	or 	pe.imports(/.{1,30}/i, /SHRegSetValue/) 
	or 	pe.imports(/.{1,30}/i, /SHRegSetUSValue/) 
	or 	pe.imports(/.{1,30}/i, /SHRegWriteUSValue/)  )  )  )  ) 
	or  (  ( 	capa_create_process

	and 	$alh  )  )  ) 
}

private rule capa_get_logon_sessions { 
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

private rule capa_get_session_integrity_level { 
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

private rule capa_link_function_at_runtime { 
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

private rule capa_linked_against_Crypto__ { 
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
 	$str_ali = "Cryptographic algorithms are disabled after a power-up self test failed." ascii wide
	$str_alj = ": this object requires an IV" ascii wide
	$str_alk = "BER decode error" ascii wide
	$str_all = ".?AVException@CryptoPP@@" ascii wide
	$str_alm = "FileStore: error reading file" ascii wide
	$str_aln = "StreamTransformationFilter: PKCS_PADDING cannot be used with " ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_ali 
	or 	$str_alj 
	or 	$str_alk 
	or 	$str_all 
	or 	$str_alm 
	or 	$str_aln  ) 
}

private rule capa_linked_against_OpenSSL { 
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
 	$str_alo = "RC4 for x86_64, CRYPTOGAMS by <appro@openssl.org>" ascii wide
	$str_alp = "AES for x86_64, CRYPTOGAMS by <appro@openssl.org>" ascii wide
	$str_alq = "DSA-SHA1-old" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_alo 
	or 	$str_alp 
	or 	$str_alq  ) 
}

private rule capa_linked_against_PolarSSL_mbed_TLS { 
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
 	$str_alr = "PolarSSLTest" ascii wide
	$str_als = "mbedtls_cipher_setup" ascii wide
	$str_alt = "mbedtls_pk_verify" ascii wide
	$str_alu = "mbedtls_ssl_write_record" ascii wide
	$str_alv = "mbedtls_ssl_fetch_input" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_alr 
	or 	$str_als 
	or 	$str_alt 
	or 	$str_alu 
	or 	$str_alv  ) 
}

private rule capa_linked_against_libcurl { 
  meta: 
 	description = "linked against libcurl (converted from capa rule)"
	namespace = "linking/static/libcurl"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	hash = "A90E5B3454AA71D9700B2EA54615F44B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/libcurl/linked-against-libcurl.yml"
	date = "2021-05-15"

  strings: 
 	$alw = /CLIENT libcurl/ ascii wide 
	$alx = /curl\.haxx\.se/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$alw 
	or 	$alx  ) 
}

private rule capa_linked_against_Microsoft_Detours { 
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
 ( 	for any aly in pe.sections : ( aly.name == ".detourc" ) 
	or 	for any alz in pe.sections : ( alz.name == ".detourd" )  ) 
}

private rule capa_linked_against_ZLIB { 
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
 	$ama = /deflate .{,1000} Copyright/ ascii wide 
	$amb = /inflate .{,1000} Copyright/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$ama 
	or 	$amb  ) 
}

private rule capa_reference_Base64_string { 
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
 	$amc = /ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
	$amc 
}

private rule capa_import_public_key { 
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

private rule capa_encrypt_or_decrypt_via_WinCrypt { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/.{1,30}/i, /CryptEncrypt/) 
	or 	pe.imports(/.{1,30}/i, /CryptDecrypt/)  )  )  ) 
}

private rule capa_encrypt_data_using_DPAPI { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /CryptProtectMemory/) 
	or 	pe.imports(/.{1,30}/i, /CryptUnprotectMemory/) 
	or 	pe.imports(/crypt32/i, /CryptProtectData/) 
	or 	pe.imports(/crypt32/i, /CryptUnprotectData/)  ) 
}

private rule capa_encrypt_data_using_Camellia { 
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
 	$amd = { 00 70 70 70 00 82 82 82 00 2C 2C 2C 00 EC EC EC 00 B3 B3 B3 00 27 27 27 00 C0 C0 C0 00 E5 E5 E5 00 E4 E4 E4 00 85 85 85 00 57 57 57 00 35 35 35 00 EA EA EA 00 0C 0C 0C 00 AE AE AE 00 41 41 41 00 23 23 23 00 EF EF EF 00 6B 6B 6B 00 93 93 93 00 45 45 45 00 19 19 19 00 A5 A5 A5 00 21 21 21 00 ED ED ED 00 0E 0E 0E 00 4F 4F 4F 00 4E 4E 4E 00 1D 1D 1D 00 65 65 65 00 92 92 92 00 BD BD BD 00 86 86 86 00 B8 B8 B8 00 AF AF AF 00 8F 8F 8F 00 7C 7C 7C 00 EB EB EB 00 1F 1F 1F 00 CE CE CE 00 3E 3E 3E 00 30 30 30 00 DC DC }
	$ame = { E0 E0 E0 00 05 05 05 00 58 58 58 00 D9 D9 D9 00 67 67 67 00 4E 4E 4E 00 81 81 81 00 CB CB CB 00 C9 C9 C9 00 0B 0B 0B 00 AE AE AE 00 6A 6A 6A 00 D5 D5 D5 00 18 18 18 00 5D 5D 5D 00 82 82 82 00 46 46 46 00 DF DF DF 00 D6 D6 D6 00 27 27 27 00 8A 8A 8A 00 32 32 32 00 4B 4B 4B 00 42 42 42 00 DB DB DB 00 1C 1C 1C 00 9E 9E 9E 00 9C 9C 9C 00 3A 3A 3A 00 CA CA CA 00 25 25 25 00 7B 7B 7B 00 0D 0D 0D 00 71 71 71 00 5F 5F 5F 00 1F 1F 1F 00 F8 F8 F8 00 D7 D7 D7 00 3E 3E 3E 00 9D 9D 9D 00 7C 7C 7C 00 60 60 60 00 B9 B9 B9 }
	$amf = { 38 38 00 38 41 41 00 41 16 16 00 16 76 76 00 76 D9 D9 00 D9 93 93 00 93 60 60 00 60 F2 F2 00 F2 72 72 00 72 C2 C2 00 C2 AB AB 00 AB 9A 9A 00 9A 75 75 00 75 06 06 00 06 57 57 00 57 A0 A0 00 A0 91 91 00 91 F7 F7 00 F7 B5 B5 00 B5 C9 C9 00 C9 A2 A2 00 A2 8C 8C 00 8C D2 D2 00 D2 90 90 00 90 F6 F6 00 F6 07 07 00 07 A7 A7 00 A7 27 27 00 27 8E 8E 00 8E B2 B2 00 B2 49 49 00 49 DE DE 00 DE 43 43 00 43 5C 5C 00 5C D7 D7 00 D7 C7 C7 00 C7 3E 3E 00 3E F5 F5 00 F5 8F 8F 00 8F 67 67 00 67 1F 1F 00 1F 18 18 00 18 6E 6E 00 }
	$amg = { 70 00 70 70 2C 00 2C 2C B3 00 B3 B3 C0 00 C0 C0 E4 00 E4 E4 57 00 57 57 EA 00 EA EA AE 00 AE AE 23 00 23 23 6B 00 6B 6B 45 00 45 45 A5 00 A5 A5 ED 00 ED ED 4F 00 4F 4F 1D 00 1D 1D 92 00 92 92 86 00 86 86 AF 00 AF AF 7C 00 7C 7C 1F 00 1F 1F 3E 00 3E 3E DC 00 DC DC 5E 00 5E 5E 0B 00 0B 0B A6 00 A6 A6 39 00 39 39 D5 00 D5 D5 5D 00 5D 5D D9 00 D9 D9 5A 00 5A 5A 51 00 51 51 6C 00 6C 6C 8B 00 8B 8B 9A 00 9A 9A FB 00 FB FB B0 00 B0 B0 74 00 74 74 2B 00 2B 2B F0 00 F0 F0 84 00 84 84 DF 00 DF DF CB 00 CB CB 34 00 34 }
	$amh = { 70 82 2C EC B3 27 C0 E5 E4 85 57 35 EA 0C AE 41 23 EF 6B 93 45 19 A5 21 ED 0E 4F 4E 1D 65 92 BD 86 B8 AF 8F 7C EB 1F CE 3E 30 DC 5F 5E C5 0B 1A A6 E1 39 CA D5 47 5D 3D D9 01 5A D6 51 56 6C 4D 8B 0D 9A 66 FB CC B0 2D 74 12 2B 20 F0 B1 84 99 DF 4C CB C2 34 7E 76 05 6D B7 A9 31 D1 17 04 D7 14 58 3A 61 DE 1B 11 1C 32 0F 9C 16 53 18 F2 22 FE 44 CF B2 C3 B5 7A 91 24 08 E8 A8 60 FC 69 50 AA D0 A0 7D A1 89 62 97 54 5B 1E 95 E0 FF 64 D2 10 C4 00 48 A3 F7 75 DB 8A 03 E6 DA 09 3F DD 94 87 5C 83 02 CD 4A 90 33 73 67 F6 F3 9D 7F BF E2 52 9B D8 26 C8 37 C6 3B 81 96 6F 4B 13 BE 63 2E E9 79 A7 8C 9F 6E BC 8E 29 F5 F9 B6 2F FD B4 59 78 98 06 6A E7 46 71 BA D4 25 AB 42 88 A2 8D FA 72 07 B9 55 F8 EE AC 0A 36 49 2A 68 3C 38 F1 A4 40 28 D3 7B BB C9 43 C1 15 E3 AD F4 77 C7 80 9E }
	$num_ami = { 3B CC 90 8B }
	$num_amj = { A0 9E 66 7F }
	$num_amk = { 4C AA 73 B2 }
	$num_aml = { B6 7A E8 58 }
	$num_amm = { C6 EF 37 2F }
	$num_amn = { E9 4F 82 BE }
	$num_amo = { 54 FF 53 A5 }
	$num_amp = { F1 D3 6F 1C }
	$num_amq = { 10 E5 27 FA }
	$num_amr = { DE 68 2D 1D }
	$num_ams = { B0 56 88 C2 }
	$num_amt = { B3 E6 C1 FD }
	$amu = { 8B 90 CC 3B 7F 66 9E A0 }
	$amv = { B2 73 AA 4C 58 E8 7A B6 }
	$amw = { BE 82 4F E9 2F 37 EF C6 }
	$amx = { 1C 6F D3 F1 A5 53 FF 54 }
	$amy = { 1D 2D 68 DE FA 27 E5 10 }
	$amz = { FD C1 E6 B3 C2 88 56 B0 }
	$ana = /A09E667F3BCC908B/ nocase ascii wide 
	$str_anb = "/B67AE8584CAA73B" ascii wide
	$anc = /C6EF372FE94F82BE/ nocase ascii wide 
	$and = /54FF53A5F1D36F1C/ nocase ascii wide 
	$ane = /10E527FADE682D1D/ nocase ascii wide 
	$anf = /B05688C2B3E6C1FD/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$amd 
	or 	$ame 
	or 	$amf 
	or 	$amg 
	or 	$amh 
	or  (  (  (  ( $num_ami 
	and $num_amj 
	and $num_amk 
	and $num_aml 
	and $num_amm 
	and $num_amn 
	and $num_amo 
	and $num_amp 
	and $num_amq 
	and $num_amr 
	and $num_ams 
	and $num_amt  )  ) 
	or  (  ( 	$amu 
	and 	$amv 
	and 	$amw 
	and 	$amx 
	and 	$amy 
	and 	$amz  )  ) 
	or  (  ( 	$ana 
	and 	$str_anb 
	and 	$anc 
	and 	$and 
	and 	$ane 
	and 	$anf  )  )  )  )  ) 
}

private rule capa_encrypt_data_using_RC6 { 
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
 	$num_ang = { B7 E1 51 63 }
	$num_anh = { 9E 37 79 B9 }
	$num_ani = { 61 C8 86 47 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( $num_ang 
	and  (  ( $num_anh 
	or $num_ani  )  )  ) 
}

private rule capa_encrypt_data_using_twofish { 
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
 	$anj = { A9 67 B3 E8 04 FD A3 76 9A 92 80 78 E4 DD D1 38 0D C6 35 98 18 F7 EC 6C 43 75 37 26 FA 13 94 48 F2 D0 8B 30 84 54 DF 23 19 5B 3D 59 F3 AE A2 82 63 01 83 2E D9 51 9B 7C A6 EB A5 BE 16 0C E3 61 C0 8C 3A F5 73 2C 25 0B BB 4E 89 6B 53 6A B4 F1 E1 E6 BD 45 E2 F4 B6 66 CC 95 03 56 D4 1C 1E D7 FB C3 8E B5 E9 CF BF BA EA 77 39 AF 33 C9 62 71 81 79 09 AD 24 CD F9 D8 E5 C5 B9 4D 44 08 86 E7 A1 1D AA ED 06 70 B2 D2 41 7B A0 11 31 C2 27 90 20 F6 60 FF 96 5C B1 AB 9E 9C 52 1B 5F 93 0A EF 91 85 49 EE 2D 4F 8F 3B 47 87 6D }
	$ank = { 75 F3 C6 F4 DB 7B FB C8 4A D3 E6 6B 45 7D E8 4B D6 32 D8 FD 37 71 F1 E1 30 0F F8 1B 87 FA 06 3F 5E BA AE 5B 8A 00 BC 9D 6D C1 B1 0E 80 5D D2 D5 A0 84 07 14 B5 90 2C A3 B2 73 4C 54 92 74 36 51 38 B0 BD 5A FC 60 62 96 6C 42 F7 10 7C 28 27 8C 13 95 9C C7 24 46 3B 70 CA E3 85 CB 11 D0 93 B8 A6 83 20 FF 9F 77 C3 CC 03 6F 08 BF 40 E7 2B E2 79 0C AA 82 41 3A EA B9 E4 9A A4 97 7E DA 7A 17 66 94 A1 1D 3D F0 DE B3 0B 72 A7 1C EF D1 53 3E 8F 33 26 5F EC 76 2A 49 81 88 EE 21 C4 1A EB D9 C5 39 99 CD AD 31 8B 01 18 23 DD }
	$anl = { 75 32 BC BC F3 21 EC EC C6 43 20 20 F4 C9 B3 B3 DB 03 DA DA 7B 8B 02 02 FB 2B E2 E2 C8 FA 9E 9E 4A EC C9 C9 D3 09 D4 D4 E6 6B 18 18 6B 9F 1E 1E 45 0E 98 98 7D 38 B2 B2 E8 D2 A6 A6 4B B7 26 26 D6 57 3C 3C 32 8A 93 93 D8 EE 82 82 FD 98 52 52 37 D4 7B 7B 71 37 BB BB F1 97 5B 5B E1 83 47 47 30 3C 24 24 0F E2 51 51 F8 C6 BA BA 1B F3 4A 4A 87 48 BF BF FA 70 0D 0D 06 B3 B0 B0 3F DE 75 75 5E FD D2 D2 BA 20 7D 7D AE 31 66 66 5B A3 3A 3A 8A 1C 59 59 00 00 00 00 BC 93 CD CD 9D E0 1A 1A 6D 2C AE AE C1 AB 7F 7F B1 C7 2B }
	$anm = { 39 39 D9 A9 17 17 90 67 9C 9C 71 B3 A6 A6 D2 E8 07 07 05 04 52 52 98 FD 80 80 65 A3 E4 E4 DF 76 45 45 08 9A 4B 4B 02 92 E0 E0 A0 80 5A 5A 66 78 AF AF DD E4 6A 6A B0 DD 63 63 BF D1 2A 2A 36 38 E6 E6 54 0D 20 20 43 C6 CC CC 62 35 F2 F2 BE 98 12 12 1E 18 EB EB 24 F7 A1 A1 D7 EC 41 41 77 6C 28 28 BD 43 BC BC 32 75 7B 7B D4 37 88 88 9B 26 0D 0D 70 FA 44 44 F9 13 FB FB B1 94 7E 7E 5A 48 03 03 7A F2 8C 8C E4 D0 B6 B6 47 8B 24 24 3C 30 E7 E7 A5 84 6B 6B 41 54 DD DD 06 DF 60 60 C5 23 FD FD 45 19 3A 3A A3 5B C2 C2 68 }
	$ann = { 32 BC 75 BC 21 EC F3 EC 43 20 C6 20 C9 B3 F4 B3 03 DA DB DA 8B 02 7B 02 2B E2 FB E2 FA 9E C8 9E EC C9 4A C9 09 D4 D3 D4 6B 18 E6 18 9F 1E 6B 1E 0E 98 45 98 38 B2 7D B2 D2 A6 E8 A6 B7 26 4B 26 57 3C D6 3C 8A 93 32 93 EE 82 D8 82 98 52 FD 52 D4 7B 37 7B 37 BB 71 BB 97 5B F1 5B 83 47 E1 47 3C 24 30 24 E2 51 0F 51 C6 BA F8 BA F3 4A 1B 4A 48 BF 87 BF 70 0D FA 0D B3 B0 06 B0 DE 75 3F 75 FD D2 5E D2 20 7D BA 7D 31 66 AE 66 A3 3A 5B 3A 1C 59 8A 59 00 00 00 00 93 CD BC CD E0 1A 9D 1A 2C AE 6D AE AB 7F C1 7F C7 2B B1 }
	$ano = { D9 A9 39 D9 90 67 17 90 71 B3 9C 71 D2 E8 A6 D2 05 04 07 05 98 FD 52 98 65 A3 80 65 DF 76 E4 DF 08 9A 45 08 02 92 4B 02 A0 80 E0 A0 66 78 5A 66 DD E4 AF DD B0 DD 6A B0 BF D1 63 BF 36 38 2A 36 54 0D E6 54 43 C6 20 43 62 35 CC 62 BE 98 F2 BE 1E 18 12 1E 24 F7 EB 24 D7 EC A1 D7 77 6C 41 77 BD 43 28 BD 32 75 BC 32 D4 37 7B D4 9B 26 88 9B 70 FA 0D 70 F9 13 44 F9 B1 94 FB B1 5A 48 7E 5A 7A F2 03 7A E4 D0 8C E4 47 8B B6 47 3C 30 24 3C A5 84 E7 A5 41 54 6B 41 06 DF DD 06 C5 23 60 C5 45 19 FD 45 A3 5B 3A A3 68 3D C2 }
	$anp = { 01 02 04 08 10 20 40 80 4D 9A 79 F2 A9 1F 3E 7C F8 BD 37 6E DC F5 A7 03 06 0C 18 30 60 C0 CD D7 E3 8B 5B B6 21 42 84 45 8A 59 B2 29 52 A4 05 0A 14 28 50 A0 0D 1A 34 68 D0 ED 97 63 C6 C1 CF D3 EB 9B 7B F6 A1 0F 1E 3C 78 F0 AD 17 2E 5C B8 3D 7A F4 A5 07 0E 1C 38 70 E0 8D 57 AE 11 22 44 88 5D BA 39 72 E4 85 47 8E 51 A2 09 12 24 48 90 6D DA F9 BF 33 66 CC D5 E7 83 4B 96 61 C2 C9 DF F3 AB 1B 36 6C D8 FD B7 23 46 8C 55 AA 19 32 64 C8 DD F7 A3 0B 16 2C 58 B0 2D 5A B4 25 4A 94 65 CA D9 FF B3 2B 56 AC 15 2A 54 A8 1D }
	$anq = { A9 75 67 F3 B3 C6 E8 F4 04 DB FD 7B A3 FB 76 C8 9A 4A 92 D3 80 E6 78 6B E4 45 DD 7D D1 E8 38 4B 0D D6 C6 32 35 D8 98 FD 18 37 F7 71 EC F1 6C E1 43 30 75 0F 37 F8 26 1B FA 87 13 FA 94 06 48 3F F2 5E D0 BA 8B AE 30 5B 84 8A 54 00 DF BC 23 9D 19 6D 5B C1 3D B1 59 0E F3 80 AE 5D A2 D2 82 D5 63 A0 01 84 83 07 2E 14 D9 B5 51 90 9B 2C 7C A3 A6 B2 EB 73 A5 4C BE 54 16 92 0C 74 E3 36 61 51 C0 38 8C B0 3A BD F5 5A 73 FC 2C 60 25 62 0B 96 BB 6C 4E 42 89 F7 6B 10 53 7C 6A 28 B4 27 F1 8C E1 13 E6 95 BD 9C 45 C7 E2 24 F4 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$anj 
	or 	$ank 
	or 	$anl 
	or 	$anm 
	or 	$ann 
	or 	$ano 
	or 	$anp 
	or 	$anq  ) 
}

private rule capa_encrypt_data_using_Sosemanuk { 
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
 	$anr = { 00 00 00 00 E1 9F CF 13 6B 97 37 26 8A 08 F8 35 D6 87 6E 4C 37 18 A1 5F BD 10 59 6A 5C 8F 96 79 05 A7 DC 98 E4 38 13 8B 6E 30 EB BE 8F AF 24 AD D3 20 B2 D4 32 BF 7D C7 B8 B7 85 F2 59 28 4A E1 0A E7 11 99 EB 78 DE 8A 61 70 26 BF 80 EF E9 AC DC 60 7F D5 3D FF B0 C6 B7 F7 48 F3 56 68 87 E0 0F 40 CD 01 EE DF 02 12 64 D7 FA 27 85 48 35 34 D9 C7 A3 4D 38 58 6C 5E B2 50 94 6B 53 CF 5B 78 }
	$ans = { 00 00 00 00 13 CF 9F E1 26 37 97 6B 35 F8 08 8A 4C 6E 87 D6 5F A1 18 37 6A 59 10 BD 79 96 8F 5C 98 DC A7 05 8B 13 38 E4 BE EB 30 6E AD 24 AF 8F D4 B2 20 D3 C7 7D BF 32 F2 85 B7 B8 E1 4A 28 59 99 11 E7 0A 8A DE 78 EB BF 26 70 61 AC E9 EF 80 D5 7F 60 DC C6 B0 FF 3D F3 48 F7 B7 E0 87 68 56 01 CD 40 0F 12 02 DF EE 27 FA D7 64 34 35 48 85 4D A3 C7 D9 5E 6C 58 38 6B 94 50 B2 78 5B CF 53 }
	$ant = { 00 00 00 00 18 0F 40 CD 30 1E 80 33 28 11 C0 FE 60 3C A9 66 78 33 E9 AB 50 22 29 55 48 2D 69 98 C0 78 FB CC D8 77 BB 01 F0 66 7B FF E8 69 3B 32 A0 44 52 AA B8 4B 12 67 90 5A D2 99 88 55 92 54 29 F0 5F 31 31 FF 1F FC 19 EE DF 02 01 E1 9F CF 49 CC F6 57 51 C3 B6 9A 79 D2 76 64 61 DD 36 A9 E9 88 A4 FD F1 87 E4 30 D9 96 24 CE C1 99 64 03 89 B4 0D 9B 91 BB 4D 56 B9 AA 8D A8 A1 A5 CD 65 }
	$anu = { 00 00 00 00 CD 40 0F 18 33 80 1E 30 FE C0 11 28 66 A9 3C 60 AB E9 33 78 55 29 22 50 98 69 2D 48 CC FB 78 C0 01 BB 77 D8 FF 7B 66 F0 32 3B 69 E8 AA 52 44 A0 67 12 4B B8 99 D2 5A 90 54 92 55 88 31 5F F0 29 FC 1F FF 31 02 DF EE 19 CF 9F E1 01 57 F6 CC 49 9A B6 C3 51 64 76 D2 79 A9 36 DD 61 FD A4 88 E9 30 E4 87 F1 CE 24 96 D9 03 64 99 C1 9B 0D B4 89 56 4D BB 91 A8 8D AA B9 65 CD A5 A1 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$anr 
	or 	$ans 
	or 	$ant 
	or 	$anu 
  ) 
}

private rule capa_encrypt_data_using_DES { 
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
 	$anv = { 0E 04 0D 01 02 0F 0B 08 03 0A 06 0C 05 09 00 07 00 0F 07 04 0E 02 0D 01 0A 06 0C 0B 09 05 03 08 04 01 0E 08 0D 06 02 0B 0F 0C 09 07 03 0A 05 00 0F 0C 08 02 04 09 01 07 05 0B 03 0E 0A 00 06 0D }
	$anw = { 0F 01 08 0E 06 0B 03 04 09 07 02 0D 0C 00 05 0A 03 0D 04 07 0F 02 08 0E 0C 00 01 0A 06 09 0B 05 00 0E 07 0B 0A 04 0D 01 05 08 0C 06 09 03 02 0F 0D 08 0A 01 03 0F 04 02 0B 06 07 0C 00 05 0E 09 }
	$anx = { 0A 00 09 0E 06 03 0F 05 01 0D 0C 07 0B 04 02 08 0D 07 00 09 03 04 06 0A 02 08 05 0E 0C 0B 0F 01 0D 06 04 09 08 0F 03 00 0B 01 02 0C 05 0A 0E 07 01 0A 0D 00 06 09 08 07 04 0F 0E 03 0B 05 02 0C }
	$any = { 07 0D 0E 03 00 06 09 0A 01 02 08 05 0B 0C 04 0F 0D 08 0B 05 06 0F 00 03 04 07 02 0C 01 0A 0E 09 0A 06 09 00 0C 0B 07 0D 0F 01 03 0E 05 02 08 04 03 0F 00 06 0A 01 0D 08 09 04 05 0B 0C 07 02 0E }
	$anz = { 02 0C 04 01 07 0A 0B 06 08 05 03 0F 0D 00 0E 09 0E 0B 02 0C 04 07 0D 01 05 00 0F 0A 03 09 08 06 04 02 01 0B 0A 0D 07 08 0F 09 0C 05 06 03 00 0E 0B 08 0C 07 01 0E 02 0D 06 0F 00 09 0A 04 05 03 }
	$aoa = { 0C 01 0A 0F 09 02 06 08 00 0D 03 04 0E 07 05 0B 0A 0F 04 02 07 0C 09 05 06 01 0D 0E 00 0B 03 08 09 0E 0F 05 02 08 0C 03 07 00 04 0A 01 0D 0B 06 04 03 02 0C 09 05 0F 0A 0B 0E 01 07 06 00 08 0D }
	$aob = { 04 0B 02 0E 0F 00 08 0D 03 0C 09 07 05 0A 06 01 0D 00 0B 07 04 09 01 0A 0E 03 05 0C 02 0F 08 06 01 04 0B 0D 0C 03 07 0E 0A 0F 06 08 00 05 09 02 06 0B 0D 08 01 04 0A 07 09 05 00 0F 0E 02 03 0C }
	$aoc = { 0D 02 08 04 06 0F 0B 01 0A 09 03 0E 05 00 0C 07 01 0F 0D 08 0A 03 07 04 0C 05 06 0B 00 0E 09 02 07 0B 04 01 09 0C 0E 02 00 06 0A 0D 0F 03 05 08 02 01 0E 07 04 0A 08 0D 0F 0C 09 00 03 05 06 0B }
	$aod = { 39 31 29 21 19 11 09 01 3A 32 2A 22 1A 12 0A 02 3B 33 2B 23 1B 13 0B 03 3C 34 2C 24 3F 37 2F 27 1F 17 0F 07 3E 36 2E 26 1E 16 0E 06 3D 35 2D 25 1D 15 0D 05 1C 14 0C 04 }
	$aoe = { 0E 11 0B 18 01 05 03 1C 0F 06 15 0A 17 13 0C 04 1A 08 10 07 1B 14 0D 02 29 34 1F 25 2F 37 1E 28 33 2D 21 30 2C 31 27 38 22 35 2E 2A 32 24 1D 20 }
	$aof = { 3A 32 2A 22 1A 12 0A 02 3C 34 2C 24 1C 14 0C 04 3E 36 2E 26 1E 16 0E 06 40 38 30 28 20 18 10 08 39 31 29 21 19 11 09 01 3B 33 2B 23 1B 13 0B 03 3D 35 2D 25 1D 15 0D 05 3F 37 2F 27 1F 17 0F 07 }
	$aog = { 28 08 30 10 38 18 40 20 27 07 2F 0F 37 17 3F 1F 26 06 2E 0E 36 16 3E 1E 25 05 2D 0D 35 15 3D 1D 24 04 2C 0C 34 14 3C 1C 23 03 2B 0B 33 13 3B 1B 22 02 2A 0A 32 12 3A 1A 21 01 29 09 31 11 39 19 }
	$aoh = { 20 01 02 03 04 05 04 05 06 07 08 09 08 09 0A 0B 0C 0D 0C 0D 0E 0F 10 11 10 11 12 13 14 15 14 15 16 17 18 19 18 19 1A 1B 1C 1D 1C 1D 1E 1F 20 01 }
	$aoi = { 10 07 14 15 1D 0C 1C 11 01 0F 17 1A 05 12 1F 0A 02 08 18 0E 20 1B 03 09 13 0D 1E 06 16 0B 04 19 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$anv 
	or 	$anw 
	or 	$anx 
	or 	$any 
	or 	$anz 
	or 	$aoa 
	or 	$aob 
	or 	$aoc 
	or 	$aod 
	or 	$aoe 
	or 	$aof 
	or 	$aog 
	or 	$aoh 
	or 	$aoi 
  ) 
}

private rule capa_encrypt_data_using_AES_via__NET { 
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
 	$str_aoj = "RijndaelManaged" ascii wide
	$str_aok = "CryptoStream" ascii wide
	$str_aol = "System.Security.Cryptography" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_aoj 
	and 	$str_aok 
	and 	$str_aol  ) 
}

private rule capa_encrypt_data_using_skipjack { 
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
 	$aom = { A3 D7 09 83 F8 48 F6 F4 B3 21 15 78 99 B1 AF F9 E7 2D 4D 8A CE 4C CA 2E 52 95 D9 1E 4E 38 44 28 0A DF 02 A0 17 F1 60 68 12 B7 7A C3 E9 FA 3D 53 96 84 6B BA F2 63 9A 19 7C AE E5 F5 F7 16 6A A2 39 B6 7B 0F C1 93 81 1B EE B4 1A EA D0 91 2F B8 55 B9 DA 85 3F 41 BF E0 5A 58 80 5F 66 0B D8 90 35 D5 C0 A7 33 06 65 69 45 00 94 56 6D 98 9B 76 97 FC B2 C2 B0 FE DB 20 E1 EB D6 E4 DD 47 4A 1D 42 ED 9E 6E 49 3C CD 43 27 D2 07 D4 DE C7 67 18 89 CB 30 1F 8D C6 8F AA C8 74 DC C9 5D 5C 31 A4 70 88 61 2C 9F 0D 2B 87 50 82 54 64 26 7D 03 40 34 4B 1C 73 D1 C4 FD 3B CC FB 7F AB E6 3E 5B A5 AD 04 23 9C 14 51 22 F0 29 79 71 7E FF 8C 0E E2 0C EF BC 72 75 6F 37 A1 EC D3 8E 62 8B 86 10 E8 08 77 11 BE 92 4F 24 C5 32 36 9D CF F3 A6 BB AC 5E 6C A9 13 57 25 B5 E3 BD A8 3A 01 05 59 2A 46 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aom  ) 
}

private rule capa_reference_public_RSA_key { 
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
 	$aon = { 06 02 00 00 00 A4 00 00 52 53 41 31 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aon  ) 
}

private rule capa_encrypt_data_using_vest { 
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
 	$aoo = { 07 56 D2 37 3A F7 0A 52 5D C6 2C 87 DA 05 C1 D7 F4 1F 8C 34 }
	$aop = { 41 4B 1B DD 0D 65 72 EE 09 E7 A1 93 3F 0E 55 9C 63 89 3F B2 AB 5A 0E CB 2F 13 E3 9A C7 09 C5 8D C9 09 0D D7 59 1F A2 D6 CB B0 61 E5 39 44 F8 C5 8B C6 E5 B2 BD E3 82 D2 AB 04 DD D6 1F 94 CA EC 73 43 E7 94 5D 52 66 86 4F 4B 05 D4 AD 0F 66 A3 F9 15 9C C6 C9 3E 3A B8 9D 31 65 F8 C7 9A CE E0 6D BD 18 8D 63 F5 0A CD 11 B4 B5 EE 9B 28 9C A5 93 78 5B D1 D3 B1 2B 84 17 AB F4 85 EF 22 E1 D1 }
	$aoq = { 4F 70 46 DA E1 8D F6 41 59 E8 5D 26 1E CC 2F 89 26 6D 52 BA BC 11 6B A9 C6 47 E4 9C 1E B6 65 A2 B6 CD 90 47 1C DF F8 10 4B D2 7C C4 72 25 C6 97 25 5D C6 1D 4B 36 BC 38 36 33 F8 89 B4 4C 65 A7 96 CA 1B 63 C3 4B 6A 63 DC 85 4C 57 EE 2A 05 C7 0C E7 39 35 8A C1 BF 13 D9 52 51 3D 2E 41 F5 72 85 23 FE A1 AA 53 61 3B 25 5F 62 B4 36 EE 2A 51 AF 18 8E 9A C6 CF C4 07 4A 9B 25 9B 76 62 0E 3E 96 3A A7 64 23 6B B6 19 BC 2D 40 D7 36 3E E2 85 9A D1 22 9F BC 30 15 9F C2 5D F1 23 E6 3A 73 C0 A6 AD 71 B0 94 1C 9D B6 56 B6 2B }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aoo 
	or 	$aop 
	or 	$aoq  ) 
}

private rule capa_encrypt_data_using_blowfish { 
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
 	$num_aos = { 3A 39 CE 37 }
	$num_aot = { E9 3D 5A 68 }
	$num_aou = { 4B 7A 70 E9 }
	$num_aov = { D1 31 0B A6 }
	$aow = { 88 6A 3F 24 D3 08 A3 85 2E 8A 19 13 44 73 70 03 22 38 09 A4 D0 31 9F 29 98 FA 2E 08 89 6C 4E EC E6 21 28 45 77 13 D0 38 CF 66 54 BE 6C 0C E9 34 B7 29 AC C0 DD 50 7C C9 B5 D5 84 3F 17 09 47 B5 D9 D5 16 92 1B FB 79 89 }
	$aox = { A6 0B 31 D1 AC B5 DF 98 DB 72 FD 2F B7 DF 1A D0 ED AF E1 B8 96 7E 26 6A 45 90 7C BA 99 7F 2C F1 47 99 A1 24 F7 6C 91 B3 E2 F2 01 08 16 FC 8E 85 D8 20 69 63 69 4E 57 71 A3 FE 58 A4 7E 3D 93 F4 8F 74 95 0D 58 B6 8E 72 58 CD 8B 71 EE 4A 15 82 1D A4 54 7B B5 59 5A C2 39 D5 30 9C 13 60 F2 2A 23 B0 D1 C5 F0 85 60 28 18 79 41 CA EF 38 DB B8 B0 DC 79 8E 0E 18 3A 60 8B 0E 9E 6C 3E 8A 1E B0 C1 77 15 D7 27 4B 31 BD DA 2F AF 78 60 5C 60 55 F3 25 55 E6 94 AB 55 AA 62 98 48 57 40 14 E8 63 6A 39 CA 55 B6 10 AB 2A 34 5C CC }
	$aoy = { E9 70 7A 4B 44 29 B3 B5 2E 09 75 DB 23 26 19 C4 B0 A6 6E AD 7D DF A7 49 B8 60 EE 9C 66 B2 ED 8F 71 8C AA EC FF 17 9A 69 6C 52 64 56 E1 9E B1 C2 A5 02 36 19 29 4C 09 75 40 13 59 A0 3E 3A 18 E4 9A 98 54 3F 65 9D 42 5B D6 E4 8F 6B D6 3F F7 99 07 9C D2 A1 F5 30 E8 EF E6 38 2D 4D C1 5D 25 F0 86 20 DD 4C 26 EB 70 84 C6 E9 82 63 5E CC 1E 02 3F 6B 68 09 C9 EF BA 3E 14 18 97 3C A1 70 6A 6B 84 35 7F 68 86 E2 A0 52 05 53 9C B7 37 07 50 AA 1C 84 07 3E 5C AE DE 7F EC 44 7D 8E B8 F2 16 57 37 DA 3A B0 0D 0C 50 F0 04 1F 1C }
	$aoz = { 68 5A 3D E9 F7 40 81 94 1C 26 4C F6 34 29 69 94 F7 20 15 41 F7 D4 02 76 2E 6B F4 BC 68 00 A2 D4 71 24 08 D4 6A F4 20 33 B7 D4 B7 43 AF 61 00 50 2E F6 39 1E 46 45 24 97 74 4F 21 14 40 88 8B BF 1D FC 95 4D AF 91 B5 96 D3 DD F4 70 45 2F A0 66 EC 09 BC BF 85 97 BD 03 D0 6D AC 7F 04 85 CB 31 B3 27 EB 96 41 39 FD 55 E6 47 25 DA 9A 0A CA AB 25 78 50 28 F4 29 04 53 DA 86 2C 0A FB 6D B6 E9 62 14 DC 68 00 69 48 D7 A4 C0 0E 68 EE 8D A1 27 A2 FE 3F 4F 8C AD 87 E8 06 E0 8C B5 B6 D6 F4 7A 7C 1E CE AA EC 5F 37 D3 99 A3 78 }
	$apa = { 37 CE 39 3A CF F5 FA D3 37 77 C2 AB 1B 2D C5 5A 9E 67 B0 5C 42 37 A3 4F 40 27 82 D3 BE 9B BC 99 9D 8E 11 D5 15 73 0F BF 7E 1C 2D D6 7B C4 00 C7 6B 1B 8C B7 45 90 A1 21 BE B1 6E B2 B4 6E 36 6A 2F AB 48 57 79 6E 94 BC D2 76 A3 C6 C8 C2 49 65 EE F8 0F 53 7D DE 8D 46 1D 0A 73 D5 C6 4D D0 4C DB BB 39 29 50 46 BA A9 E8 26 95 AC 04 E3 5E BE F0 D5 FA A1 9A 51 2D 6A E2 8C EF 63 22 EE 86 9A B8 C2 89 C0 F6 2E 24 43 AA 03 1E A5 A4 D0 F2 9C BA 61 C0 83 4D 6A E9 9B 50 15 E5 8F D6 5B 64 BA F9 A2 26 28 E1 3A 3A A7 86 95 A9 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( $num_aos 
	and $num_aot 
	and $num_aou 
	and $num_aov  )  ) 
	or  (  ( 	$aow 
	or 	$aox 
	or 	$aoy 
	or 	$aoz 
	or 	$apa  )  )  ) 
}

private rule capa_generate_random_numbers_via_WinAPI { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/.{1,30}/i, /BCryptGenRandom/) 
	or 	pe.imports(/.{1,30}/i, /CryptGenRandom/)  )  )  ) 
}

private rule capa_generate_random_numbers_using_a_Mersenne_Twister { 
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
 	$num_apb = { 6C 07 89 65 }
	$num_apc = { 99 08 B0 DF }
	$num_apd = { 9D 2C 56 80 }
	$num_ape = { EF C6 00 00 }
	$num_apf = { FF 3A 58 AD }
	$num_apg = { B5 02 6F 5A A9 66 19 E9 }
	$num_aph = { 71 D6 7F FF ED A6 00 00 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( $num_apb 
	or $num_apc 
	or $num_apd 
	or $num_ape 
	or $num_apf 
	or $num_apg 
	or $num_aph  ) 
}

private rule capa_compress_data_via_WinAPI { 
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
 	$str_apk = "RtlDecompressBuffer" ascii wide
	$str_apl = "RtlDecompressBufferEx" ascii wide
	$str_apm = "RtlDecompressBufferEx2" ascii wide
	$str_apn = "RtlCompressBuffer" ascii wide
	$str_apo = "RtlCompressBufferLZNT1" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /RtlDecompressBuffer/) 
	or 	$str_apk 
	or 	pe.imports(/.{1,30}/i, /RtlDecompressBufferEx/) 
	or 	$str_apl 
	or 	pe.imports(/.{1,30}/i, /RtlDecompressBufferEx2/) 
	or 	$str_apm 
	or 	pe.imports(/.{1,30}/i, /RtlCompressBuffer/) 
	or 	$str_apn 
	or 	pe.imports(/.{1,30}/i, /RtlCompressBufferLZNT1/) 
	or 	$str_apo  ) 
}

private rule capa_hash_data_with_CRC32 { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /RtlComputeCrc32/)  ) 
}

private rule capa_hash_data_via_WinCrypt { 
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

private rule capa_hash_data_using_SHA256 { 
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
 	$num_app = { 6A 09 E6 67 }
	$num_apq = { BB 67 AE 85 }
	$num_apr = { 3C 6E F3 72 }
	$num_aps = { A5 4F F5 3A }
	$num_apt = { 51 0E 52 7F }
	$num_apu = { 9B 05 68 8C }
	$num_apv = { 1F 83 D9 AB }
	$num_apw = { 5B E0 CD 19 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( $num_app 
	and $num_apq 
	and $num_apr 
	and $num_aps 
	and $num_apt 
	and $num_apu 
	and $num_apv 
	and $num_apw  ) 
}

private rule capa_hash_data_using_tiger { 
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
 	$aqd = { 5E 0C E9 F7 7C B1 AA 02 EC A8 43 E2 03 4B 42 AC D3 FC D5 0D E3 5B CD 72 3A 7F F9 F6 93 9B 01 6D 93 91 1F D2 FF 78 99 CD E2 29 80 70 C9 A1 73 75 C3 83 2A 92 6B 32 64 B1 70 58 91 04 EE 3E 88 46 E6 EC 03 71 05 E3 AC EA 5C 53 A3 08 B8 69 41 C5 7C C4 DE 8D 91 54 E7 4C 0C F4 0D DC DF F4 A2 0A FA BE 4D A7 18 6F B7 10 6A AB D1 5A 23 B6 CC C6 FF E2 2F 57 21 61 72 13 1E 92 9D 19 6F 8C 48 1A CA 07 00 DA F4 F9 C9 4B C7 41 52 E8 F6 E6 F5 26 B6 47 59 EA DB 79 90 85 92 8C 9E C9 C5 85 18 4F 4B 86 6F A9 1E 76 8E D7 7D C1 B5 }
	$aqe = { 38 21 A1 05 5A BE A6 E6 98 7C F8 B4 A5 22 A1 B5 90 69 0B 14 89 60 3C 56 D5 5D 1F 39 2E CB 46 4C 34 94 B7 C9 DB AD 32 D9 F5 AF 15 20 E4 70 EA 08 F1 8C 47 3E 67 A6 65 D7 99 8D 27 AB 7E 75 FB C4 92 06 6E 2D 86 C6 11 DF 16 3B 7F 0D F1 84 EB DD 04 EA 65 A6 04 F6 2E 6F B3 DF E0 F0 0F 0F 8E 4A 51 BA BC 3D F8 EE ED A5 1E 37 A4 0E 2A 0A 4F FC 29 84 B3 5C A8 1D 3E E8 E2 1C 1B BA 82 F8 8F DC 0D E8 53 83 5E 50 45 CD 17 07 DB D4 00 9A D1 18 01 81 F3 A5 ED CF A0 34 F2 CA 87 88 51 7E E7 0B 36 51 C4 B3 38 14 34 1E F9 CC 89 }
	$aqf = { 9B F3 DA F1 2F CC 9F F4 81 92 F2 6F C6 D5 7F 48 3F A8 DC FC 67 06 A3 E8 63 CE FC D2 E3 4B 9B 2C C2 BB FB 93 4B F7 3F DA 66 BA 70 FE D2 65 A1 2F D4 93 0E 97 79 E2 03 A1 71 5E E4 B0 77 EC CD BE 97 E4 85 39 72 1E B4 CF 17 50 F7 5E 02 AA 0A B7 E0 B8 40 38 F0 09 23 D4 79 85 89 35 D0 1A FC 8E C5 AB B2 E2 0B 92 C6 96 72 91 5A 37 63 41 AF 66 FB 27 71 CA DC AB 74 21 41 FF 72 4A A6 CE 3C B3 A5 66 30 08 33 49 4A F0 F5 9A 28 D7 CD 0A 97 8D 5E C2 C8 31 E0 E8 96 8F 47 5D 87 76 22 C0 FE F3 DD 90 61 05 10 F3 7B EC 91 14 0F }
	$aqg = { 55 3C 32 26 85 60 0E 5B F5 59 1B FA A9 C1 46 1A FA 8F 4C 7C A1 45 E2 A9 D7 55 29 DB 59 51 CA 65 C2 AF 35 CE 76 0A DB 05 45 3D 11 A9 7E C7 EA 81 0D 0A AC B6 8A F8 8E 52 FF E3 7B 59 53 A2 9E A0 56 CD 48 AC B3 DF 0D 43 6F E4 5C F4 7A A6 B3 C4 5E D0 E2 FB D8 CF CE 4E F0 35 99 B3 10 6F F5 3E C6 19 D6 9C 82 D6 22 0B 69 20 DF 74 0A 46 FD 17 40 ED 10 85 8E CC F8 6C A7 CA 6E 3A BF 24 C8 D6 49 70 81 1A 58 3D 24 61 A2 63 C1 BB B6 AC 8B 04 32 CC 44 7D C2 8A A3 D9 AB 10 F4 AA 5B FF DD 7F 4B 82 04 A8 5A 49 6D AD 94 9F 8C }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aqd 
	or 	$aqe 
	or 	$aqf 
	or 	$aqg 
  ) 
}

private rule capa_hash_data_using_SHA224 { 
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
 	$num_aqv = { C1 05 9E D8 }
	$num_aqw = { 36 7C D5 07 }
	$num_aqx = { 30 70 DD 17 }
	$num_aqy = { F7 0E 59 39 }
	$num_aqz = { FF C0 0B 31 }
	$num_ara = { 68 58 15 11 }
	$num_arb = { 64 F9 8F A7 }
	$num_arc = { BE FA 4F A4 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( $num_aqv 
	and $num_aqw 
	and $num_aqx 
	and $num_aqy 
	and $num_aqz 
	and $num_ara 
	and $num_arb 
	and $num_arc  ) 
}

private rule capa_schedule_task_via_command_line { 
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
 	$ard = /schtasks/ nocase ascii wide 
	$are = /\/create / nocase ascii wide 
	$arf = /Register-ScheduledTask / nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_create_process

	and  (  (  (  ( 	$ard 
	and 	$are  )  ) 
	or 	$arf  )  )  ) 
}

private rule capa_persist_via_Windows_service { 
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
 	$ari = /^sc(\.exe)?$/ nocase ascii wide 
	$arj = /create / nocase ascii wide 
	$ark = /^sc(\.exe)? create/ nocase ascii wide 
	$arl = /New-Service / nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_create_process

	and  (  (  (  ( 	$ari 
	and 	$arj  )  ) 
	or 	$ark 
	or 	$arl  )  )  )  )  ) 
}

private rule capa_persist_via_Active_Setup_registry_key { 
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
 	$num_arm = { 80 00 00 02 }
	$arn = /Software\\Microsoft\\Active Setup\\Installed Components/ nocase ascii wide 
	$str_aro = "StubPath" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_set_registry_value

	or $num_arm  )  ) 
	and 	$arn 
	and 	$str_aro  ) 
}

private rule capa_persist_via_GinaDLL_registry_key { 
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
 	$num_arp = { 80 00 00 02 }
	$arq = /SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon/ nocase ascii wide 
	$arr = /GinaDLL/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_set_registry_value

	or $num_arp  )  ) 
	and 	$arq 
	and 	$arr  ) 
}

private rule capa_persist_via_AppInit_DLLs_registry_key { 
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
 	$num_ars = { 80 00 00 02 }
	$art = /Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows/ nocase ascii wide 
	$aru = /Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows/ nocase ascii wide 
	$arv = /AppInit_DLLs/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_set_registry_value

	or $num_ars  )  ) 
	and  (  ( 	$art 
	or 	$aru  )  ) 
	and 	$arv  ) 
}

private rule capa_persist_via_Run_registry_key { 
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
 	$num_arx = { 80 00 00 01 }
	$num_ary = { 80 00 00 02 }
	$arz = /Software\\Microsoft\\Windows\\CurrentVersion/ nocase ascii wide 
	$asa = /Run/ nocase ascii wide 
	$asb = /Explorer\\Shell Folders/ nocase ascii wide 
	$asc = /User Shell Folders/ nocase ascii wide 
	$asd = /RunServices/ nocase ascii wide 
	$ase = /Policies\\Explorer\\Run/ nocase ascii wide 
	$asf = /Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load/ nocase ascii wide 
	$asg = /System\\CurrentControlSet\\Control\\Session Manager\\BootExecute/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_set_registry_value

	or $num_arx 
	or $num_ary  )  ) 
	and  (  (  (  ( 	$arz 
	and  (  ( 	$asa 
	or 	$asb 
	or 	$asc 
	or 	$asd 
	or 	$ase  )  )  )  ) 
	or 	$asf 
	or 	$asg  )  )  ) 
}

private rule capa_persist_via_Winlogon_Helper_DLL_registry_key { 
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
 	$num_ash = { 80 00 00 01 }
	$num_asi = { 80 00 00 02 }
	$asj = /Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon/ nocase ascii wide 
	$ask = /Notify/ nocase ascii wide 
	$asl = /Userinit/ nocase ascii wide 
	$asm = /Shell/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	capa_set_registry_value

	or $num_ash 
	or $num_asi  )  ) 
	and 	$asj 
	and  (  ( 	$ask 
	or 	$asl 
	or 	$asm  )  )  ) 
}

private rule capa_compiled_to_the__NET_platform { 
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

private rule capa_get_COMSPEC_environment_variable { 
  meta: 
 	description = "get COMSPEC environment variable (converted from capa rule)"
	namespace = "host-interaction/environment-variable"
	author = "matthew.williams@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-comspec-environment-variable.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_asn = "COMSPEC" ascii wide
	$str_aso = "%COMSPEC%" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_query_environment_variable

	and  (  ( 	$str_asn 
	or 	$str_aso  )  )  ) 
}

private rule capa_packed_with_MaskPE { 
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
 ( 	for any asp in pe.sections : ( asp.name == ".MaskPE" )  ) 
}

private rule capa_add_file_to_cabinet_file { 
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

private rule capa_reference_Quad9_DNS_server { 
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
 	$str_asq = "9.9.9.9" ascii wide
	$str_asr = "149.112.112.112" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_asq 
	or 	$str_asr  ) 
}

private rule capa_run_PowerShell_expression { 
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
 	$ass = / iex\(/ nocase ascii wide 
	$ast = / iex / nocase ascii wide 
	$asu = /Invoke-Expression/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$ass 
	or 	$ast 
	or 	$asu  )  )  ) 
}

private rule capa_get_file_size { 
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

private rule capa_open_cabinet_file { 
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

private rule capa_packed_with_Dragon_Armor { 
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
 ( 	for any asv in pe.sections : ( asv.name == "DAStub" )  ) 
}

private rule capa_hooked_by_API_Override { 
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
 ( 	for any asw in pe.sections : ( asw.name == ".winapi" )  ) 
}

private rule capa_get_service_handle { 
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

private rule capa_packed_with_Neolite { 
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
 ( 	for any asx in pe.sections : ( asx.name == ".neolite" ) 
	or 	for any asy in pe.sections : ( asy.name == ".neolit" )  ) 
}

private rule capa_encrypt_data_using_Salsa20_or_ChaCha { 
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
 	$str_asz = "expand 32-byte k = sigma" ascii wide
	$str_ata = "expand 16-byte k = tau" ascii wide
	$str_atb = "expand 32-byte kexpand 16-byte k" ascii wide
	$str_atc = "expa" ascii wide
	$str_atd = "nd 3" ascii wide
	$str_ate = "2-by" ascii wide
	$str_atf = "te k" ascii wide
	$num_atg = { 61 70 78 65 }
	$num_ath = { 33 20 64 6E }
	$num_ati = { 79 62 2D 32 }
	$num_atj = { 6B 20 65 74 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_asz 
	or 	$str_ata 
	or 	$str_atb 
	or  (  ( 	$str_atc 
	and 	$str_atd 
	and 	$str_ate 
	and 	$str_atf  )  ) 
	or  (  ( $num_atg 
	and $num_ath 
	and $num_ati 
	and $num_atj  )  )  ) 
}

private rule capa_create_container { 
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
 	$atk = /^docker(\.exe)? create/ ascii wide 
	$atl = /^docker(\.exe)? start/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$atk 
	or 	$atl 
  ) 
}

private rule capa_listen_for_remote_procedure_calls { 
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

private rule capa_enumerate_internet_cache { 
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

private rule capa_reference_Verisign_DNS_server { 
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
 	$str_atm = "64.6.64.6" ascii wide
	$str_atn = "64.6.65.6" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_atm 
	or 	$str_atn  ) 
}

private rule capa_packaged_as_a_NSIS_installer { 
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
 	$ato = /http:\/\/nsis\.sf\.net/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$ato  ) 
}

private rule capa_reference_AliDNS_DNS_server { 
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
 	$str_atp = "223.5.5.5" ascii wide
	$str_atq = "223.6.6.6" ascii wide
	$str_atr = "2400:3200::1" ascii wide
	$str_ats = "2400:3200:baba::1" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_atp 
	or 	$str_atq 
	or 	$str_atr 
	or 	$str_ats  ) 
}

private rule capa_get_networking_parameters { 
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

private rule capa_packed_with_TSULoader { 
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
 ( 	for any atx in pe.sections : ( atx.name == ".tsuarch" ) 
	or 	for any aty in pe.sections : ( aty.name == ".tsustub" )  ) 
}

private rule capa_packaged_as_a_WinZip_self_extracting_archive { 
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
 ( 	for any atz in pe.sections : ( atz.name == "_winzip_" )  ) 
}

private rule capa_list_containers { 
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
 	$aua = /^docker(\.exe)? ps/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aua 
  ) 
}

private rule capa_get_file_version_info { 
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

private rule capa_packed_with_RPCrypt { 
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
 ( 	for any aub in pe.sections : ( aub.name == "RCryptor" ) 
	or 	for any auc in pe.sections : ( auc.name == ".RCrypt" )  ) 
}

private rule capa_get_proxy { 
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
 	$str_aud = "ProxyServer" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_create_or_open_registry_key

	and 	$str_aud  ) 
}

private rule capa_reference_DNS_over_HTTPS_endpoints { 
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
 	$aue = /https:\/\/doh.seby.io:8443\/dns-query.{,1000}/ nocase ascii wide 
	$auf = /https:\/\/family.cloudflare-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$aug = /https:\/\/free.bravedns.com\/dns-query.{,1000}/ nocase ascii wide 
	$auh = /https:\/\/doh.familyshield.opendns.com\/dns-query.{,1000}/ nocase ascii wide 
	$aui = /https:\/\/doh-de.blahdns.com\/dns-query.{,1000}/ nocase ascii wide 
	$auj = /https:\/\/adblock.mydns.network\/dns-query.{,1000}/ nocase ascii wide 
	$auk = /https:\/\/bravedns.com\/configure.{,1000}/ nocase ascii wide 
	$aul = /https:\/\/cloudflare-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$aum = /https:\/\/commons.host.{,1000}/ nocase ascii wide 
	$aun = /https:\/\/dns.aa.net.uk\/dns-query.{,1000}/ nocase ascii wide 
	$auo = /https:\/\/dns.alidns.com\/dns-query.{,1000}/ nocase ascii wide 
	$aup = /https:\/\/dns-asia.wugui.zone\/dns-query.{,1000}/ nocase ascii wide 
	$auq = /https:\/\/dns.containerpi.com\/dns-query.{,1000}/ nocase ascii wide 
	$aur = /https:\/\/dns.containerpi.com\/doh\/family-filter\/.{,1000}/ nocase ascii wide 
	$aus = /https:\/\/dns.containerpi.com\/doh\/secure-filter\/.{,1000}/ nocase ascii wide 
	$aut = /https:\/\/dns.digitale-gesellschaft.ch\/dns-query.{,1000}/ nocase ascii wide 
	$auu = /https:\/\/dns.dnshome.de\/dns-query.{,1000}/ nocase ascii wide 
	$auv = /https:\/\/dns.dns-over-https.com\/dns-query.{,1000}/ nocase ascii wide 
	$auw = /https:\/\/dns.dnsoverhttps.net\/dns-query.{,1000}/ nocase ascii wide 
	$aux = /https:\/\/dns.flatuslifir.is\/dns-query.{,1000}/ nocase ascii wide 
	$auy = /https:\/\/dnsforge.de\/dns-query.{,1000}/ nocase ascii wide 
	$auz = /https:\/\/dns.google\/dns-query.{,1000}/ nocase ascii wide 
	$ava = /https:\/\/dns.nextdns.io\/<config_id>.{,1000}/ nocase ascii wide 
	$avb = /https:\/\/dns.rubyfish.cn\/dns-query.{,1000}/ nocase ascii wide 
	$avc = /https:\/\/dns.switch.ch\/dns-query.{,1000}/ nocase ascii wide 
	$avd = /https:\/\/dns.twnic.tw\/dns-query.{,1000}/ nocase ascii wide 
	$ave = /https:\/\/dns.wugui.zone\/dns-query.{,1000}/ nocase ascii wide 
	$avf = /https:\/\/doh-2.seby.io\/dns-query.{,1000}/ nocase ascii wide 
	$avg = /https:\/\/doh.42l.fr\/dns-query.{,1000}/ nocase ascii wide 
	$avh = /https:\/\/doh.applied-privacy.net\/query.{,1000}/ nocase ascii wide 
	$avi = /https:\/\/doh.armadillodns.net\/dns-query.{,1000}/ nocase ascii wide 
	$avj = /https:\/\/doh.captnemo.in\/dns-query.{,1000}/ nocase ascii wide 
	$avk = /https:\/\/doh.centraleu.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$avl = /https:\/\/doh.cleanbrowsing.org\/doh\/family-filter\/.{,1000}/ nocase ascii wide 
	$avm = /https:\/\/doh.crypto.sx\/dns-query.{,1000}/ nocase ascii wide 
	$avn = /https:\/\/doh.dnslify.com\/dns-query.{,1000}/ nocase ascii wide 
	$avo = /https:\/\/doh.dns.sb\/dns-query.{,1000}/ nocase ascii wide 
	$avp = /https:\/\/dohdot.coxlab.net\/dns-query.{,1000}/ nocase ascii wide 
	$avq = /https:\/\/doh.eastas.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$avr = /https:\/\/doh.eastau.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$avs = /https:\/\/doh.eastus.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$avt = /https:\/\/doh.ffmuc.net\/dns-query.{,1000}/ nocase ascii wide 
	$avu = /https:\/\/doh.libredns.gr\/dns-query.{,1000}/ nocase ascii wide 
	$avv = /https:\/\/doh.li\/dns-query.{,1000}/ nocase ascii wide 
	$avw = /https:\/\/doh.northeu.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$avx = /https:\/\/doh.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$avy = /https:\/\/doh.powerdns.org.{,1000}/ nocase ascii wide 
	$avz = /https:\/\/doh.tiarap.org\/dns-query.{,1000}/ nocase ascii wide 
	$awa = /https:\/\/doh.tiar.app\/dns-query.{,1000}/ nocase ascii wide 
	$awb = /https:\/\/doh.westus.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$awc = /https:\/\/doh.xfinity.com\/dns-query.{,1000}/ nocase ascii wide 
	$awd = /https:\/\/example.doh.blockerdns.com\/dns-query.{,1000}/ nocase ascii wide 
	$awe = /https:\/\/fi.doh.dns.snopyta.org\/dns-query.{,1000}/ nocase ascii wide 
	$awf = /https:\/\/ibksturm.synology.me\/dns-query.{,1000}/ nocase ascii wide 
	$awg = /https:\/\/ibuki.cgnat.net\/dns-query.{,1000}/ nocase ascii wide 
	$awh = /https:\/\/jcdns.fun\/dns-query.{,1000}/ nocase ascii wide 
	$awi = /https:\/\/jp.tiarap.org\/dns-query.{,1000}/ nocase ascii wide 
	$awj = /https:\/\/jp.tiar.app\/dns-query.{,1000}/ nocase ascii wide 
	$awk = /https:\/\/odvr.nic.cz\/doh.{,1000}/ nocase ascii wide 
	$awl = /https:\/\/ordns.he.net\/dns-query.{,1000}/ nocase ascii wide 
	$awm = /https:\/\/rdns.faelix.net\/.{,1000}/ nocase ascii wide 
	$awn = /https:\/\/resolver-eu.lelux.fi\/dns-query.{,1000}/ nocase ascii wide 
	$awo = /https:\/\/doh-jp.blahdns.com\/dns-query.{,1000}/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$aue 
	or 	$auf 
	or 	$aug 
	or 	$auh 
	or 	$aui 
	or 	$auj 
	or 	$auk 
	or 	$aul 
	or 	$aum 
	or 	$aun 
	or 	$auo 
	or 	$aup 
	or 	$auq 
	or 	$aur 
	or 	$aus 
	or 	$aut 
	or 	$auu 
	or 	$auv 
	or 	$auw 
	or 	$aux 
	or 	$auy 
	or 	$auz 
	or 	$ava 
	or 	$avb 
	or 	$avc 
	or 	$avd 
	or 	$ave 
	or 	$avf 
	or 	$avg 
	or 	$avh 
	or 	$avi 
	or 	$avj 
	or 	$avk 
	or 	$avl 
	or 	$avm 
	or 	$avn 
	or 	$avo 
	or 	$avp 
	or 	$avq 
	or 	$avr 
	or 	$avs 
	or 	$avt 
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
	or 	$awh 
	or 	$awi 
	or 	$awj 
	or 	$awk 
	or 	$awl 
	or 	$awm 
	or 	$awn 
	or 	$awo  ) 
}

private rule capa_packed_with_Crunch { 
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
 ( 	for any awp in pe.sections : ( awp.name == "BitArts" )  ) 
}

private rule capa_delete_registry_key_via_offline_registry_library { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /ORDeleteKey/) 
	or 	pe.imports(/.{1,30}/i, /ORDeleteValue/)  ) 
}

private rule capa_get_token_membership { 
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

private rule capa_packed_with_PECompact { 
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
 ( 	for any awq in pe.sections : ( awq.name == "PEC2TO" ) 
	or 	for any awr in pe.sections : ( awr.name == "PEC2" ) 
	or 	for any aws in pe.sections : ( aws.name == "pec" ) 
	or 	for any awt in pe.sections : ( awt.name == "pec1" ) 
	or 	for any awu in pe.sections : ( awu.name == "pec2" ) 
	or 	for any awv in pe.sections : ( awv.name == "pec3" ) 
	or 	for any aww in pe.sections : ( aww.name == "pec4" ) 
	or 	for any awx in pe.sections : ( awx.name == "pec5" ) 
	or 	for any awy in pe.sections : ( awy.name == "pec6" ) 
	or 	for any awz in pe.sections : ( awz.name == "PEC2MO" )  ) 
}

private rule capa_packaged_as_a_CreateInstall_installer { 
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
 ( 	for any axa in pe.sections : ( axa.name == ".gentee" )  ) 
}

private rule capa_packed_with_Pepack { 
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
 ( 	for any axb in pe.sections : ( axb.name == "PEPACK!!" )  ) 
}

private rule capa_reference_Google_Public_DNS_server { 
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
 	$str_axc = "8.8.8.8" ascii wide
	$str_axd = "8.8.4.4" ascii wide
	$str_axe = "2001:4860:4860::8888" ascii wide
	$str_axf = "2001:4860:4860::8844" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_axc 
	or 	$str_axd 
	or 	$str_axe 
	or 	$str_axf  ) 
}

private rule capa_linked_against_C___regex_library { 
  meta: 
 	description = "linked against C++ regex library (converted from capa rule)"
	namespace = "linking/static/cppregex"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-c-regex-library.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_axg = "regex_error(error_syntax)" ascii wide
	$str_axh = "regex_error(error_collate): The expression contained an invalid collating element name." ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_axg 
	or 	$str_axh  ) 
}

private rule capa_packed_with_MEW { 
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
 ( 	for any axm in pe.sections : ( axm.name == "MEW" )  ) 
}

private rule capa_reference_114DNS_DNS_server { 
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
 	$str_axn = "114.114.114.114" ascii wide
	$str_axo = "114.114.115.115" ascii wide
	$str_axp = "114.114.114.119" ascii wide
	$str_axq = "114.114.115.119" ascii wide
	$str_axr = "114.114.114.110" ascii wide
	$str_axs = "114.114.115.110" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_axn 
	or 	$str_axo 
	or 	$str_axp 
	or 	$str_axq 
	or 	$str_axr 
	or 	$str_axs  ) 
}

private rule capa_migrate_process_to_active_window_station { 
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
 	$str_axt = "winsta0" ascii wide
	$str_axu = "WinSta0" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /OpenWindowStation/) 
	and  (  ( 	$str_axt 
	or 	$str_axu  )  ) 
	and 	pe.imports(/.{1,30}/i, /SetProcessWindowStation/) 
	and 	pe.imports(/.{1,30}/i, /OpenInputDesktop/) 
	and 	pe.imports(/.{1,30}/i, /SetThreadDesktop/)  ) 
}

private rule capa_packed_with_Epack { 
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
 ( 	for any axv in pe.sections : ( axv.name == "!Epack" )  ) 
}

private rule capa_packaged_as_a_Pintool { 
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
 ( 	for any axw in pe.sections : ( axw.name == ".charmve" ) 
	or 	for any axx in pe.sections : ( axx.name == ".pinclie" )  ) 
}

private rule capa_get_thread_local_storage_value { 
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

private rule capa_rebuilt_by_ImpRec { 
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
 ( 	for any axz in pe.sections : ( axz.name == ".mackt" )  ) 
}

private rule capa_enumerate_threads { 
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

private rule capa_reference_Comodo_Secure_DNS_server { 
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
 	$str_aya = "8.26.56.26" ascii wide
	$str_ayb = "8.20.247.20" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_aya 
	or 	$str_ayb  ) 
}

private rule capa_build_Docker_image { 
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
 	$ayc = /^docker(\.exe)? build/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$ayc 
  ) 
}

private rule capa_decrypt_data_via_SSPI { 
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

private rule capa_reference_L3_DNS_server { 
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
 	$str_ayd = "4.2.2.1" ascii wide
	$str_aye = "4.2.2.2" ascii wide
	$str_ayf = "4.2.2.3" ascii wide
	$str_ayg = "4.2.2.4" ascii wide
	$str_ayh = "4.2.2.5" ascii wide
	$str_ayi = "4.2.2.6" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_ayd 
	or 	$str_aye 
	or 	$str_ayf 
	or 	$str_ayg 
	or 	$str_ayh 
	or 	$str_ayi  ) 
}

private rule capa_packaged_as_a_Wise_installer { 
  meta: 
 	description = "packaged as a Wise installer (converted from capa rule)"
	namespace = "executable/installer/wiseinstall"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-wise-installer.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_ayj = "WiseMain" ascii wide
	$ayk = /Wise Installation Wizard/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_ayj 
	or 	$ayk  ) 
}

private rule capa_run_in_container { 
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
 	$ayl = /^docker(\.exe)? exec/ ascii wide 
	$aym = /^kubectl(\.exe)? exec/ ascii wide 
	$ayn = /^kubectl(\.exe)? run/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$ayl 
	or 	$aym 
	or 	$ayn 
  ) 
}

private rule capa_acquire_debug_privileges { 
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
 	$str_ayo = "SeDebugPrivilege" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_ayo  ) 
}

private rule capa_empty_the_recycle_bin { 
  meta: 
 	description = "empty the recycle bin (converted from capa rule)"
	namespace = "host-interaction/recycle-bin"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/empty-the-recycle-bin.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /SHEmptyRecycleBin/)  ) 
}

private rule capa_compare_security_identifiers { 
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

private rule capa_query_remote_server_for_available_data { 
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

private rule capa_packed_with_enigma { 
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
 ( 	for any ayp in pe.sections : ( ayp.name == ".enigma1" ) 
	or 	for any ayq in pe.sections : ( ayq.name == ".enigma2" )  ) 
}

private rule capa_initialize_hashing_via_WinCrypt { 
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

private rule capa_packed_with_StarForce { 
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
 ( 	for any ayr in pe.sections : ( ayr.name == ".sforce3" )  ) 
}

private rule capa_encrypt_data_via_SSPI { 
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

private rule capa_packed_with_ProCrypt { 
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
 ( 	for any ays in pe.sections : ( ays.name == "ProCrypt" )  ) 
}

private rule capa_packed_with_WWPACK { 
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
 ( 	for any ayt in pe.sections : ( ayt.name == ".WWPACK" ) 
	or 	for any ayu in pe.sections : ( ayu.name == ".WWP32" )  ) 
}

private rule capa_reference_Cloudflare_DNS_server { 
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
 	$str_ayv = "1.1.1.1" ascii wide
	$str_ayw = "1.0.0.1" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_ayv 
	or 	$str_ayw  ) 
}

private rule capa_get_system_firmware_table { 
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

private rule capa_get_socket_information { 
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

private rule capa_check_license_value { 
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
 	$str_ayx = "Kernel-VMDetection-Private" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /NtQueryLicenseValue/) 
	and 	$str_ayx  ) 
}

private rule capa_bypass_UAC_via_ICMLuaUtil { 
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
 	$str_ayy = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide
	$ayz = { F9 C7 5F 3E 51 9A 67 43 90 63 A1 20 24 4F BE C7 }
	$str_aza = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_ayy 
	or 	$ayz  )  ) 
	and 	$str_aza  ) 
}

private rule capa_reference_screen_saver_executable { 
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
 	$str_azb = "SCRNSAVE.EXE" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_azb  ) 
}

private rule capa_create_Restart_Manager_session { 
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

private rule capa_reference_kornet_DNS_server { 
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
 	$str_azc = "168.126.63.1" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_azc  ) 
}

private rule capa_packed_with_Themida { 
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
 ( 	for any azd in pe.sections : ( azd.name == "Themida" ) 
	or 	for any aze in pe.sections : ( aze.name == ".Themida" ) 
	or 	for any azf in pe.sections : ( azf.name == "WinLicen" )  ) 
}

private rule capa_impersonate_user { 
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

private rule capa_get_user_security_identifier { 
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

private rule capa_read_raw_disk_data { 
  meta: 
 	description = "read raw disk data (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/read-raw-disk-data.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_azg = "\\\\.\\PhysicalDrive0" ascii wide
	$str_azh = "\\\\.\\C:" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_azg 
	or 	$str_azh  ) 
}

private rule capa_bypass_UAC_via_scheduled_task_environment_variable { 
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
 	$str_azi = "schtasks.exe" ascii wide
	$azj = /Microsoft\\Windows\\DiskCleanup\\SilentCleanup/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_azi 
	and 	$azj 
	and 	capa_create_process
 ) 
}

private rule capa_reference_AES_constants { 
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
 	$azo = { 50 A7 F4 51 53 65 41 7E }
	$azp = { 63 7C 77 7B F2 6B 6F C5 }
	$azq = { 52 09 6A D5 30 36 A5 38 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$azo 
	or 	$azp 
	or 	$azq  ) 
}

private rule capa_compiled_with_Nim { 
  meta: 
 	description = "compiled with Nim (converted from capa rule)"
	namespace = "compiler/nim"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/compiled-with-nim.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$azr = /NimMain/ ascii wide 
	$azs = /NimMainModule/ ascii wide 
	$azt = /NimMainInner/ ascii wide 
	$azu = /io.nim$/ ascii wide 
	$azv = /fatal.nim$/ ascii wide 
	$azw = /system.nim$/ ascii wide 
	$azx = /alloc.nim$/ ascii wide 
	$azy = /osalloc.nim$/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$azr 
	or 	$azs 
	or 	$azt 
	or 	$azu 
	or 	$azv 
	or 	$azw 
	or 	$azx 
	or 	$azy  ) 
}

private rule capa_hook_routines_via_microsoft_detours { 
  meta: 
 	description = "hook routines via microsoft detours (converted from capa rule)"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/Flare-On%202017/Challenge7.pdf"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/hook-routines-via-microsoft-detours.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$num_azz = { 52 72 74 64 }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( $num_azz  ) 
}

private rule capa_packed_with_SVKP { 
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
 ( 	for any baa in pe.sections : ( baa.name == ".svkp" )  ) 
}

private rule capa_flush_cabinet_file { 
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

private rule capa_enumerate_system_firmware_tables { 
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

private rule capa_reference_startup_folder { 
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
 	$bab = /Start Menu\\Programs\\Startup/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bab  ) 
}

private rule capa_encrypt_or_decrypt_data_via_BCrypt { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/.{1,30}/i, /BCryptDecrypt/) 
	or 	pe.imports(/.{1,30}/i, /BCryptEncrypt/)  )  )  ) 
}

private rule capa_connect_network_resource { 
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

private rule capa_packed_with_Shrinker { 
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
 ( 	for any bac in pe.sections : ( bac.name == ".shrink1" ) 
	or 	for any bad in pe.sections : ( bad.name == ".shrink2" ) 
	or 	for any bae in pe.sections : ( bae.name == ".shrink3" )  ) 
}

private rule capa_packed_with_VProtect { 
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
 ( 	for any baf in pe.sections : ( baf.name == "VProtect" )  ) 
}

private rule capa_packed_with_CCG { 
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
 ( 	for any bag in pe.sections : ( bag.name == ".ccg" )  ) 
}

private rule capa_set_console_window_title { 
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

private rule capa_get_routing_table { 
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

private rule capa_reference_Hurricane_Electric_DNS_server { 
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
 	$str_bah = "216.218.130.2" ascii wide
	$str_bai = "216.218.131.2" ascii wide
	$str_baj = "216.218.132.2" ascii wide
	$str_bak = "216.66.1.2" ascii wide
	$str_bal = "216.66.80.18" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bah 
	or 	$str_bai 
	or 	$str_baj 
	or 	$str_bak 
	or 	$str_bal  ) 
}

private rule capa_packed_with_Mpress { 
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
 ( 	for any bam in pe.sections : ( bam.name == ".MPRESS1" ) 
	or 	for any ban in pe.sections : ( ban.name == ".MPRESS2" )  ) 
}

private rule capa_packaged_as_an_InstallShield_installer { 
  meta: 
 	description = "packaged as an InstallShield installer (converted from capa rule)"
	namespace = "executable/installer/installshield"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-an-installshield-installer.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bao = "InstallShield" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bao  ) 
}

private rule capa_mine_cryptocurrency { 
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
 	$str_bap = "stratum+tcp://" ascii wide
	$str_baq = "xmrig" ascii wide
	$str_bar = "xmr-stak" ascii wide
	$str_bas = "supportxmr.com:" ascii wide
	$str_bat = "dwarfpool.com:" ascii wide
	$str_bau = "minergate" ascii wide
	$str_bav = "xmr." ascii wide
	$str_baw = "monero." ascii wide
	$str_bax = "Bitcoin" ascii wide
	$str_bay = "Bitcoin" ascii wide
	$str_baz = "BitcoinGold" ascii wide
	$str_bba = "BtcCash" ascii wide
	$str_bbb = "Ethereum" ascii wide
	$str_bbc = "BlackCoin" ascii wide
	$str_bbd = "ByteCoin" ascii wide
	$str_bbe = "EmerCoin" ascii wide
	$str_bbf = "ReddCoin" ascii wide
	$str_bbg = "Peercoin" ascii wide
	$str_bbh = "Ripple" ascii wide
	$str_bbi = "Miota" ascii wide
	$str_bbj = "Cardano" ascii wide
	$str_bbk = "Lisk" ascii wide
	$str_bbl = "Stratis" ascii wide
	$str_bbm = "Waves" ascii wide
	$str_bbn = "Qtum" ascii wide
	$str_bbo = "Stellar" ascii wide
	$str_bbp = "ViaCoin" ascii wide
	$str_bbq = "Electroneum" ascii wide
	$str_bbr = "Dash" ascii wide
	$str_bbs = "Doge" ascii wide
	$str_bbt = "Monero" ascii wide
	$str_bbu = "Graft" ascii wide
	$str_bbv = "Zcash" ascii wide
	$str_bbw = "Ya.money" ascii wide
	$str_bbx = "Ya.disc" ascii wide
	$str_bby = "Steam" ascii wide
	$str_bbz = "vk.cc" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bap 
	or 	$str_baq 
	or 	$str_bar 
	or 	$str_bas 
	or 	$str_bat 
	or 	$str_bau 
	or 	$str_bav 
	or 	$str_baw 
	or 	$str_bax 
	or 	$str_bay 
	or 	$str_baz 
	or 	$str_bba 
	or 	$str_bbb 
	or 	$str_bbc 
	or 	$str_bbd 
	or 	$str_bbe 
	or 	$str_bbf 
	or 	$str_bbg 
	or 	$str_bbh 
	or 	$str_bbi 
	or 	$str_bbj 
	or 	$str_bbk 
	or 	$str_bbl 
	or 	$str_bbm 
	or 	$str_bbn 
	or 	$str_bbo 
	or 	$str_bbp 
	or 	$str_bbq 
	or 	$str_bbr 
	or 	$str_bbs 
	or 	$str_bbt 
	or 	$str_bbu 
	or 	$str_bbv 
	or 	$str_bbw 
	or 	$str_bbx 
	or 	$str_bby 
	or 	$str_bbz  ) 
}

private rule capa_packed_with_SeauSFX { 
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
 ( 	for any bca in pe.sections : ( bca.name == ".seau" )  ) 
}

private rule capa_debug_build { 
  meta: 
 	description = "debug build (converted from capa rule)"
	namespace = "executable/pe/debug"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/debug-build.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$str_bcb = "Assertion failed!" ascii wide
	$str_bcc = "Assertion failed:" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bcb 
	or 	$str_bcc  ) 
}

private rule capa_packed_with_Simple_Pack { 
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
 ( 	for any bcd in pe.sections : ( bcd.name == ".spack" )  ) 
}

private rule capa_resolve_function_by_hash { 
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
 	$num_bce = { 6A 4A BC 5B }
	$num_bcf = { 3C FA 68 5D }
	$num_bcg = { EC 0E 4E 8E }
	$num_bch = { 7C 0D FC AA }
	$num_bci = { 91 AF CA 54 }
	$num_bcj = { 53 4C 0A B8 }
	$num_bck = { FF 7F 06 1A }
	$num_bcl = { 60 E0 CE EF }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( $num_bce 
	or $num_bcf 
	or $num_bcg 
	or $num_bch 
	or $num_bci 
	or $num_bcj 
	or $num_bck 
	or $num_bcl  ) 
}

private rule capa_hash_data_via_BCrypt { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/.{1,30}/i, /BCryptHash/) 
	or  (  ( 	pe.imports(/.{1,30}/i, /BCryptHashData/)  )  )  )  )  ) 
}

private rule capa_delete_internet_cache { 
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

private rule capa_reference_OpenDNS_DNS_server { 
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
 	$str_bcm = "208.67.222.222" ascii wide
	$str_bcn = "208.67.220.220" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bcm 
	or 	$str_bcn  ) 
}

private rule capa_read_process_memory { 
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

private rule capa_linked_against_XZip { 
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
 	$str_bco = "ct_init: length != 256" ascii wide
	$str_bcp = "ct_init: dist != 256" ascii wide
	$str_bcq = "ct_init: 256+dist != 512" ascii wide
	$str_bcr = "bit length overflow" ascii wide
	$str_bcs = "code %d bits %d->%d" ascii wide
	$str_bct = "inconsistent bit counts" ascii wide
	$str_bcu = "gen_codes: max_code %d " ascii wide
	$str_bcv = "dyn trees: dyn %ld, stat %ld" ascii wide
	$str_bcw = "bad pack level" ascii wide
	$str_bcx = "Code too clever" ascii wide
	$str_bcy = "unknown zip result code" ascii wide
	$str_bcz = "Culdn't duplicate handle" ascii wide
	$str_bda = "File not found in the zipfile" ascii wide
	$str_bdb = "Still more data to unzip" ascii wide
	$str_bdc = "Caller: the file had already been partially unzipped" ascii wide
	$str_bdd = "Caller: can only get memory of a memory zipfile" ascii wide
	$str_bde = "Zip-bug: internal initialisation not completed" ascii wide
	$str_bdf = "Zip-bug: an internal error during flation" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bco 
	or 	$str_bcp 
	or 	$str_bcq 
	or 	$str_bcr 
	or 	$str_bcs 
	or 	$str_bct 
	or 	$str_bcu 
	or 	$str_bcv 
	or 	$str_bcw 
	or 	$str_bcx 
	or 	$str_bcy 
	or 	$str_bcz 
	or 	$str_bda 
	or 	$str_bdb 
	or 	$str_bdc 
	or 	$str_bdd 
	or 	$str_bde 
	or 	$str_bdf  ) 
}

private rule capa_compiled_from_EPL { 
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
 	$str_bdg = "GetNewSock" ascii wide
	$str_bdh = "Software\\FlySky\\E\\Install" ascii wide
	$str_bdi = "Not found the kernel library or the kernel library is invalid!" ascii wide
	$str_bdj = "Failed to allocate memory!" ascii wide
	$str_bdk = "/ MADE BY E COMPILER – WUTAO" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bdg 
	or 	$str_bdh 
	or 	$str_bdi 
	or 	$str_bdj 
	or 	$str_bdk 
	or 	for any bdl in pe.sections : ( bdl.name == ".ecode" ) 
	or 	for any bdm in pe.sections : ( bdm.name == ".edata" ) 
	or 	pe.imports(/krnln/i, /fne/) 
	or 	pe.imports(/krnln/i, /fnr/) 
	or 	pe.imports(/eAPI/i, /fne/) 
	or 	pe.imports(/RegEx/i, /fnr/)  ) 
}

private rule capa_get_session_information { 
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

private rule capa_packed_with_Perplex { 
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
 ( 	for any bdn in pe.sections : ( bdn.name == ".perplex" )  ) 
}

private rule capa_compiled_with_Go { 
  meta: 
 	description = "compiled with Go (converted from capa rule)"
	namespace = "compiler/go"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	hash = "49a34cfbeed733c24392c9217ef46bb6"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/go/compiled-with-go.yml"
	date = "2021-05-15"

  strings: 
 	$str_bdo = "Go build ID:" ascii wide
	$str_bdp = "go.buildid" ascii wide
	$str_bdq = "Go buildinf:" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bdo 
	or 	$str_bdp 
	or 	$str_bdq  ) 
}

private rule capa_compiled_with_ps2exe { 
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
 	$str_bdr = "PS2EXEApp" ascii wide
	$str_bds = "PS2EXE" ascii wide
	$str_bdt = "PS2EXE_Host" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_compiled_to_the__NET_platform

	and 	$str_bdr 
	and 	$str_bds 
	and 	$str_bdt  ) 
}

private rule capa_compiled_with_MinGW_for_Windows { 
  meta: 
 	description = "compiled with MinGW for Windows (converted from capa rule)"
	namespace = "compiler/mingw"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	hash = "5b3968b47eb16a1cb88525e3b565eab1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/mingw/compiled-with-mingw-for-windows.yml"
	date = "2021-05-15"

  strings: 
 	$str_bdu = "Mingw runtime failure:" ascii wide
	$str_bdv = "_Jv_RegisterClasses" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bdu 
	and 	$str_bdv  ) 
}

private rule capa_compiled_from_Visual_Basic { 
  meta: 
 	description = "compiled from Visual Basic (converted from capa rule)"
	namespace = "compiler/vb"
	author = "@williballenthin"
	scope = "file"
	hash = "9bca6b99e7981208af4c7925b96fb9cf"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/vb/compiled-from-visual-basic.yml"
	date = "2021-05-15"

  strings: 
 	$bdw = /VB5!.{,1000}/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bdw 
	and 	pe.imports(/msvbvm60/i, /ThunRTMain/)  ) 
}

private rule capa_compiled_with_pyarmor { 
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
 	$str_bdy = "pyarmor_runtimesh" ascii wide
	$str_bdz = "PYARMOR" ascii wide
	$str_bea = "__pyarmor__" ascii wide
	$str_beb = "PYARMOR_SIGNATURE" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bdy 
	or 	$str_bdz 
	or 	$str_bea 
	or 	$str_beb  ) 
}

private rule capa_compiled_with_exe4j { 
  meta: 
 	description = "compiled with exe4j (converted from capa rule)"
	namespace = "compiler/exe4j"
	author = "johnk3r"
	scope = "file"
	hash = "6b25f1e754ef486bbb28a66d46bababe"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/exe4j/compiled-with-exe4j.yml"
	date = "2021-05-15"

  strings: 
 	$str_bec = "exe4j_log" ascii wide
	$str_bed = "install4j_log" ascii wide
	$str_bee = "exe4j_java_home" ascii wide
	$str_bef = "install4j" ascii wide
	$str_beg = "exe4j.isinstall4j" ascii wide
	$beh = /com\/exe4j\/runtime\/exe4jcontroller/ nocase ascii wide 
	$bei = /com\/exe4j\/runtime\/winlauncher/ nocase ascii wide 
	$str_bej = "EXE4J_LOG" ascii wide
	$str_bek = "INSTALL4J_LOG" ascii wide
	$str_bel = "EXE4J_JAVA_HOME" ascii wide
	$str_bem = "INSTALL4J" ascii wide
	$str_ben = "EXE4J.ISINSTALL4J" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bec 
	or 	$str_bed 
	or 	$str_bee 
	or 	$str_bef 
	or 	$str_beg 
	or 	$beh 
	or 	$bei 
	or 	$str_bej 
	or 	$str_bek 
	or 	$str_bel 
	or 	$str_bem 
	or 	$str_ben  ) 
}

private rule capa_compiled_with_AutoIt { 
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
 	$str_beo = "AutoIt has detected the stack has become corrupt.\n\nStack corruption typically occurs when either the wrong calling convention is used or when the function is called with the wrong number of arguments.\n\nAutoIt supports the __stdcall (WINAPI) and __cdecl calling conventions.  The __stdcall (WINAPI) convention is used by default but __cdecl can be used instead.  See the DllCall() documentation for details on changing the calling convention." ascii wide
	$str_bep = "AutoIt Error" ascii wide
	$beq = />>>AUTOIT SCRIPT<<</ ascii wide 
	$str_ber = ">>>AUTOIT NO CMDEXECUTE<<<" ascii wide
	$str_bes = "#requireadmin" ascii wide
	$str_bet = "#OnAutoItStartRegister" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_beo 
	or 	$str_bep 
	or 	$beq 
	or 	$str_ber 
	or 	$str_bes 
	or 	$str_bet  ) 
}

private rule capa_compiled_with_Borland_Delphi { 
  meta: 
 	description = "compiled with Borland Delphi (converted from capa rule)"
	namespace = "compiler/delphi"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	hash = "4BDD67FF852C221112337FECD0681EAC"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/delphi/compiled-with-borland-delphi.yml"
	date = "2021-05-15"

  strings: 
 	$str_beu = "Borland C++ - Copyright 2002 Borland Corporation" ascii wide
	$bev = /SOFTWARE\\Borland\\Delphi\\RTL/ ascii wide 
	$str_bew = "Sysutils::Exception" ascii wide
	$str_bex = "TForm1" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_beu 
	or 	$bev 
	or 	$str_bew 
	or 	$str_bex 
	or 	pe.imports(/BORLNDMM/i, /DLL/)  ) 
}

private rule capa_compiled_with_dmd { 
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
 ( 	for any bey in pe.sections : ( bey.name == "._deh" ) 
	and 	for any bez in pe.sections : ( bez.name == ".tp" ) 
	and 	for any bfa in pe.sections : ( bfa.name == ".dp" ) 
	and 	for any bfb in pe.sections : ( bfb.name == ".minfo" )  ) 
}

private rule capa_compiled_with_py2exe { 
  meta: 
 	description = "compiled with py2exe (converted from capa rule)"
	namespace = "compiler/py2exe"
	author = "@_re_fox"
	scope = "basic block"
	hash = "ed888dc2f04f5eac83d6d14088d002de"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/py2exe/compiled-with-py2exe.yml"
	date = "2021-05-15"

  strings: 
 	$str_bfc = "PY2EXE_VERBOSE" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bfc 
	and 	pe.imports(/.{1,30}/i, /getenv/)  ) 
}

private rule capa_identify_ATM_dispenser_service_provider { 
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
 	$str_bfd = "CurrencyDispenser1" ascii wide
	$str_bfe = "CDM30" ascii wide
	$str_bff = "DBD_AdvFuncDisp" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bfd 
	or 	$str_bfe 
	or 	$str_bff  ) 
}

private rule capa_load_NCR_ATM_library { 
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
 	$str_bfg = "MSXFS.dll" ascii wide
	$str_bfh = "msxfs.dll" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/msxfs/i, /dll/) 
	or 	$str_bfg 
	or 	$str_bfh  ) 
}

private rule capa_reference_NCR_ATM_library_routines { 
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
 	$str_bfi = "msxfs.dll" ascii wide
	$str_bfj = "WFSCleanUp" ascii wide
	$str_bfk = "WFSClose" ascii wide
	$str_bfl = "WFSExecute" ascii wide
	$str_bfm = "WFSFreeResult" ascii wide
	$str_bfn = "WFSGetInfo" ascii wide
	$str_bfo = "WFSLock" ascii wide
	$str_bfp = "WFSOpen" ascii wide
	$str_bfq = "WFSRegister" ascii wide
	$str_bfr = "WFSStartUp" ascii wide
	$str_bfs = "WFSUnlock" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bfi 
	or 	pe.imports(/msxfs/i, /WFSCleanUp/) 
	or 	$str_bfj 
	or 	pe.imports(/msxfs/i, /WFSClose/) 
	or 	$str_bfk 
	or 	pe.imports(/msxfs/i, /WFSExecute/) 
	or 	$str_bfl 
	or 	pe.imports(/msxfs/i, /WFSFreeResult/) 
	or 	$str_bfm 
	or 	pe.imports(/msxfs/i, /WFSGetInfo/) 
	or 	$str_bfn 
	or 	pe.imports(/msxfs/i, /WFSLock/) 
	or 	$str_bfo 
	or 	pe.imports(/msxfs/i, /WFSOpen/) 
	or 	$str_bfp 
	or 	pe.imports(/msxfs/i, /WFSRegister/) 
	or 	$str_bfq 
	or 	pe.imports(/msxfs/i, /WFSStartUp/) 
	or 	$str_bfr 
	or 	pe.imports(/msxfs/i, /WFSUnlock/) 
	or 	$str_bfs  ) 
}

private rule capa_reference_Diebold_ATM_routines { 
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
 	$str_bft = "DBD_AdvFuncDisp" ascii wide
	$str_bfu = "DBD_EPP4" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bft 
	or 	$str_bfu  ) 
}

private rule capa_load_Diebold_Nixdorf_ATM_library { 
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
 	$str_bfv = "CSCWCNG.dll" ascii wide
	$str_bfw = "CscCngStatusWrite" ascii wide
	$str_bfx = "CscCngCasRefInit" ascii wide
	$str_bfy = "CscCngEncryption" ascii wide
	$str_bfz = "CscCngRecovery" ascii wide
	$str_bga = "CscCngService" ascii wide
	$str_bgb = "CscCngOpen" ascii wide
	$str_bgc = "CscCngReset" ascii wide
	$str_bgd = "CscCngClose" ascii wide
	$str_bge = "CscCngDispense" ascii wide
	$str_bgf = "CscCngTransport" ascii wide
	$str_bgg = "CscCngStatusRead" ascii wide
	$str_bgh = "CscCngInit" ascii wide
	$str_bgi = "CscCngGetRelease" ascii wide
	$str_bgj = "CscCngLock" ascii wide
	$str_bgk = "CscCngUnlock" ascii wide
	$str_bgl = "CscCngShutter" ascii wide
	$str_bgm = "CscCngPowerOff" ascii wide
	$str_bgn = "CscCngSelStatus" ascii wide
	$str_bgo = "CscCngBim" ascii wide
	$str_bgp = "CscCngConfigure" ascii wide
	$str_bgq = "CscCngStatistics" ascii wide
	$str_bgr = "CscCngControl" ascii wide
	$str_bgs = "CscCngPsm" ascii wide
	$str_bgt = "CscCngGetTrace" ascii wide
	$str_bgu = "CscCngOptimization" ascii wide
	$str_bgv = "CscCngSelftest" ascii wide
	$str_bgw = "CscCngEco" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/cscwcng/i, /dll/) 
	or 	$str_bfv 
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
	or 	$str_bfw 
	or 	$str_bfx 
	or 	$str_bfy 
	or 	$str_bfz 
	or 	$str_bga 
	or 	$str_bgb 
	or 	$str_bgc 
	or 	$str_bgd 
	or 	$str_bge 
	or 	$str_bgf 
	or 	$str_bgg 
	or 	$str_bgh 
	or 	$str_bgi 
	or 	$str_bgj 
	or 	$str_bgk 
	or 	$str_bgl 
	or 	$str_bgm 
	or 	$str_bgn 
	or 	$str_bgo 
	or 	$str_bgp 
	or 	$str_bgq 
	or 	$str_bgr 
	or 	$str_bgs 
	or 	$str_bgt 
	or 	$str_bgu 
	or 	$str_bgv 
	or 	$str_bgw  ) 
}

private rule capa_initialize_WinHTTP_library { 
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

private rule capa_set_HTTP_header { 
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

private rule capa_initialize_IWebBrowser2 { 
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
 	$bgx = { 01 DF 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
	$bgy = { 61 16 0C D3 AF CD D0 11 8A 3E 00 C0 4F C9 E2 6E }
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/ole32/i, /CoCreateInstance/) 
	and 	$bgx 
	and 	$bgy  ) 
}

private rule capa_read_HTTP_header { 
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

private rule capa_send_HTTP_response { 
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

private rule capa_start_HTTP_server { 
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

private rule capa_receive_HTTP_response { 
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

private rule capa_create_HTTP_request { 
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

private rule capa_connect_to_URL { 
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

private rule capa_send_file_via_HTTP { 
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

private rule capa_download_URL_to_file { 
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

private rule capa_send_HTTP_request { 
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

private rule capa_prepare_HTTP_request { 
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

private rule capa_read_data_from_Internet { 
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

private rule capa_connect_to_HTTP_server { 
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

private rule capa_send_file_using_FTP_via_wininet { 
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

private rule capa_send_ICMP_echo_request { 
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

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/.{1,30}/i, /IcmpSendEcho/) 
	or 	pe.imports(/.{1,30}/i, /IcmpSendEcho2/) 
	or 	pe.imports(/.{1,30}/i, /IcmpSendEcho2Ex/) 
	or 	pe.imports(/.{1,30}/i, /Icmp6SendEcho2/)  )  )  ) 
}

private rule capa_initialize_Winsock_library { 
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

private rule capa_get_socket_status { 
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

private rule capa_set_socket_configuration { 
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

private rule capa_receive_data_on_socket { 
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

private rule capa_send_data_on_socket { 
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

private rule capa_create_pipe { 
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

private rule capa_write_pipe { 
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

private rule capa_connect_pipe { 
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

private rule capa_read_pipe { 
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

private rule capa_access_PE_header { 
  meta: 
 	description = "access PE header (converted from capa rule)"
	namespace = "load-code/pe"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Execution::Shared Modules [T1129]"
	hash = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/load-code/pe/access-pe-header.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /RtlImageNtHeader/) 
	or 	pe.imports(/ntdll/i, /RtlImageNtHeaderEx/)  ) 
}

private rule capa_acquire_credentials_from_Windows_Credential_Manager { 
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
 	$str_bhb = ".vcrd" ascii wide
	$str_bhc = "*.vcrd" ascii wide
	$str_bhd = "Policy.vpol" ascii wide
	$bhe = /AppData\\Local\\Microsoft\\(Vault|Credentials)/ ascii wide 
	$bhf = /vaultcmd(\.exe)?/ ascii wide 
	$bhg = /\/listcreds:/ ascii wide 
	$bhh = /"Windows Credentials"/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bhb 
	or 	$str_bhc 
	or 	$str_bhd 
	or 	$bhe 
	or 	pe.imports(/.{1,30}/i, /CredEnumerate/) 
	or  (  (  (  ( 	$bhf 
	or 	$bhg 
	or 	$bhh  )  )  )  )  ) 
}

private rule capa_get_geographical_location { 
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
 	$bhi = /geolocation/ nocase ascii wide 
	$bhj = /geo-location/ nocase ascii wide 
	$bhk = /^city/ nocase ascii wide 
	$bhl = /region_code/ nocase ascii wide 
	$bhm = /region_name/ nocase ascii wide 
	$bhn = /^country/ nocase ascii wide 
	$bho = /country_code/ nocase ascii wide 
	$bhp = /countrycode/ nocase ascii wide 
	$bhq = /country_name/ nocase ascii wide 
	$bhr = /continent_code/ nocase ascii wide 
	$bhs = /continent_name/ nocase ascii wide 
	$bht = /^latitude/ nocase ascii wide 
	$bhu = /^longitude/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /GetLocaleInfo/) 
	or 	pe.imports(/.{1,30}/i, /GetLocaleInfoEx/) 
	or 	$bhi 
	or 	$bhj 
	or 	$bhk 
	or 	$bhl 
	or 	$bhm 
	or 	$bhn 
	or 	$bho 
	or 	$bhp 
	or 	$bhq 
	or 	$bhr 
	or 	$bhs 
	or 	$bht 
	or 	$bhu  ) 
}

private rule capa_log_keystrokes_via_polling { 
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

private rule capa_log_keystrokes { 
  meta: 
 	description = "log keystrokes (converted from capa rule)"
	namespace = "collection/keylog"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Collection::Input Capture::Keylogging [T1056.001]"
	hash = "C91887D861D9BD4A5872249B641BC9F9"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/keylog/log-keystrokes.yml"
	date = "2021-05-15"

  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	pe.imports(/.{1,30}/i, /SetWindowsHookEx/) 
	and 	pe.imports(/.{1,30}/i, /GetKeyState/)  )  ) 
	or  (  ( 	pe.imports(/.{1,30}/i, /RegisterHotKey/) 
	and 	pe.imports(/user32/i, /keybd_event/) 
	and 	pe.imports(/.{1,30}/i, /UnregisterHotKey/)  )  ) 
	or  (  ( 	pe.imports(/.{1,30}/i, /CallNextHookEx/) 
	and 	pe.imports(/user32/i, /GetKeyNameText/) 
	and 	pe.imports(/user32/i, /GetAsyncKeyState/) 
	and 	pe.imports(/user32/i, /GetForgroundWindow/)  )  ) 
	or 	pe.imports(/user32/i, /AttachThreadInput/) 
	or 	pe.imports(/user32/i, /MapVirtualKey/)  ) 
}

private rule capa_capture_microphone_audio { 
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
 	$bhw = /^open/ nocase ascii wide 
	$bhx = /waveaudio/ nocase ascii wide 
	$bhy = /^record/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /mciSendString/) 
	and 	$bhw 
	and 	$bhx 
	and 	$bhy  ) 
}

private rule capa_get_domain_trust_relationships { 
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
 	$bhz = /nltest/ nocase ascii wide 
	$bia = /\/domain_trusts/ nocase ascii wide 
	$bib = /\/dclist/ nocase ascii wide 
	$bic = /\/all_trusts/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$bhz 
	and  (  ( 	$bia 
	or 	$bib 
	or 	$bic  )  )  )  ) 
	or 	pe.imports(/.{1,30}/i, /DsEnumerateDomainTrusts/)  ) 
}

private rule capa_capture_network_configuration_via_ipconfig { 
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
 	$bid = /ipconfig(\.exe)?/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bid 
	and 	pe.imports(/msvcr100/i, /system/)  ) 
}

private rule capa_capture_public_ip { 
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
 	$bie = /bot\.whatismyipaddress\.com/ ascii wide 
	$bif = /ipinfo\.io\/ip/ ascii wide 
	$big = /checkip\.dyndns\.org/ ascii wide 
	$bih = /ifconfig\.me/ ascii wide 
	$bii = /ipecho\.net\/plain/ ascii wide 
	$bij = /api\.ipify\.org/ ascii wide 
	$bik = /checkip\.amazonaws\.com/ ascii wide 
	$bil = /icanhazip\.com/ ascii wide 
	$bim = /wtfismyip\.com\/text/ ascii wide 
	$bin = /api\.myip\.com/ ascii wide 
	$bio = /ip\-api\.com\/line/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	pe.imports(/.{1,30}/i, /InternetOpen/) 
	and 	pe.imports(/.{1,30}/i, /InternetOpenUrl/) 
	and 	pe.imports(/.{1,30}/i, /InternetReadFile/) 
	and  (  ( 	$bie 
	or 	$bif 
	or 	$big 
	or 	$bih 
	or 	$bii 
	or 	$bij 
	or 	$bik 
	or 	$bil 
	or 	$bim 
	or 	$bin 
	or 	$bio  )  )  ) 
}

private rule capa_gather_cuteftp_information { 
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
 	$bip = /\\sm\.dat/ ascii wide 
	$biq = /\\GlobalSCAPE\\CuteFTP/ nocase ascii wide 
	$bir = /\\GlobalSCAPE\\CuteFTP Pro/ nocase ascii wide 
	$bis = /\\CuteFTP/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bip 
	and  (  ( 	$biq 
	or 	$bir 
	or 	$bis  )  )  ) 
}

private rule capa_gather_ftprush_information { 
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
 	$bit = /\\FTPRush/ ascii wide 
	$biu = /RushSite\.xml/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bit 
	and 	$biu  ) 
}

private rule capa_gather_smart_ftp_information { 
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
 	$biv = /\\SmartFTP/ ascii wide 
	$str_biw = ".xml" ascii wide
	$bix = /Favorites\.dat/ nocase ascii wide 
	$biy = /History\.dat/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$biv 
	and 	$str_biw 
	and 	$bix 
	and 	$biy  )  )  ) 
}

private rule capa_gather_cyberduck_information { 
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
 	$biz = /\\Cyberduck/ ascii wide 
	$str_bja = "user.config" ascii wide
	$str_bjb = ".duck" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$biz 
	and  (  ( 	$str_bja 
	or 	$str_bjb  )  )  ) 
}

private rule capa_gather_ws_ftp_information { 
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
 	$bjc = /\\Ipswitch\\WS_FTP/ ascii wide 
	$bjd = /\\win\.ini/ ascii wide 
	$bje = /WS_FTP/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bjc 
	and 	$bjd 
	and 	$bje  ) 
}

private rule capa_gather_fling_ftp_information { 
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
 	$bjf = /SOFTWARE\\NCH Software\\Fling\\Accounts/ ascii wide 
	$str_bjg = "FtpPassword" ascii wide
	$str_bjh = "_FtpPassword" ascii wide
	$str_bji = "FtpServer" ascii wide
	$str_bjj = "FtpUserName" ascii wide
	$str_bjk = "FtpDirectory" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bjf 
	or  (  ( 	$str_bjg 
	and 	$str_bjh 
	and 	$str_bji 
	and 	$str_bjj 
	and 	$str_bjk  )  )  ) 
}

private rule capa_gather_directory_opus_information { 
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
 	$bjl = /\\GPSoftware\\Directory Opus/ ascii wide 
	$str_bjm = ".oxc" ascii wide
	$str_bjn = ".oll" ascii wide
	$str_bjo = "ftplast.osd" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bjl 
	and 	$str_bjm 
	and 	$str_bjn 
	and 	$str_bjo  ) 
}

private rule capa_gather_coreftp_information { 
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
 	$bjp = /Software\\FTPWare\\COREFTP\\Sites/ ascii wide 
	$str_bjq = "Host" ascii wide
	$str_bjr = "User" ascii wide
	$str_bjs = "Port" ascii wide
	$str_bjt = "PthR" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bjp 
	or  (  ( 	$str_bjq 
	and 	$str_bjr 
	and 	$str_bjs 
	and 	$str_bjt  )  )  ) 
}

private rule capa_gather_wise_ftp_information { 
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
 	$str_bju = "wiseftpsrvs.ini" ascii wide
	$str_bjv = "wiseftp.ini" ascii wide
	$str_bjw = "wiseftpsrvs.bin" ascii wide
	$str_bjx = "wiseftpsrvs.bin" ascii wide
	$bjy = /\\AceBIT/ ascii wide 
	$bjz = /Software\\AceBIT/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_bju 
	and 	$str_bjv 
	and 	$str_bjw  )  ) 
	or  (  ( 	$str_bjx 
	and  (  ( 	$bjy 
	or 	$bjz  )  )  )  )  ) 
}

private rule capa_gather_winzip_information { 
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
 	$bka = /Software\\Nico Mak Computing\\WinZip\\FTP/ ascii wide 
	$bkb = /Software\\Nico Mak Computing\\WinZip\\mru\\jobs/ ascii wide 
	$str_bkc = "Site" ascii wide
	$str_bkd = "UserID" ascii wide
	$str_bke = "xflags" ascii wide
	$str_bkf = "Port" ascii wide
	$str_bkg = "Folder" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$bka 
	and 	$bkb  )  ) 
	or  (  ( 	$str_bkc 
	and 	$str_bkd 
	and 	$str_bke 
	and 	$str_bkf 
	and 	$str_bkg  )  )  ) 
}

private rule capa_gather_southriver_webdrive_information { 
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
 	$bkh = /Software\\South River Technologies\\WebDrive\\Connections/ ascii wide 
	$str_bki = "PassWord" ascii wide
	$str_bkj = "UserName" ascii wide
	$str_bkk = "RootDirectory" ascii wide
	$str_bkl = "Port" ascii wide
	$str_bkm = "ServerType" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bkh 
	or  (  ( 	$str_bki 
	and 	$str_bkj 
	and 	$str_bkk 
	and 	$str_bkl 
	and 	$str_bkm  )  )  ) 
}

private rule capa_gather_freshftp_information { 
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
 	$str_bkn = "FreshFTP" ascii wide
	$str_bko = ".SMF" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bkn 
	and 	$str_bko  ) 
}

private rule capa_gather_fasttrack_ftp_information { 
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
 	$str_bkp = "FastTrack" ascii wide
	$str_bkq = "ftplist.txt" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_bkp 
	and 	$str_bkq  )  )  ) 
}

private rule capa_gather_classicftp_information { 
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
 	$bkr = /Software\\NCH Software\\ClassicFTP\\FTPAccounts/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bkr  ) 
}

private rule capa_gather_softx_ftp_information { 
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
 	$bks = /Software\\FTPClient\\Sites/ ascii wide 
	$bkt = /Software\\SoftX.org\\FTPClient\\Sites/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bks 
	or 	$bkt  ) 
}

private rule capa_gather_ffftp_information { 
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
 	$bku = /Software\\Sota\\FFFTP\\Options/ ascii wide 
	$bkv = /Software\\Sota\\FFFTP/ ascii wide 
	$bkw = /CredentialSalt/ ascii wide 
	$bkx = /CredentialCheck/ ascii wide 
	$str_bky = "Password" ascii wide
	$str_bkz = "UserName" ascii wide
	$str_bla = "HostAdrs" ascii wide
	$str_blb = "RemoteDir" ascii wide
	$str_blc = "Port" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  (  (  ( 	$bku 
	or 	$bkv  )  ) 
	and  (  ( 	$bkw 
	or 	$bkx  )  )  )  ) 
	or  (  ( 	$str_bky 
	and 	$str_bkz 
	and 	$str_bla 
	and 	$str_blb 
	and 	$str_blc  )  )  ) 
}

private rule capa_gather_ftpshell_information { 
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
 	$str_bld = "FTPShell" ascii wide
	$str_ble = "ftpshell.fsi" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bld 
	and 	$str_ble  ) 
}

private rule capa_gather_winscp_information { 
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
 	$str_blf = "Password" ascii wide
	$str_blg = "HostName" ascii wide
	$str_blh = "UserName" ascii wide
	$str_bli = "RemoteDirectory" ascii wide
	$str_blj = "PortNumber" ascii wide
	$str_blk = "FSProtocol" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_blf 
	and 	$str_blg 
	and 	$str_blh 
	and 	$str_bli 
	and 	$str_blj 
	and 	$str_blk  ) 
}

private rule capa_gather_frigate3_information { 
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
 	$bll = /FtpSite\.xml/ ascii wide 
	$blm = /\\Frigate3/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bll 
	and 	$blm  ) 
}

private rule capa_gather_staff_ftp_information { 
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
 	$str_bln = "Staff-FTP" ascii wide
	$str_blo = "sites.ini" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bln 
	and 	$str_blo  ) 
}

private rule capa_gather_xftp_information { 
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
 	$str_blp = ".xfp" ascii wide
	$blq = /\\NetSarang/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_blp 
	and 	$blq  ) 
}

private rule capa_gather_leapftp_information { 
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
 	$str_blr = "InstallPath" ascii wide
	$str_bls = "DataDir" ascii wide
	$str_blt = "sites.dat" ascii wide
	$str_blu = "sites.ini" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_blr 
	and 	$str_bls 
	and 	$str_blt 
	and 	$str_blu  )  ) 
  ) 
}

private rule capa_gather_ftpnow_information { 
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
 	$str_blx = "FTPNow" ascii wide
	$str_bly = "FTP Now" ascii wide
	$str_blz = "sites.xml" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_blx 
	and 	$str_bly 
	and 	$str_blz  ) 
}

private rule capa_gather_ftpgetter_information { 
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
 	$str_bma = "servers.xml" ascii wide
	$bmb = /\\FTPGetter/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bma 
	and 	$bmb  ) 
}

private rule capa_gather_nova_ftp_information { 
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
 	$str_bmc = "NovaFTP.db" ascii wide
	$bmd = /\\INSoftware\\NovaFTP/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_bmc 
	and 	$bmd  )  )  ) 
}

private rule capa_gather_ftp_explorer_information { 
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
 	$bme = /profiles\.xml/ ascii wide 
	$bmf = /Software\\FTP Explorer\\FTP Explorer\\Workspace\\MFCToolBar-224/ ascii wide 
	$bmg = /Software\\FTP Explorer\\Profiles/ ascii wide 
	$bmh = /\\FTP Explorer/ ascii wide 
	$str_bmi = "Password" ascii wide
	$str_bmj = "Host" ascii wide
	$str_bmk = "Login" ascii wide
	$str_bml = "InitialPath" ascii wide
	$str_bmm = "PasswordType" ascii wide
	$str_bmn = "Port" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$bme 
	and  (  ( 	$bmf 
	or 	$bmg 
	or 	$bmh  )  )  )  ) 
	or  (  ( 	$str_bmi 
	and 	$str_bmj 
	and 	$str_bmk 
	and 	$str_bml 
	and 	$str_bmm 
	and 	$str_bmn  )  )  ) 
}

private rule capa_gather_bitkinex_information { 
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
 	$bmo = /bitkinex\.ds/ ascii wide 
	$bmp = /\\BitKinex/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bmo 
	and 	$bmp  ) 
}

private rule capa_gather_turbo_ftp_information { 
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
 	$str_bmq = "addrbk.dat" ascii wide
	$str_bmr = "quick.dat" ascii wide
	$bms = /installpath/ ascii wide 
	$bmt = /Software\\TurboFTP/ ascii wide 
	$bmu = /\\TurboFTP/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_bmq 
	and 	$str_bmr  )  ) 
	or  (  ( 	$bms 
	and  (  ( 	$bmt 
	or 	$bmu  )  )  )  )  ) 
}

private rule capa_gather_nexusfile_information { 
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
 	$str_bmv = "NexusFile" ascii wide
	$str_bmw = "ftpsite.ini" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bmv 
	and 	$str_bmw  ) 
}

private rule capa_gather_ftp_voyager_information { 
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
 	$bmx = /\\RhinoSoft.com/ ascii wide 
	$str_bmy = "FTPVoyager.ftp" ascii wide
	$str_bmz = "FTPVoyager.qc" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bmx 
	and 	$str_bmy 
	and 	$str_bmz  ) 
}

private rule capa_gather_blazeftp_information { 
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
 	$str_bna = "BlazeFtp" ascii wide
	$str_bnb = "site.dat" ascii wide
	$str_bnc = "LastPassword" ascii wide
	$str_bnd = "LastAddress" ascii wide
	$str_bne = "LastUser" ascii wide
	$str_bnf = "LastPort" ascii wide
	$bng = /Software\\FlashPeak\\BlazeFtp\\Settings/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bna 
	and 	$str_bnb 
	and  (  ( 	$str_bnc 
	or 	$str_bnd 
	or 	$str_bne 
	or 	$str_bnf 
	or 	$bng  )  )  ) 
}

private rule capa_gather_ftp_commander_information { 
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
 	$bnh = /FTP Navigator/ ascii wide 
	$bni = /FTP Commander/ ascii wide 
	$str_bnj = "ftplist.txt" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$bnh 
	or 	$bni  )  ) 
	and  (  ( 	$str_bnj  )  )  ) 
}

private rule capa_gather_global_downloader_information { 
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
 	$bnq = /\\Global Downloader/ ascii wide 
	$str_bnr = "SM.arch" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bnq 
	and 	$str_bnr  ) 
}

private rule capa_gather_faststone_browser_information { 
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
 	$bnz = /FastStone Browser/ ascii wide 
	$str_boa = "FTPList.db" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bnz 
	and 	$str_boa  ) 
}

private rule capa_gather_ultrafxp_information { 
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
 	$bob = /UltraFXP/ ascii wide 
	$boc = /\\sites\.xml/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bob 
	and 	$boc  ) 
}

private rule capa_gather_netdrive_information { 
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
 	$str_bod = "NDSites.ini" ascii wide
	$boe = /\\NetDrive/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bod 
	and 	$boe  ) 
}

private rule capa_gather_total_commander_information { 
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
 	$bof = /Software\\Ghisler\\Total Commander/ ascii wide 
	$bog = /Software\\Ghisler\\Windows Commander/ ascii wide 
	$str_boh = "FtpIniName" ascii wide
	$str_boi = "wcx_ftp.ini" ascii wide
	$boj = /\\GHISLER/ ascii wide 
	$str_bok = "InstallDir" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$bof 
	or 	$bog  )  ) 
	and  (  ( 	$str_boh 
	or 	$str_boi 
	or 	$boj 
	or 	$str_bok  )  )  ) 
}

private rule capa_gather_ftpinfo_information { 
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
 	$str_bol = "ServerList.xml" ascii wide
	$str_bom = "DataDir" ascii wide
	$bon = /Software\\MAS-Soft\\FTPInfo\\Setup/ ascii wide 
	$boo = /FTPInfo/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bol 
	and 	$str_bom 
	and  (  ( 	$bon 
	or 	$boo  )  )  ) 
}

private rule capa_gather_flashfxp_information { 
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
 	$bop = /Software\\FlashFXP/ ascii wide 
	$boq = /DataFolder/ ascii wide 
	$bor = /Install Path/ ascii wide 
	$bos = /\\Sites.dat/ ascii wide 
	$bot = /\\Quick.dat/ ascii wide 
	$bou = /\\History.dat/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$bop 
	and 	$boq 
	and 	$bor  )  ) 
	or  (  ( 	$bos 
	and 	$bot 
	and 	$bou  )  )  ) 
}

private rule capa_gather_securefx_information { 
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
 	$bov = /\\Sessions/ ascii wide 
	$str_bow = ".ini" ascii wide
	$box = /Config Path/ ascii wide 
	$boy = /_VanDyke\\Config\\Sessions/ ascii wide 
	$boz = /Software\\VanDyke\\SecureFX/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bov 
	and 	$str_bow 
	and 	$box 
	and  (  ( 	$boy 
	or 	$boz  )  )  ) 
}

private rule capa_gather_robo_ftp_information { 
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
 	$bpa = /SOFTWARE\\Robo-FTP/ ascii wide 
	$bpb = /\\FTPServers/ ascii wide 
	$bpc = /FTP File/ ascii wide 
	$str_bpd = "FTP Count" ascii wide
	$str_bpe = "Password" ascii wide
	$str_bpf = "ServerName" ascii wide
	$str_bpg = "UserID" ascii wide
	$str_bph = "PortNumber" ascii wide
	$str_bpi = "InitialDirectory" ascii wide
	$str_bpj = "ServerType" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$bpa 
	and  (  ( 	$bpb 
	or 	$bpc 
	or 	$str_bpd  )  )  )  ) 
	or  (  ( 	$str_bpe 
	and 	$str_bpf 
	and 	$str_bpg 
	and 	$str_bph 
	and 	$str_bpi 
	and 	$str_bpj  )  )  ) 
}

private rule capa_gather_bulletproof_ftp_information { 
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
 	$str_bpk = ".dat" ascii wide
	$str_bpl = ".bps" ascii wide
	$bpm = /Software\\BPFTP\\Bullet Proof FTP\\Main/ ascii wide 
	$bpn = /Software\\BulletProof Software\\BulletProof FTP Client\\Main/ ascii wide 
	$bpo = /Software\\BulletProof Software\\BulletProof FTP Client\\Options/ ascii wide 
	$bpp = /Software\\BPFTP\\Bullet Proof FTP\\Options/ ascii wide 
	$bpq = /Software\\BPFTP/ ascii wide 
	$str_bpr = "LastSessionFile" ascii wide
	$str_bps = "SitesDir" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$str_bpk 
	and 	$str_bpl  )  ) 
	or  (  (  (  ( 	$bpm 
	or 	$bpn 
	or 	$bpo 
	or 	$bpp 
	or 	$bpq  )  ) 
	and  (  ( 	$str_bpr 
	or 	$str_bps  )  )  )  )  ) 
}

private rule capa_gather_alftp_information { 
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
 	$str_bpt = "ESTdb2.dat" ascii wide
	$str_bpu = "QData.dat" ascii wide
	$bpv = /\\Estsoft\\ALFTP/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bpt 
	and 	$str_bpu 
	and 	$bpv  ) 
}

private rule capa_gather_expandrive_information { 
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
 	$bpw = /Software\\ExpanDrive\\Sessions/ ascii wide 
	$bpx = /Software\\ExpanDrive/ ascii wide 
	$bpy = /ExpanDrive_Home/ ascii wide 
	$bpz = /\\drives\.js/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 (  (  ( 	$bpw 
	or 	$bpx  )  ) 
	and  (  ( 	$bpy 
	or 	$bpz  )  )  ) 
}

private rule capa_gather_goftp_information { 
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
 	$str_bqa = "GoFTP" ascii wide
	$str_bqb = "Connections.txt" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bqa 
	and 	$str_bqb  ) 
}

private rule capa_gather_3d_ftp_information { 
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
 	$str_bqc = "3D-FTP" ascii wide
	$str_bqd = "sites.ini" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bqc 
	and 	$str_bqd  ) 
}

private rule capa_reference_SQL_statements { 
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
 	$bqj = /SELECT.{,1000}FROM.{,1000}WHERE/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bqj  ) 
}

private rule capa_reference_WMI_statements { 
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
 	$bqk = /SELECT\s+\*\s+FROM\s+CIM_./ ascii wide 
	$bql = /SELECT\s+\*\s+FROM\s+Win32_./ ascii wide 
	$bqm = /SELECT\s+\*\s+FROM\s+MSAcpi_./ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$bqk 
	or 	$bql 
	or 	$bqm  ) 
}

private rule capa_create_reverse_shell { 
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

private rule capa_write_and_execute_a_file { 
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

private rule capa_self_delete_via_COMSPEC_environment_variable { 
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
 	$bqo = /\/c\s*del\s*/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_get_COMSPEC_environment_variable

	and 	capa_create_process

	and 	$bqo  ) 
}

private rule capa_check_for_windows_sandbox_via_process_name { 
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
 	$str_bqq = "CExecSvc.exe" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_enumerate_processes

	and 	$str_bqq  ) 
}

private rule capa_get_CPU_information { 
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
 	$bqt = /Hardware\\Description\\System\\CentralProcessor/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_query_or_enumerate_registry_value

	and 	$bqt  ) 
}

private rule capa_disable_code_signing { 
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
 	$bqu = /^bcdedit(\.exe)? -set TESTSIGNING ON/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_create_process

	and 	$bqu  ) 
}

private rule capa_find_taskbar { 
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
 	$str_bqv = "Shell_TrayWnd" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	$str_bqv 
	and 	capa_find_graphical_window
 ) 
}

private rule capa_check_mutex { 
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

private rule capa_linked_against_Go_process_enumeration_library { 
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
 	$str_bry = "github.com/mitchellh/go-ps.FindProcess" ascii wide
	$str_brz = "github.com/mitchellh/go-ps.Processes" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_compiled_with_Go

	and  (  (  (  ( 	$str_bry 
	or 	$str_brz  )  )  )  )  ) 
}

private rule capa_linked_against_Go_WMI_library { 
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
 	$str_bsf = "github.com/StackExchange/wmi.CreateQuery" ascii wide
	$str_bsg = "github.com/StackExchange/wmi.Query" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_compiled_with_Go

	and  (  (  (  ( 	$str_bsf 
	or 	$str_bsg  )  )  )  )  ) 
}

private rule capa_send_HTTP_request_with_Host_header { 
  meta: 
 	description = "send HTTP request with Host header (converted from capa rule)"
	namespace = "communication/http"
	author = "anamaria.martinezgom@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/send-http-request-with-host-header.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$bsh = /Host:/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_send_HTTP_request

	and 	$bsh  ) 
}

private rule capa_check_for_windows_sandbox_via_mutex { 
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
 	$str_bsi = "WindowsSandboxMutex" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_check_mutex

	and 	$str_bsi  ) 
}

private rule capa_linked_against_Go_registry_library { 
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
 	$str_bsj = "golang.org/x/sys/windows/registry.Key.Close" ascii wide
	$str_bsk = "github.com/golang/sys/windows/registry.Key.Close" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_compiled_with_Go

	and  (  ( 	$str_bsj 
	or 	$str_bsk  )  )  ) 
}

private rule capa_capture_screenshot_in_Go { 
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
 	$str_bsp = "syscall.NewLazyDLL" ascii wide
	$bsq = /user32.dll/ ascii wide 
	$bsr = /GetWindowDC/ ascii wide 
	$bss = /GetDC/ ascii wide 
	$bst = /gdi32.dll/ ascii wide 
	$bsu = /BitBlt/ ascii wide 
	$bsv = /GetDIBits/ ascii wide 
	$bsw = /CreateCompatibleDC/ ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_compiled_with_Go

	and  (  (  (  ( 	$str_bsp 
	and  (  (  (  ( 	$bsq 
	and  (  ( 	$bsr 
	or 	$bss  )  )  )  ) 
	or  (  ( 	$bst 
	and  (  ( 	$bsu 
	or 	$bsv  )  )  )  )  )  ) 
	and 	$bsw  )  )  )  )  ) 
}

private rule capa_linked_against_Go_static_asset_library { 
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
 	$str_bsx = "github.com/rakyll/statik/fs.IsDefaultNamespace" ascii wide
	$str_bsy = "github.com/rakyll/statik/fs.RegisterWithNamespace" ascii wide
	$str_bsz = "github.com/rakyll/statik/fs.NewWithNamespace" ascii wide
	$str_bta = "github.com/rakyll/statik/fs.Register" ascii wide
	$str_btb = "github.com/gobuffalo/packr.NewBox" ascii wide
	$str_btc = "github.com/markbates/pkger.Open" ascii wide
	$str_btd = "github.com/markbates/pkger.Include" ascii wide
	$str_bte = "github.com/markbates/pkger.Parse" ascii wide
	$str_btf = "github.com/GeertJohan/go.rice.FindBox" ascii wide
	$str_btg = "github.com/GeertJohan/go.rice.MustFindBox" ascii wide
	$bth = /\/bindata\.go/ ascii wide 
	$bti = /\.Asset/ ascii wide 
	$str_btj = "github.com/lu4p/binclude.Include" ascii wide
	$str_btk = "github.com/omeid/go-resources" ascii wide
	$str_btl = "github.com/pyros2097/go-embed" ascii wide
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_compiled_with_Go

	and  (  (  (  ( 	$str_bsx 
	or 	$str_bsy 
	or 	$str_bsz 
	or 	$str_bta  )  ) 
	or  (  ( 	$str_btb  )  ) 
	or  (  ( 	$str_btc 
	or 	$str_btd 
	or 	$str_bte  )  ) 
	or  (  ( 	$str_btf 
	or 	$str_btg  )  ) 
	or  (  ( 	$bth 
	and 	$bti  )  ) 
	or  (  ( 	$str_btj  )  ) 
	or  (  ( 	$str_btk  )  ) 
	or  (  ( 	$str_btl  )  )  )  )  ) 
}

private rule capa_make_an_HTTP_request_with_a_Cookie { 
  meta: 
 	description = "make an HTTP request with a Cookie (converted from capa rule)"
	namespace = "communication/http/client"
	author = "anamaria.martinezgom@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/make-an-http-request-with-a-cookie.yml"
	capa_nursery = "True"
	date = "2021-05-15"

  strings: 
 	$btm = /Cookie:/ nocase ascii wide 
 
  condition: 
	(
		uint16be(0) == 0x4d5a or
		uint16be(0) == 0x558b or
		uint16be(0) == 0x5649
	) and
 ( 	capa_send_HTTP_request

	and 	$btm  ) 
}

private rule capa_receive_data { 
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

private rule capa_send_data { 
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

private rule capa_download_and_write_a_file { 
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

private rule capa_read_and_send_data_from_client_to_server { 
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

private rule capa_receive_and_write_data_from_server_to_client { 
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

