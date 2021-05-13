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
	date = "2021-05-13"

 strings: 
 	$aap = /vssadmin.* delete shadows/ nocase ascii wide 
	$aar = /vssadmin.* resize shadowstorage/ nocase ascii wide 
	$aat = /wmic.* shadowcopy delete/ nocase ascii wide 
 
 condition: 
  ( 	$aap or	$aar or	$aat  ) 
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
	date = "2021-05-13"

 strings: 
 	$aav = /ollydbg.exe/ nocase ascii wide 
	$aax = /ProcessHacker.exe/ nocase ascii wide 
	$aaz = /tcpview.exe/ nocase ascii wide 
	$abb = /autoruns.exe/ nocase ascii wide 
	$abd = /autorunsc.exe/ nocase ascii wide 
	$abf = /filemon.exe/ nocase ascii wide 
	$abh = /procmon.exe/ nocase ascii wide 
	$abj = /regmon.exe/ nocase ascii wide 
	$abl = /procexp.exe/ nocase ascii wide 
	$abn = /idaq.exe/ nocase ascii wide 
	$abp = /idaq64.exe/ nocase ascii wide 
	$abr = /ImmunityDebugger.exe/ nocase ascii wide 
	$abt = /Wireshark.exe/ nocase ascii wide 
	$abv = /dumpcap.exe/ nocase ascii wide 
	$abx = /HookExplorer.exe/ nocase ascii wide 
	$abz = /ImportREC.exe/ nocase ascii wide 
	$acb = /PETools.exe/ nocase ascii wide 
	$acd = /LordPE.exe/ nocase ascii wide 
	$acf = /SysInspector.exe/ nocase ascii wide 
	$ach = /proc_analyzer.exe/ nocase ascii wide 
	$acj = /sysAnalyzer.exe/ nocase ascii wide 
	$acl = /sniff_hit.exe/ nocase ascii wide 
	$acn = /windbg.exe/ nocase ascii wide 
	$acp = /joeboxcontrol.exe/ nocase ascii wide 
	$acr = /joeboxserver.exe/ nocase ascii wide 
	$act = /ResourceHacker.exe/ nocase ascii wide 
	$acv = /x32dbg.exe/ nocase ascii wide 
	$acx = /x64dbg.exe/ nocase ascii wide 
	$acz = /Fiddler.exe/ nocase ascii wide 
	$adb = /httpdebugger.exe/ nocase ascii wide 
	$add = /fakenet.exe/ nocase ascii wide 
	$adf = /netmon.exe/ nocase ascii wide 
	$adh = /WPE PRO.exe/ nocase ascii wide 
	$adj = /decompile.exe/ nocase ascii wide 
 
 condition: 
  ( 	$aav or	$aax or	$aaz or	$abb or	$abd or	$abf or	$abh or	$abj or	$abl or	$abn or	$abp or	$abr or	$abt or	$abv or	$abx or	$abz or	$acb or	$acd or	$acf or	$ach or	$acj or	$acl or	$acn or	$acp or	$acr or	$act or	$acv or	$acx or	$acz or	$adb or	$add or	$adf or	$adh or	$adj  ) 
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
	date = "2021-05-13"

 strings: 
 	$aeb = "ConfusedByAttribute" ascii wide
 
 condition: 
  ( 	$aeb  ) 
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
	date = "2021-05-13"

 strings: 
 	$aed = "Amber - Reflective PE Packer" ascii wide
 
 condition: 
  ( 	$aed  ) 
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
	date = "2021-05-13"

 strings: 
 	$aer = /VMWare/ nocase ascii wide 
	$aet = /VMTools/ nocase ascii wide 
	$aev = /SOFTWARE\\VMware, Inc\.\\VMware Tools/ nocase ascii wide 
	$aex = /vmnet.sys/ nocase ascii wide 
	$aez = /vmmouse.sys/ nocase ascii wide 
	$afb = /vmusb.sys/ nocase ascii wide 
	$afd = /vm3dmp.sys/ nocase ascii wide 
	$aff = /vmci.sys/ nocase ascii wide 
	$afh = /vmhgfs.sys/ nocase ascii wide 
	$afj = /vmmemctl.sys/ nocase ascii wide 
	$afl = /vmx86.sys/ nocase ascii wide 
	$afn = /vmrawdsk.sys/ nocase ascii wide 
	$afp = /vmusbmouse.sys/ nocase ascii wide 
	$afr = /vmkdb.sys/ nocase ascii wide 
	$aft = /vmnetuserif.sys/ nocase ascii wide 
	$afv = /vmnetadapter.sys/ nocase ascii wide 
	$afx = /\\\\.\\HGFS/ nocase ascii wide 
	$afz = /\\\\.\\vmci/ nocase ascii wide 
	$agb = /vmtoolsd.exe/ nocase ascii wide 
	$agd = /vmwaretray.exe/ nocase ascii wide 
	$agf = /vmwareuser.exe/ nocase ascii wide 
	$agh = /VGAuthService.exe/ nocase ascii wide 
	$agj = /vmacthlp.exe/ nocase ascii wide 
	$agl = /vmci/ nocase ascii wide 
	$agn = /vmhgfs/ nocase ascii wide 
	$agp = /vmmouse/ nocase ascii wide 
	$agr = /vmmemctl/ nocase ascii wide 
	$agt = /vmusb/ nocase ascii wide 
	$agv = /vmusbmouse/ nocase ascii wide 
	$agx = /vmx_svga/ nocase ascii wide 
	$agz = /vmxnet/ nocase ascii wide 
	$ahb = /vmx86/ nocase ascii wide 
	$ahd = /VMwareVMware/ nocase ascii wide 
	$ahf = /vmGuestLib.dll/ nocase ascii wide 
 
 condition: 
  ( 	$aer or	$aet or	$aev or	$aex or	$aez or	$afb or	$afd or	$aff or	$afh or	$afj or	$afl or	$afn or	$afp or	$afr or	$aft or	$afv or	$afx or	$afz or	$agb or	$agd or	$agf or	$agh or	$agj or	$agl or	$agn or	$agp or	$agr or	$agt or	$agv or	$agx or	$agz or	$ahb or	$ahd or	$ahf  ) 
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
	date = "2021-05-13"

 strings: 
 	$ahn = /Parallels/ nocase ascii wide 
	$ahp = /prl_cc.exe/ nocase ascii wide 
	$ahr = /prl_tools.exe/ nocase ascii wide 
	$aht = /prl hyperv/ nocase ascii wide 
 
 condition: 
  ( 	$ahn or	$ahp or	$ahr or	$aht  ) 
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
	date = "2021-05-13"

 strings: 
 	$ahv = /VBOX/ nocase ascii wide 
	$ahx = /VEN_VBOX/ nocase ascii wide 
	$ahz = /VirtualBox/ nocase ascii wide 
	$aib = /06\/23\/99/ nocase ascii wide 
	$aid = /HARDWARE\\ACPI\\DSDT\\VBOX__/ nocase ascii wide 
	$aif = /HARDWARE\\ACPI\\FADT\\VBOX__/ nocase ascii wide 
	$aih = /HARDWARE\\ACPI\\RSDT\\VBOX__/ nocase ascii wide 
	$aij = /SOFTWARE\\Oracle\\VirtualBox Guest Additions/ nocase ascii wide 
	$ail = /SYSTEM\\ControlSet001\\Services\\VBoxGuest/ nocase ascii wide 
	$ain = /SYSTEM\\ControlSet001\\Services\\VBoxMouse/ nocase ascii wide 
	$aip = /SYSTEM\\ControlSet001\\Services\\VBoxService/ nocase ascii wide 
	$air = /SYSTEM\\ControlSet001\\Services\\VBoxSF/ nocase ascii wide 
	$ait = /SYSTEM\\ControlSet001\\Services\\VBoxVideo/ nocase ascii wide 
	$aiv = /VBoxMouse.sys/ nocase ascii wide 
	$aix = /VBoxGuest.sys/ nocase ascii wide 
	$aiz = /VBoxSF.sys/ nocase ascii wide 
	$ajb = /VBoxVideo.sys/ nocase ascii wide 
	$ajd = /vboxdisp.dll/ nocase ascii wide 
	$ajf = /vboxhook.dll/ nocase ascii wide 
	$ajh = /vboxmrxnp.dll/ nocase ascii wide 
	$ajj = /vboxogl.dll/ nocase ascii wide 
	$ajl = /vboxoglarrayspu.dll/ nocase ascii wide 
	$ajn = /vboxoglcrutil.dll/ nocase ascii wide 
	$ajp = /vboxoglerrorspu.dll/ nocase ascii wide 
	$ajr = /vboxoglfeedbackspu.dll/ nocase ascii wide 
	$ajt = /vboxoglpackspu.dll/ nocase ascii wide 
	$ajv = /vboxoglpassthroughspu.dll/ nocase ascii wide 
	$ajx = /vboxservice.exe/ nocase ascii wide 
	$ajz = /vboxtray.exe/ nocase ascii wide 
	$akb = /VBoxControl.exe/ nocase ascii wide 
	$akd = /oracle\\virtualbox guest additions\\/ nocase ascii wide 
	$akf = /\\\\.\\VBoxMiniRdrDN/ nocase ascii wide 
	$akh = /\\\\.\\VBoxGuest/ nocase ascii wide 
	$akj = /\\\\.\\pipe\\VBoxMiniRdDN/ nocase ascii wide 
	$akl = /\\\\.\\VBoxTrayIPC/ nocase ascii wide 
	$akn = /\\\\.\\pipe\\VBoxTrayIPC/ nocase ascii wide 
	$akp = /VBoxTrayToolWndClass/ nocase ascii wide 
	$akr = /VBoxTrayToolWnd/ nocase ascii wide 
	$akt = /vboxservice.exe/ nocase ascii wide 
	$akv = /vboxtray.exe/ nocase ascii wide 
	$akx = /vboxvideo/ nocase ascii wide 
	$akz = /VBoxVideoW8/ nocase ascii wide 
	$alb = /VBoxWddm/ nocase ascii wide 
	$ald = /PCI\\VEN_80EE&DEV_CAFE/ nocase ascii wide 
	$alf = /82801FB/ nocase ascii wide 
	$alh = /82441FX/ nocase ascii wide 
	$alj = /82371SB/ nocase ascii wide 
	$all = /OpenHCD/ nocase ascii wide 
	$aln = /ACPIBus_BUS_0/ nocase ascii wide 
	$alp = /PCI_BUS_0/ nocase ascii wide 
	$alr = /PNP_BUS_0/ nocase ascii wide 
	$alt = /Oracle Corporation/ nocase ascii wide 
	$alv = /VBoxWdd/ nocase ascii wide 
	$alx = /VBoxS/ nocase ascii wide 
	$alz = /VBoxMouse/ nocase ascii wide 
	$amb = /VBoxGuest/ nocase ascii wide 
	$amd = /VBoxVBoxVBox/ nocase ascii wide 
	$amf = /innotek GmbH/ nocase ascii wide 
	$amh = /drivers\\vboxdrv/ nocase ascii wide 
 
 condition: 
  ( 	$ahv or	$ahx or	$ahz or	$aib or	$aid or	$aif or	$aih or	$aij or	$ail or	$ain or	$aip or	$air or	$ait or	$aiv or	$aix or	$aiz or	$ajb or	$ajd or	$ajf or	$ajh or	$ajj or	$ajl or	$ajn or	$ajp or	$ajr or	$ajt or	$ajv or	$ajx or	$ajz or	$akb or	$akd or	$akf or	$akh or	$akj or	$akl or	$akn or	$akp or	$akr or	$akt or	$akv or	$akx or	$akz or	$alb or	$ald or	$alf or	$alh or	$alj or	$all or	$aln or	$alp or	$alr or	$alt or	$alv or	$alx or	$alz or	$amb or	$amd or	$amf or	$amh  ) 
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
	date = "2021-05-13"

 strings: 
 	$amk = /^Xen/ nocase ascii wide 
	$amm = /XenVMMXenVMM/ nocase ascii wide 
	$amo = /xenservice.exe/ nocase ascii wide 
	$amq = /XenVMMXenVMM/ nocase ascii wide 
	$ams = /HVM domU/ nocase ascii wide 
 
 condition: 
  ( 	$amk or	$amm or	$amo or	$amq or	$ams  ) 
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
	date = "2021-05-13"

 strings: 
 	$amu = /HARDWARE\\ACPI\\(DSDT|FADT|RSDT)\\BOCHS/ nocase ascii wide 
	$amw = /HARDWARE\\DESCRIPTION\\System\\(SystemBiosVersion|VideoBiosVersion)/ nocase ascii wide 
	$amy = /HARDWARE\\DESCRIPTION\\System\\CentralProcessor/ nocase ascii wide 
	$ana = /HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0/ nocase ascii wide 
	$anc = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Enum\\IDE/ nocase ascii wide 
	$ane = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Services\\Disk\\Enum\\/ nocase ascii wide 
	$ang = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Control\\SystemInformation\\SystemManufacturer/ nocase ascii wide 
	$ani = /A M I/ nocase ascii wide 
	$ank = /Hyper-V/ nocase ascii wide 
	$anm = /Kernel-VMDetection-Private/ nocase ascii wide 
	$ano = /KVMKVMKVM/ nocase ascii wide 
	$anq = /Microsoft Hv/ nocase ascii wide 
	$ans = /avghookx.dll/ nocase ascii wide 
	$anu = /avghooka.dll/ nocase ascii wide 
	$anw = /snxhk.dll/ nocase ascii wide 
	$any = /pstorec.dll/ nocase ascii wide 
	$aoa = /vmcheck.dll/ nocase ascii wide 
	$aoc = /wpespy.dll/ nocase ascii wide 
	$aoe = /cmdvrt64.dll/ nocase ascii wide 
	$aog = /cmdvrt32.dll/ nocase ascii wide 
	$aoi = /sample.exe/ nocase ascii wide 
	$aok = /bot.exe/ nocase ascii wide 
	$aom = /sandbox.exe/ nocase ascii wide 
	$aoo = /malware.exe/ nocase ascii wide 
	$aoq = /test.exe/ nocase ascii wide 
	$aos = /klavme.exe/ nocase ascii wide 
	$aou = /myapp.exe/ nocase ascii wide 
	$aow = /testapp.exe/ nocase ascii wide 
 
 condition: 
  ( 	$amu or	$amw or	$amy or	$ana or	$anc or	$ane or	$ang or	$ani or	$ank or	$anm or	$ano or	$anq or	$ans or	$anu or	$anw or	$any or	$aoa or	$aoc or	$aoe or	$aog or	$aoi or	$aok or	$aom or	$aoo or	$aoq or	$aos or	$aou or	$aow  ) 
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
	date = "2021-05-13"

 strings: 
 	$aoz = /Qemu/ nocase ascii wide 
	$apb = /qemu-ga.exe/ nocase ascii wide 
	$apd = /BOCHS/ nocase ascii wide 
	$apf = /BXPC/ nocase ascii wide 
 
 condition: 
  ( 	$aoz or	$apb or	$apd or	$apf  ) 
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
	date = "2021-05-13"

 strings: 
 	$aph = /VirtualPC/ nocase ascii wide 
	$apj = /VMSrvc.exe/ nocase ascii wide 
	$apl = /VMUSrvc.exe/ nocase ascii wide 
	$apn = /SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters/ nocase ascii wide 
 
 condition: 
  ( 	$aph or	$apj or	$apl or	$apn  ) 
}
rule capa_contains_PDB_path { 
 meta: 
 	description = "contains PDB path (converted from capa rule)"
	namespace = "executable/pe/pdb"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	hash = "464EF2CA59782CE697BC329713698CCC"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/executable/pe/pdb/contains-pdb-path.yml"
	date = "2021-05-13"

 strings: 
 	$aqd = /:\\.*\.pdb/ ascii wide 
 
 condition: 
 	$aqd 
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
	date = "2021-05-13"

 strings: 
 	$aqg = "wextract_cleanup%d" ascii wide
	$aqi = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
	$aqk = "  <description>IExpress extraction tool</description>" ascii wide
 
 condition: 
  (  (  ( 	$aqg and	$aqi  )  ) or	$aqk  ) 
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
	date = "2021-05-13"

 strings: 
 	$ars = /SELECT\s+\*\s+FROM\s+Win32_Processor/ ascii wide 
	$aru = "NumberOfCores" ascii wide
 
 condition: 
  ( 	$ars and	$aru  ) 
}
rule capa_references_logon_banner { 
 meta: 
 	description = "references logon banner (converted from capa rule)"
	namespace = "host-interaction/gui/logon"
	author = "@_re_fox"
	scope = "basic block"
	hash = "c3341b7dfbb9d43bca8c812e07b4299f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/logon/references-logon-banner.yml"
	date = "2021-05-13"

 strings: 
 	$asw = /\\Microsoft\\Windows\\CurrentVersion\\Policies\\System/ ascii wide 
	$asz = /LegalNoticeCaption/ ascii wide 
	$atb = /LegalNoticeText/ ascii wide 
 
 condition: 
  ( 	$asw and (  ( 	$asz or	$atb  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$ati = /CreateFileTransacted./ ascii wide 
	$atl = "ZwCreateSection" ascii wide
	$atn = "NtCreateSection" ascii wide
	$atp = "RollbackTransaction" ascii wide
 
 condition: 
  ( 	$ati and (  ( 	$atl or	$atn  )  ) and	$atp  ) 
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
	date = "2021-05-13"

 strings: 
 	$avn = "Cryptographic algorithms are disabled after a power-up self test failed." ascii wide
	$avp = ": this object requires an IV" ascii wide
	$avr = "BER decode error" ascii wide
	$avt = ".?AVException@CryptoPP@@" ascii wide
	$avv = "FileStore: error reading file" ascii wide
	$avx = "StreamTransformationFilter: PKCS_PADDING cannot be used with " ascii wide
 
 condition: 
  ( 	$avn or	$avp or	$avr or	$avt or	$avv or	$avx  ) 
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
	date = "2021-05-13"

 strings: 
 	$avz = "RC4 for x86_64, CRYPTOGAMS by <appro@openssl.org>" ascii wide
	$awb = "AES for x86_64, CRYPTOGAMS by <appro@openssl.org>" ascii wide
	$awd = "DSA-SHA1-old" ascii wide
 
 condition: 
  ( 	$avz or	$awb or	$awd  ) 
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
	date = "2021-05-13"

 strings: 
 	$awf = "PolarSSLTest" ascii wide
	$awh = "mbedtls_cipher_setup" ascii wide
	$awj = "mbedtls_pk_verify" ascii wide
	$awl = "mbedtls_ssl_write_record" ascii wide
	$awn = "mbedtls_ssl_fetch_input" ascii wide
 
 condition: 
  ( 	$awf or	$awh or	$awj or	$awl or	$awn  ) 
}
rule capa_linked_against_libcurl { 
 meta: 
 	description = "linked against libcurl (converted from capa rule)"
	namespace = "linking/static/libcurl"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	hash = "A90E5B3454AA71D9700B2EA54615F44B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/libcurl/linked-against-libcurl.yml"
	date = "2021-05-13"

 strings: 
 	$awp = /CLIENT libcurl/ ascii wide 
	$awr = /curl\.haxx\.se/ ascii wide 
 
 condition: 
  ( 	$awp or	$awr  ) 
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
	date = "2021-05-13"

 strings: 
 	$awu = /deflate .* Copyright/ ascii wide 
	$aww = /inflate .* Copyright/ ascii wide 
 
 condition: 
  ( 	$awu or	$aww  ) 
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
	date = "2021-05-13"

 strings: 
 	$awy = /ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ ascii wide 
 
 condition: 
 	$awy 
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
	date = "2021-05-13"

 strings: 
 	$axu = { A9 67 B3 E8 04 FD A3 76 9A 92 80 78 E4 DD D1 38 0D C6 35 98 18 F7 EC 6C 43 75 37 26 FA 13 94 48 F2 D0 8B 30 84 54 DF 23 19 5B 3D 59 F3 AE A2 82 63 01 83 2E D9 51 9B 7C A6 EB A5 BE 16 0C E3 61 C0 8C 3A F5 73 2C 25 0B BB 4E 89 6B 53 6A B4 F1 E1 E6 BD 45 E2 F4 B6 66 CC 95 03 56 D4 1C 1E D7 FB C3 8E B5 E9 CF BF BA EA 77 39 AF 33 C9 62 71 81 79 09 AD 24 CD F9 D8 E5 C5 B9 4D 44 08 86 E7 A1 1D AA ED 06 70 B2 D2 41 7B A0 11 31 C2 27 90 20 F6 60 FF 96 5C B1 AB 9E 9C 52 1B 5F 93 0A EF 91 85 49 EE 2D 4F 8F 3B 47 87 6D }
	$axw = { 75 F3 C6 F4 DB 7B FB C8 4A D3 E6 6B 45 7D E8 4B D6 32 D8 FD 37 71 F1 E1 30 0F F8 1B 87 FA 06 3F 5E BA AE 5B 8A 00 BC 9D 6D C1 B1 0E 80 5D D2 D5 A0 84 07 14 B5 90 2C A3 B2 73 4C 54 92 74 36 51 38 B0 BD 5A FC 60 62 96 6C 42 F7 10 7C 28 27 8C 13 95 9C C7 24 46 3B 70 CA E3 85 CB 11 D0 93 B8 A6 83 20 FF 9F 77 C3 CC 03 6F 08 BF 40 E7 2B E2 79 0C AA 82 41 3A EA B9 E4 9A A4 97 7E DA 7A 17 66 94 A1 1D 3D F0 DE B3 0B 72 A7 1C EF D1 53 3E 8F 33 26 5F EC 76 2A 49 81 88 EE 21 C4 1A EB D9 C5 39 99 CD AD 31 8B 01 18 23 DD }
	$axy = { 75 32 BC BC F3 21 EC EC C6 43 20 20 F4 C9 B3 B3 DB 03 DA DA 7B 8B 02 02 FB 2B E2 E2 C8 FA 9E 9E 4A EC C9 C9 D3 09 D4 D4 E6 6B 18 18 6B 9F 1E 1E 45 0E 98 98 7D 38 B2 B2 E8 D2 A6 A6 4B B7 26 26 D6 57 3C 3C 32 8A 93 93 D8 EE 82 82 FD 98 52 52 37 D4 7B 7B 71 37 BB BB F1 97 5B 5B E1 83 47 47 30 3C 24 24 0F E2 51 51 F8 C6 BA BA 1B F3 4A 4A 87 48 BF BF FA 70 0D 0D 06 B3 B0 B0 3F DE 75 75 5E FD D2 D2 BA 20 7D 7D AE 31 66 66 5B A3 3A 3A 8A 1C 59 59 00 00 00 00 BC 93 CD CD 9D E0 1A 1A 6D 2C AE AE C1 AB 7F 7F B1 C7 2B }
	$aya = { 39 39 D9 A9 17 17 90 67 9C 9C 71 B3 A6 A6 D2 E8 07 07 05 04 52 52 98 FD 80 80 65 A3 E4 E4 DF 76 45 45 08 9A 4B 4B 02 92 E0 E0 A0 80 5A 5A 66 78 AF AF DD E4 6A 6A B0 DD 63 63 BF D1 2A 2A 36 38 E6 E6 54 0D 20 20 43 C6 CC CC 62 35 F2 F2 BE 98 12 12 1E 18 EB EB 24 F7 A1 A1 D7 EC 41 41 77 6C 28 28 BD 43 BC BC 32 75 7B 7B D4 37 88 88 9B 26 0D 0D 70 FA 44 44 F9 13 FB FB B1 94 7E 7E 5A 48 03 03 7A F2 8C 8C E4 D0 B6 B6 47 8B 24 24 3C 30 E7 E7 A5 84 6B 6B 41 54 DD DD 06 DF 60 60 C5 23 FD FD 45 19 3A 3A A3 5B C2 C2 68 }
	$ayc = { 32 BC 75 BC 21 EC F3 EC 43 20 C6 20 C9 B3 F4 B3 03 DA DB DA 8B 02 7B 02 2B E2 FB E2 FA 9E C8 9E EC C9 4A C9 09 D4 D3 D4 6B 18 E6 18 9F 1E 6B 1E 0E 98 45 98 38 B2 7D B2 D2 A6 E8 A6 B7 26 4B 26 57 3C D6 3C 8A 93 32 93 EE 82 D8 82 98 52 FD 52 D4 7B 37 7B 37 BB 71 BB 97 5B F1 5B 83 47 E1 47 3C 24 30 24 E2 51 0F 51 C6 BA F8 BA F3 4A 1B 4A 48 BF 87 BF 70 0D FA 0D B3 B0 06 B0 DE 75 3F 75 FD D2 5E D2 20 7D BA 7D 31 66 AE 66 A3 3A 5B 3A 1C 59 8A 59 00 00 00 00 93 CD BC CD E0 1A 9D 1A 2C AE 6D AE AB 7F C1 7F C7 2B B1 }
	$aye = { D9 A9 39 D9 90 67 17 90 71 B3 9C 71 D2 E8 A6 D2 05 04 07 05 98 FD 52 98 65 A3 80 65 DF 76 E4 DF 08 9A 45 08 02 92 4B 02 A0 80 E0 A0 66 78 5A 66 DD E4 AF DD B0 DD 6A B0 BF D1 63 BF 36 38 2A 36 54 0D E6 54 43 C6 20 43 62 35 CC 62 BE 98 F2 BE 1E 18 12 1E 24 F7 EB 24 D7 EC A1 D7 77 6C 41 77 BD 43 28 BD 32 75 BC 32 D4 37 7B D4 9B 26 88 9B 70 FA 0D 70 F9 13 44 F9 B1 94 FB B1 5A 48 7E 5A 7A F2 03 7A E4 D0 8C E4 47 8B B6 47 3C 30 24 3C A5 84 E7 A5 41 54 6B 41 06 DF DD 06 C5 23 60 C5 45 19 FD 45 A3 5B 3A A3 68 3D C2 }
	$ayg = { 01 02 04 08 10 20 40 80 4D 9A 79 F2 A9 1F 3E 7C F8 BD 37 6E DC F5 A7 03 06 0C 18 30 60 C0 CD D7 E3 8B 5B B6 21 42 84 45 8A 59 B2 29 52 A4 05 0A 14 28 50 A0 0D 1A 34 68 D0 ED 97 63 C6 C1 CF D3 EB 9B 7B F6 A1 0F 1E 3C 78 F0 AD 17 2E 5C B8 3D 7A F4 A5 07 0E 1C 38 70 E0 8D 57 AE 11 22 44 88 5D BA 39 72 E4 85 47 8E 51 A2 09 12 24 48 90 6D DA F9 BF 33 66 CC D5 E7 83 4B 96 61 C2 C9 DF F3 AB 1B 36 6C D8 FD B7 23 46 8C 55 AA 19 32 64 C8 DD F7 A3 0B 16 2C 58 B0 2D 5A B4 25 4A 94 65 CA D9 FF B3 2B 56 AC 15 2A 54 A8 1D }
	$ayi = { A9 75 67 F3 B3 C6 E8 F4 04 DB FD 7B A3 FB 76 C8 9A 4A 92 D3 80 E6 78 6B E4 45 DD 7D D1 E8 38 4B 0D D6 C6 32 35 D8 98 FD 18 37 F7 71 EC F1 6C E1 43 30 75 0F 37 F8 26 1B FA 87 13 FA 94 06 48 3F F2 5E D0 BA 8B AE 30 5B 84 8A 54 00 DF BC 23 9D 19 6D 5B C1 3D B1 59 0E F3 80 AE 5D A2 D2 82 D5 63 A0 01 84 83 07 2E 14 D9 B5 51 90 9B 2C 7C A3 A6 B2 EB 73 A5 4C BE 54 16 92 0C 74 E3 36 61 51 C0 38 8C B0 3A BD F5 5A 73 FC 2C 60 25 62 0B 96 BB 6C 4E 42 89 F7 6B 10 53 7C 6A 28 B4 27 F1 8C E1 13 E6 95 BD 9C 45 C7 E2 24 F4 }
 
 condition: 
  ( 	$axu or	$axw or	$axy or	$aya or	$ayc or	$aye or	$ayg or	$ayi  ) 
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
	date = "2021-05-13"

 strings: 
 	$bae = "RijndaelManaged" ascii wide
	$bag = "CryptoStream" ascii wide
	$bai = "System.Security.Cryptography" ascii wide
 
 condition: 
  ( 	$bae and	$bag and	$bai  ) 
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
	date = "2021-05-13"

 strings: 
 	$bal = { A3 D7 09 83 F8 48 F6 F4 B3 21 15 78 99 B1 AF F9 E7 2D 4D 8A CE 4C CA 2E 52 95 D9 1E 4E 38 44 28 0A DF 02 A0 17 F1 60 68 12 B7 7A C3 E9 FA 3D 53 96 84 6B BA F2 63 9A 19 7C AE E5 F5 F7 16 6A A2 39 B6 7B 0F C1 93 81 1B EE B4 1A EA D0 91 2F B8 55 B9 DA 85 3F 41 BF E0 5A 58 80 5F 66 0B D8 90 35 D5 C0 A7 33 06 65 69 45 00 94 56 6D 98 9B 76 97 FC B2 C2 B0 FE DB 20 E1 EB D6 E4 DD 47 4A 1D 42 ED 9E 6E 49 3C CD 43 27 D2 07 D4 DE C7 67 18 89 CB 30 1F 8D C6 8F AA C8 74 DC C9 5D 5C 31 A4 70 88 61 2C 9F 0D 2B 87 50 82 54 64 26 7D 03 40 34 4B 1C 73 D1 C4 FD 3B CC FB 7F AB E6 3E 5B A5 AD 04 23 9C 14 51 22 F0 29 79 71 7E FF 8C 0E E2 0C EF BC 72 75 6F 37 A1 EC D3 8E 62 8B 86 10 E8 08 77 11 BE 92 4F 24 C5 32 36 9D CF F3 A6 BB AC 5E 6C A9 13 57 25 B5 E3 BD A8 3A 01 05 59 2A 46 }
 
 condition: 
  ( 	$bal  ) 
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
	date = "2021-05-13"

 strings: 
 	$ban = { 06 02 00 00 00 A4 00 00 52 53 41 31 }
 
 condition: 
  ( 	$ban  ) 
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
	date = "2021-05-13"

 strings: 
 	$bap = { 07 56 D2 37 3A F7 0A 52 5D C6 2C 87 DA 05 C1 D7 F4 1F 8C 34 }
	$bar = { 41 4B 1B DD 0D 65 72 EE 09 E7 A1 93 3F 0E 55 9C 63 89 3F B2 AB 5A 0E CB 2F 13 E3 9A C7 09 C5 8D C9 09 0D D7 59 1F A2 D6 CB B0 61 E5 39 44 F8 C5 8B C6 E5 B2 BD E3 82 D2 AB 04 DD D6 1F 94 CA EC 73 43 E7 94 5D 52 66 86 4F 4B 05 D4 AD 0F 66 A3 F9 15 9C C6 C9 3E 3A B8 9D 31 65 F8 C7 9A CE E0 6D BD 18 8D 63 F5 0A CD 11 B4 B5 EE 9B 28 9C A5 93 78 5B D1 D3 B1 2B 84 17 AB F4 85 EF 22 E1 D1 }
	$bat = { 4F 70 46 DA E1 8D F6 41 59 E8 5D 26 1E CC 2F 89 26 6D 52 BA BC 11 6B A9 C6 47 E4 9C 1E B6 65 A2 B6 CD 90 47 1C DF F8 10 4B D2 7C C4 72 25 C6 97 25 5D C6 1D 4B 36 BC 38 36 33 F8 89 B4 4C 65 A7 96 CA 1B 63 C3 4B 6A 63 DC 85 4C 57 EE 2A 05 C7 0C E7 39 35 8A C1 BF 13 D9 52 51 3D 2E 41 F5 72 85 23 FE A1 AA 53 61 3B 25 5F 62 B4 36 EE 2A 51 AF 18 8E 9A C6 CF C4 07 4A 9B 25 9B 76 62 0E 3E 96 3A A7 64 23 6B B6 19 BC 2D 40 D7 36 3E E2 85 9A D1 22 9F BC 30 15 9F C2 5D F1 23 E6 3A 73 C0 A6 AD 71 B0 94 1C 9D B6 56 B6 2B }
 
 condition: 
  ( 	$bap or	$bar or	$bat  ) 
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
	date = "2021-05-13"

 strings: 
 	$bcb = "9.9.9.9" ascii wide
	$bcd = "149.112.112.112" ascii wide
 
 condition: 
  ( 	$bcb or	$bcd  ) 
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
	date = "2021-05-13"

 strings: 
 	$bdo = "64.6.64.6" ascii wide
	$bdq = "64.6.65.6" ascii wide
 
 condition: 
  ( 	$bdo or	$bdq  ) 
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
	date = "2021-05-13"

 strings: 
 	$bds = /http:\/\/nsis\.sf\.net/ ascii wide 
 
 condition: 
  ( 	$bds  ) 
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
	date = "2021-05-13"

 strings: 
 	$bdu = "223.5.5.5" ascii wide
	$bdw = "223.6.6.6" ascii wide
	$bdy = "2400:3200::1" ascii wide
	$bea = "2400:3200:baba::1" ascii wide
 
 condition: 
  ( 	$bdu or	$bdw or	$bdy or	$bea  ) 
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
	date = "2021-05-13"

 strings: 
 	$beu = /https:\/\/doh.seby.io:8443\/dns-query.*/ nocase ascii wide 
	$bew = /https:\/\/family.cloudflare-dns.com\/dns-query.*/ nocase ascii wide 
	$bey = /https:\/\/free.bravedns.com\/dns-query.*/ nocase ascii wide 
	$bfa = /https:\/\/doh.familyshield.opendns.com\/dns-query.*/ nocase ascii wide 
	$bfc = /https:\/\/doh-de.blahdns.com\/dns-query.*/ nocase ascii wide 
	$bfe = /https:\/\/adblock.mydns.network\/dns-query.*/ nocase ascii wide 
	$bfg = /https:\/\/bravedns.com\/configure.*/ nocase ascii wide 
	$bfi = /https:\/\/cloudflare-dns.com\/dns-query.*/ nocase ascii wide 
	$bfk = /https:\/\/commons.host.*/ nocase ascii wide 
	$bfm = /https:\/\/dns.aa.net.uk\/dns-query.*/ nocase ascii wide 
	$bfo = /https:\/\/dns.alidns.com\/dns-query.*/ nocase ascii wide 
	$bfq = /https:\/\/dns-asia.wugui.zone\/dns-query.*/ nocase ascii wide 
	$bfs = /https:\/\/dns.containerpi.com\/dns-query.*/ nocase ascii wide 
	$bfu = /https:\/\/dns.containerpi.com\/doh\/family-filter\/.*/ nocase ascii wide 
	$bfw = /https:\/\/dns.containerpi.com\/doh\/secure-filter\/.*/ nocase ascii wide 
	$bfy = /https:\/\/dns.digitale-gesellschaft.ch\/dns-query.*/ nocase ascii wide 
	$bga = /https:\/\/dns.dnshome.de\/dns-query.*/ nocase ascii wide 
	$bgc = /https:\/\/dns.dns-over-https.com\/dns-query.*/ nocase ascii wide 
	$bge = /https:\/\/dns.dnsoverhttps.net\/dns-query.*/ nocase ascii wide 
	$bgg = /https:\/\/dns.flatuslifir.is\/dns-query.*/ nocase ascii wide 
	$bgi = /https:\/\/dnsforge.de\/dns-query.*/ nocase ascii wide 
	$bgk = /https:\/\/dns.google\/dns-query.*/ nocase ascii wide 
	$bgm = /https:\/\/dns.nextdns.io\/<config_id>.*/ nocase ascii wide 
	$bgo = /https:\/\/dns.rubyfish.cn\/dns-query.*/ nocase ascii wide 
	$bgq = /https:\/\/dns.switch.ch\/dns-query.*/ nocase ascii wide 
	$bgs = /https:\/\/dns.twnic.tw\/dns-query.*/ nocase ascii wide 
	$bgu = /https:\/\/dns.wugui.zone\/dns-query.*/ nocase ascii wide 
	$bgw = /https:\/\/doh-2.seby.io\/dns-query.*/ nocase ascii wide 
	$bgy = /https:\/\/doh.42l.fr\/dns-query.*/ nocase ascii wide 
	$bha = /https:\/\/doh.applied-privacy.net\/query.*/ nocase ascii wide 
	$bhc = /https:\/\/doh.armadillodns.net\/dns-query.*/ nocase ascii wide 
	$bhe = /https:\/\/doh.captnemo.in\/dns-query.*/ nocase ascii wide 
	$bhg = /https:\/\/doh.centraleu.pi-dns.com\/dns-query.*/ nocase ascii wide 
	$bhi = /https:\/\/doh.cleanbrowsing.org\/doh\/family-filter\/.*/ nocase ascii wide 
	$bhk = /https:\/\/doh.crypto.sx\/dns-query.*/ nocase ascii wide 
	$bhm = /https:\/\/doh.dnslify.com\/dns-query.*/ nocase ascii wide 
	$bho = /https:\/\/doh.dns.sb\/dns-query.*/ nocase ascii wide 
	$bhq = /https:\/\/dohdot.coxlab.net\/dns-query.*/ nocase ascii wide 
	$bhs = /https:\/\/doh.eastas.pi-dns.com\/dns-query.*/ nocase ascii wide 
	$bhu = /https:\/\/doh.eastau.pi-dns.com\/dns-query.*/ nocase ascii wide 
	$bhw = /https:\/\/doh.eastus.pi-dns.com\/dns-query.*/ nocase ascii wide 
	$bhy = /https:\/\/doh.ffmuc.net\/dns-query.*/ nocase ascii wide 
	$bia = /https:\/\/doh.libredns.gr\/dns-query.*/ nocase ascii wide 
	$bic = /https:\/\/doh.li\/dns-query.*/ nocase ascii wide 
	$bie = /https:\/\/doh.northeu.pi-dns.com\/dns-query.*/ nocase ascii wide 
	$big = /https:\/\/doh.pi-dns.com\/dns-query.*/ nocase ascii wide 
	$bii = /https:\/\/doh.powerdns.org.*/ nocase ascii wide 
	$bik = /https:\/\/doh.tiarap.org\/dns-query.*/ nocase ascii wide 
	$bim = /https:\/\/doh.tiar.app\/dns-query.*/ nocase ascii wide 
	$bio = /https:\/\/doh.westus.pi-dns.com\/dns-query.*/ nocase ascii wide 
	$biq = /https:\/\/doh.xfinity.com\/dns-query.*/ nocase ascii wide 
	$bis = /https:\/\/example.doh.blockerdns.com\/dns-query.*/ nocase ascii wide 
	$biu = /https:\/\/fi.doh.dns.snopyta.org\/dns-query.*/ nocase ascii wide 
	$biw = /https:\/\/ibksturm.synology.me\/dns-query.*/ nocase ascii wide 
	$biy = /https:\/\/ibuki.cgnat.net\/dns-query.*/ nocase ascii wide 
	$bja = /https:\/\/jcdns.fun\/dns-query.*/ nocase ascii wide 
	$bjc = /https:\/\/jp.tiarap.org\/dns-query.*/ nocase ascii wide 
	$bje = /https:\/\/jp.tiar.app\/dns-query.*/ nocase ascii wide 
	$bjg = /https:\/\/odvr.nic.cz\/doh.*/ nocase ascii wide 
	$bji = /https:\/\/ordns.he.net\/dns-query.*/ nocase ascii wide 
	$bjk = /https:\/\/rdns.faelix.net\/.*/ nocase ascii wide 
	$bjm = /https:\/\/resolver-eu.lelux.fi\/dns-query.*/ nocase ascii wide 
	$bjo = /https:\/\/doh-jp.blahdns.com\/dns-query.*/ nocase ascii wide 
 
 condition: 
  ( 	$beu or	$bew or	$bey or	$bfa or	$bfc or	$bfe or	$bfg or	$bfi or	$bfk or	$bfm or	$bfo or	$bfq or	$bfs or	$bfu or	$bfw or	$bfy or	$bga or	$bgc or	$bge or	$bgg or	$bgi or	$bgk or	$bgm or	$bgo or	$bgq or	$bgs or	$bgu or	$bgw or	$bgy or	$bha or	$bhc or	$bhe or	$bhg or	$bhi or	$bhk or	$bhm or	$bho or	$bhq or	$bhs or	$bhu or	$bhw or	$bhy or	$bia or	$bic or	$bie or	$big or	$bii or	$bik or	$bim or	$bio or	$biq or	$bis or	$biu or	$biw or	$biy or	$bja or	$bjc or	$bje or	$bjg or	$bji or	$bjk or	$bjm or	$bjo  ) 
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
	date = "2021-05-13"

 strings: 
 	$bjy = "8.8.8.8" ascii wide
	$bka = "8.8.4.4" ascii wide
	$bkc = "2001:4860:4860::8888" ascii wide
	$bke = "2001:4860:4860::8844" ascii wide
 
 condition: 
  ( 	$bjy or	$bka or	$bkc or	$bke  ) 
}
rule capa_linked_against_C___regex_library { 
 meta: 
 	description = "linked against C++ regex library (converted from capa rule)"
	namespace = "linking/static/cppregex"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-c-regex-library.yml"
	capa_nursery = "True"
	date = "2021-05-13"

 strings: 
 	$bkh = "regex_error(error_syntax)" ascii wide
	$bkj = "regex_error(error_collate): The expression contained an invalid collating element name." ascii wide
 
 condition: 
  ( 	$bkh or	$bkj  ) 
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
	date = "2021-05-13"

 strings: 
 	$bkp = "114.114.114.114" ascii wide
	$bkr = "114.114.115.115" ascii wide
	$bkt = "114.114.114.119" ascii wide
	$bkv = "114.114.115.119" ascii wide
	$bkx = "114.114.114.110" ascii wide
	$bkz = "114.114.115.110" ascii wide
 
 condition: 
  ( 	$bkp or	$bkr or	$bkt or	$bkv or	$bkx or	$bkz  ) 
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
	date = "2021-05-13"

 strings: 
 	$bli = "8.26.56.26" ascii wide
	$blk = "8.20.247.20" ascii wide
 
 condition: 
  ( 	$bli or	$blk  ) 
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
	date = "2021-05-13"

 strings: 
 	$bln = "4.2.2.1" ascii wide
	$blp = "4.2.2.2" ascii wide
	$blr = "4.2.2.3" ascii wide
	$blt = "4.2.2.4" ascii wide
	$blv = "4.2.2.5" ascii wide
	$blx = "4.2.2.6" ascii wide
 
 condition: 
  ( 	$bln or	$blp or	$blr or	$blt or	$blv or	$blx  ) 
}
rule capa_packaged_as_a_Wise_installer { 
 meta: 
 	description = "packaged as a Wise installer (converted from capa rule)"
	namespace = "executable/installer/wiseinstall"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-wise-installer.yml"
	capa_nursery = "True"
	date = "2021-05-13"

 strings: 
 	$blz = "WiseMain" ascii wide
	$bmb = /Wise Installation Wizard/ ascii wide 
 
 condition: 
  ( 	$blz or	$bmb  ) 
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
	date = "2021-05-13"

 strings: 
 	$bmo = "1.1.1.1" ascii wide
	$bmq = "1.0.0.1" ascii wide
 
 condition: 
  ( 	$bmo or	$bmq  ) 
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
	date = "2021-05-13"

 strings: 
 	$bne = "168.126.63.1" ascii wide
 
 condition: 
  ( 	$bne  ) 
}
rule capa_read_raw_disk_data { 
 meta: 
 	description = "read raw disk data (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/read-raw-disk-data.yml"
	capa_nursery = "True"
	date = "2021-05-13"

 strings: 
 	$bnk = "\\\\.\\PhysicalDrive0" ascii wide
	$bnm = "\\\\.\\C:" ascii wide
 
 condition: 
  ( 	$bnk or	$bnm  ) 
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
	date = "2021-05-13"

 strings: 
 	$bno = { 50 A7 F4 51 53 65 41 7E }
	$bnq = { 63 7C 77 7B F2 6B 6F C5 }
	$bns = { 52 09 6A D5 30 36 A5 38 }
 
 condition: 
  ( 	$bno or	$bnq or	$bns  ) 
}
rule capa_compiled_with_Nim { 
 meta: 
 	description = "compiled with Nim (converted from capa rule)"
	namespace = "compiler/nim"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/compiled-with-nim.yml"
	capa_nursery = "True"
	date = "2021-05-13"

 strings: 
 	$bnu = /NimMain/ ascii wide 
	$bnw = /NimMainModule/ ascii wide 
	$bny = /NimMainInner/ ascii wide 
	$boa = /io.nim$/ ascii wide 
	$boc = /fatal.nim$/ ascii wide 
	$boe = /system.nim$/ ascii wide 
	$bog = /alloc.nim$/ ascii wide 
	$boi = /osalloc.nim$/ ascii wide 
 
 condition: 
  ( 	$bnu or	$bnw or	$bny or	$boa or	$boc or	$boe or	$bog or	$boi  ) 
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
	date = "2021-05-13"

 strings: 
 	$bop = /Start Menu\\Programs\\Startup/ nocase ascii wide 
 
 condition: 
  ( 	$bop  ) 
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
	date = "2021-05-13"

 strings: 
 	$bpf = "216.218.130.2" ascii wide
	$bph = "216.218.131.2" ascii wide
	$bpj = "216.218.132.2" ascii wide
	$bpl = "216.66.1.2" ascii wide
	$bpn = "216.66.80.18" ascii wide
 
 condition: 
  ( 	$bpf or	$bph or	$bpj or	$bpl or	$bpn  ) 
}
rule capa_packaged_as_an_InstallShield_installer { 
 meta: 
 	description = "packaged as an InstallShield installer (converted from capa rule)"
	namespace = "executable/installer/installshield"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-an-installshield-installer.yml"
	capa_nursery = "True"
	date = "2021-05-13"

 strings: 
 	$bpq = "InstallShield" ascii wide
 
 condition: 
  ( 	$bpq  ) 
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
	date = "2021-05-13"

 strings: 
 	$bps = "stratum+tcp://" ascii wide
	$bpu = "xmrig" ascii wide
	$bpw = "xmr-stak" ascii wide
	$bpy = "supportxmr.com:" ascii wide
	$bqa = "dwarfpool.com:" ascii wide
	$bqc = "minergate" ascii wide
	$bqe = "xmr." ascii wide
	$bqg = "monero." ascii wide
	$bqi = "Bitcoin" ascii wide
	$bqk = "Bitcoin" ascii wide
	$bqm = "BitcoinGold" ascii wide
	$bqo = "BtcCash" ascii wide
	$bqq = "Ethereum" ascii wide
	$bqs = "BlackCoin" ascii wide
	$bqu = "ByteCoin" ascii wide
	$bqw = "EmerCoin" ascii wide
	$bqy = "ReddCoin" ascii wide
	$bra = "Peercoin" ascii wide
	$brc = "Ripple" ascii wide
	$bre = "Miota" ascii wide
	$brg = "Cardano" ascii wide
	$bri = "Lisk" ascii wide
	$brk = "Stratis" ascii wide
	$brm = "Waves" ascii wide
	$bro = "Qtum" ascii wide
	$brq = "Stellar" ascii wide
	$brs = "ViaCoin" ascii wide
	$bru = "Electroneum" ascii wide
	$brw = "Dash" ascii wide
	$bry = "Doge" ascii wide
	$bsa = "Monero" ascii wide
	$bsc = "Graft" ascii wide
	$bse = "Zcash" ascii wide
	$bsg = "Ya.money" ascii wide
	$bsi = "Ya.disc" ascii wide
	$bsk = "Steam" ascii wide
	$bsm = "vk.cc" ascii wide
 
 condition: 
  ( 	$bps or	$bpu or	$bpw or	$bpy or	$bqa or	$bqc or	$bqe or	$bqg or	$bqi or	$bqk or	$bqm or	$bqo or	$bqq or	$bqs or	$bqu or	$bqw or	$bqy or	$bra or	$brc or	$bre or	$brg or	$bri or	$brk or	$brm or	$bro or	$brq or	$brs or	$bru or	$brw or	$bry or	$bsa or	$bsc or	$bse or	$bsg or	$bsi or	$bsk or	$bsm  ) 
}
rule capa_debug_build { 
 meta: 
 	description = "debug build (converted from capa rule)"
	namespace = "executable/pe/debug"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/debug-build.yml"
	capa_nursery = "True"
	date = "2021-05-13"

 strings: 
 	$bsp = "Assertion failed!" ascii wide
	$bsr = "Assertion failed:" ascii wide
 
 condition: 
  ( 	$bsp or	$bsr  ) 
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
	date = "2021-05-13"

 strings: 
 	$bsy = "208.67.222.222" ascii wide
	$bta = "208.67.220.220" ascii wide
 
 condition: 
  ( 	$bsy or	$bta  ) 
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
	date = "2021-05-13"

 strings: 
 	$btd = "ct_init: length != 256" ascii wide
	$btf = "ct_init: dist != 256" ascii wide
	$bth = "ct_init: 256+dist != 512" ascii wide
	$btj = "bit length overflow" ascii wide
	$btl = "code %d bits %d->%d" ascii wide
	$btn = "inconsistent bit counts" ascii wide
	$btp = "gen_codes: max_code %d " ascii wide
	$btr = "dyn trees: dyn %ld, stat %ld" ascii wide
	$btt = "bad pack level" ascii wide
	$btv = "Code too clever" ascii wide
	$btx = "unknown zip result code" ascii wide
	$btz = "Culdn't duplicate handle" ascii wide
	$bub = "File not found in the zipfile" ascii wide
	$bud = "Still more data to unzip" ascii wide
	$buf = "Caller: the file had already been partially unzipped" ascii wide
	$buh = "Caller: can only get memory of a memory zipfile" ascii wide
	$buj = "Zip-bug: internal initialisation not completed" ascii wide
	$bul = "Zip-bug: an internal error during flation" ascii wide
 
 condition: 
  ( 	$btd or	$btf or	$bth or	$btj or	$btl or	$btn or	$btp or	$btr or	$btt or	$btv or	$btx or	$btz or	$bub or	$bud or	$buf or	$buh or	$buj or	$bul  ) 
}
rule capa_compiled_with_Go { 
 meta: 
 	description = "compiled with Go (converted from capa rule)"
	namespace = "compiler/go"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	hash = "49a34cfbeed733c24392c9217ef46bb6"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/go/compiled-with-go.yml"
	date = "2021-05-13"

 strings: 
 	$bvc = "Go build ID:" ascii wide
	$bve = "go.buildid" ascii wide
	$bvg = "Go buildinf:" ascii wide
 
 condition: 
  ( 	$bvc or	$bve or	$bvg  ) 
}
rule capa_compiled_with_MinGW_for_Windows { 
 meta: 
 	description = "compiled with MinGW for Windows (converted from capa rule)"
	namespace = "compiler/mingw"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	hash = "5b3968b47eb16a1cb88525e3b565eab1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/mingw/compiled-with-mingw-for-windows.yml"
	date = "2021-05-13"

 strings: 
 	$bvi = "Mingw runtime failure:" ascii wide
	$bvk = "_Jv_RegisterClasses" ascii wide
 
 condition: 
  ( 	$bvi and	$bvk  ) 
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
	date = "2021-05-13"

 strings: 
 	$bvp = "pyarmor_runtimesh" ascii wide
	$bvr = "PYARMOR" ascii wide
	$bvt = "__pyarmor__" ascii wide
	$bvv = "PYARMOR_SIGNATURE" ascii wide
 
 condition: 
  ( 	$bvp or	$bvr or	$bvt or	$bvv  ) 
}
rule capa_compiled_with_exe4j { 
 meta: 
 	description = "compiled with exe4j (converted from capa rule)"
	namespace = "compiler/exe4j"
	author = "johnk3r"
	scope = "file"
	hash = "6b25f1e754ef486bbb28a66d46bababe"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/exe4j/compiled-with-exe4j.yml"
	date = "2021-05-13"

 strings: 
 	$bvx = "exe4j_log" ascii wide
	$bvz = "install4j_log" ascii wide
	$bwb = "exe4j_java_home" ascii wide
	$bwd = "install4j" ascii wide
	$bwf = "exe4j.isinstall4j" ascii wide
	$bwh = /com\/exe4j\/runtime\/exe4jcontroller/ nocase ascii wide 
	$bwj = /com\/exe4j\/runtime\/winlauncher/ nocase ascii wide 
	$bwl = "EXE4J_LOG" ascii wide
	$bwn = "INSTALL4J_LOG" ascii wide
	$bwp = "EXE4J_JAVA_HOME" ascii wide
	$bwr = "INSTALL4J" ascii wide
	$bwt = "EXE4J.ISINSTALL4J" ascii wide
 
 condition: 
  ( 	$bvx or	$bvz or	$bwb or	$bwd or	$bwf or	$bwh or	$bwj or	$bwl or	$bwn or	$bwp or	$bwr or	$bwt  ) 
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
	date = "2021-05-13"

 strings: 
 	$bwv = "AutoIt has detected the stack has become corrupt.\n\nStack corruption typically occurs when either the wrong calling convention is used or when the function is called with the wrong number of arguments.\n\nAutoIt supports the __stdcall (WINAPI) and __cdecl calling conventions.  The __stdcall (WINAPI) convention is used by default but __cdecl can be used instead.  See the DllCall() documentation for details on changing the calling convention." ascii wide
	$bwx = "AutoIt Error" ascii wide
	$bwz = />>>AUTOIT SCRIPT<<</ ascii wide 
	$bxb = ">>>AUTOIT NO CMDEXECUTE<<<" ascii wide
	$bxd = "#requireadmin" ascii wide
	$bxf = "#OnAutoItStartRegister" ascii wide
 
 condition: 
  ( 	$bwv or	$bwx or	$bwz or	$bxb or	$bxd or	$bxf  ) 
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
	date = "2021-05-13"

 strings: 
 	$bxu = "CurrencyDispenser1" ascii wide
	$bxw = "CDM30" ascii wide
	$bxy = "DBD_AdvFuncDisp" ascii wide
 
 condition: 
  ( 	$bxu or	$bxw or	$bxy  ) 
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
	date = "2021-05-13"

 strings: 
 	$bye = "DBD_AdvFuncDisp" ascii wide
	$byg = "DBD_EPP4" ascii wide
 
 condition: 
  ( 	$bye or	$byg  ) 
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
	date = "2021-05-13"

 strings: 
 	$caq = /\\sm\.dat/ ascii wide 
	$cat = /\\GlobalSCAPE\\CuteFTP/ nocase ascii wide 
	$cav = /\\GlobalSCAPE\\CuteFTP Pro/ nocase ascii wide 
	$cax = /\\CuteFTP/ ascii wide 
 
 condition: 
  ( 	$caq and (  ( 	$cat or	$cav or	$cax  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$caz = /\\FTPRush/ ascii wide 
	$cbb = /RushSite\.xml/ ascii wide 
 
 condition: 
  ( 	$caz and	$cbb  ) 
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
	date = "2021-05-13"

 strings: 
 	$cbe = /\\SmartFTP/ ascii wide 
	$cbg = ".xml" ascii wide
	$cbi = /Favorites\.dat/ nocase ascii wide 
	$cbk = /History\.dat/ nocase ascii wide 
 
 condition: 
  (  (  ( 	$cbe and	$cbg and	$cbi and	$cbk  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cbm = /\\Cyberduck/ ascii wide 
	$cbp = "user.config" ascii wide
	$cbr = ".duck" ascii wide
 
 condition: 
  ( 	$cbm and (  ( 	$cbp or	$cbr  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cbt = /\\Ipswitch\\WS_FTP/ ascii wide 
	$cbv = /\\win\.ini/ ascii wide 
	$cbx = /WS_FTP/ ascii wide 
 
 condition: 
  ( 	$cbt and	$cbv and	$cbx  ) 
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
	date = "2021-05-13"

 strings: 
 	$cbz = /SOFTWARE\\NCH Software\\Fling\\Accounts/ ascii wide 
	$ccc = "FtpPassword" ascii wide
	$cce = "_FtpPassword" ascii wide
	$ccg = "FtpServer" ascii wide
	$cci = "FtpUserName" ascii wide
	$cck = "FtpDirectory" ascii wide
 
 condition: 
  ( 	$cbz or (  ( 	$ccc and	$cce and	$ccg and	$cci and	$cck  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$ccm = /\\GPSoftware\\Directory Opus/ ascii wide 
	$cco = ".oxc" ascii wide
	$ccq = ".oll" ascii wide
	$ccs = "ftplast.osd" ascii wide
 
 condition: 
  ( 	$ccm and	$cco and	$ccq and	$ccs  ) 
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
	date = "2021-05-13"

 strings: 
 	$ccu = /Software\\FTPWare\\COREFTP\\Sites/ ascii wide 
	$ccx = "Host" ascii wide
	$ccz = "User" ascii wide
	$cdb = "Port" ascii wide
	$cdd = "PthR" ascii wide
 
 condition: 
  ( 	$ccu or (  ( 	$ccx and	$ccz and	$cdb and	$cdd  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cdg = "wiseftpsrvs.ini" ascii wide
	$cdi = "wiseftp.ini" ascii wide
	$cdk = "wiseftpsrvs.bin" ascii wide
	$cdn = "wiseftpsrvs.bin" ascii wide
	$cdq = /\\AceBIT/ ascii wide 
	$cds = /Software\\AceBIT/ ascii wide 
 
 condition: 
  (  (  ( 	$cdg and	$cdi and	$cdk  )  ) or (  ( 	$cdn and (  ( 	$cdq or	$cds  )  )  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cdv = /Software\\Nico Mak Computing\\WinZip\\FTP/ ascii wide 
	$cdx = /Software\\Nico Mak Computing\\WinZip\\mru\\jobs/ ascii wide 
	$cea = "Site" ascii wide
	$cec = "UserID" ascii wide
	$cee = "xflags" ascii wide
	$ceg = "Port" ascii wide
	$cei = "Folder" ascii wide
 
 condition: 
  (  (  ( 	$cdv and	$cdx  )  ) or (  ( 	$cea and	$cec and	$cee and	$ceg and	$cei  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cek = /Software\\South River Technologies\\WebDrive\\Connections/ ascii wide 
	$cen = "PassWord" ascii wide
	$cep = "UserName" ascii wide
	$cer = "RootDirectory" ascii wide
	$cet = "Port" ascii wide
	$cev = "ServerType" ascii wide
 
 condition: 
  ( 	$cek or (  ( 	$cen and	$cep and	$cer and	$cet and	$cev  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cex = "FreshFTP" ascii wide
	$cez = ".SMF" ascii wide
 
 condition: 
  ( 	$cex and	$cez  ) 
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
	date = "2021-05-13"

 strings: 
 	$cfc = "FastTrack" ascii wide
	$cfe = "ftplist.txt" ascii wide
 
 condition: 
  (  (  ( 	$cfc and	$cfe  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cfg = /Software\\NCH Software\\ClassicFTP\\FTPAccounts/ ascii wide 
 
 condition: 
  ( 	$cfg  ) 
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
	date = "2021-05-13"

 strings: 
 	$cfi = /Software\\FTPClient\\Sites/ ascii wide 
	$cfk = /Software\\SoftX.org\\FTPClient\\Sites/ ascii wide 
 
 condition: 
  ( 	$cfi or	$cfk  ) 
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
	date = "2021-05-13"

 strings: 
 	$cfo = /Software\\Sota\\FFFTP\\Options/ ascii wide 
	$cfq = /Software\\Sota\\FFFTP/ ascii wide 
	$cft = /CredentialSalt/ ascii wide 
	$cfv = /CredentialCheck/ ascii wide 
	$cfy = "Password" ascii wide
	$cga = "UserName" ascii wide
	$cgc = "HostAdrs" ascii wide
	$cge = "RemoteDir" ascii wide
	$cgg = "Port" ascii wide
 
 condition: 
  (  (  (  (  ( 	$cfo or	$cfq  )  ) and (  ( 	$cft or	$cfv  )  )  )  ) or (  ( 	$cfy and	$cga and	$cgc and	$cge and	$cgg  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cgi = "FTPShell" ascii wide
	$cgk = "ftpshell.fsi" ascii wide
 
 condition: 
  ( 	$cgi and	$cgk  ) 
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
	date = "2021-05-13"

 strings: 
 	$cgm = "Password" ascii wide
	$cgo = "HostName" ascii wide
	$cgq = "UserName" ascii wide
	$cgs = "RemoteDirectory" ascii wide
	$cgu = "PortNumber" ascii wide
	$cgw = "FSProtocol" ascii wide
 
 condition: 
  ( 	$cgm and	$cgo and	$cgq and	$cgs and	$cgu and	$cgw  ) 
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
	date = "2021-05-13"

 strings: 
 	$cgy = /FtpSite\.xml/ ascii wide 
	$cha = /\\Frigate3/ ascii wide 
 
 condition: 
  ( 	$cgy and	$cha  ) 
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
	date = "2021-05-13"

 strings: 
 	$chc = "Staff-FTP" ascii wide
	$che = "sites.ini" ascii wide
 
 condition: 
  ( 	$chc and	$che  ) 
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
	date = "2021-05-13"

 strings: 
 	$chg = ".xfp" ascii wide
	$chi = /\\NetSarang/ ascii wide 
 
 condition: 
  ( 	$chg and	$chi  ) 
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
	date = "2021-05-13"

 strings: 
 	$chz = "FTPNow" ascii wide
	$cib = "FTP Now" ascii wide
	$cid = "sites.xml" ascii wide
 
 condition: 
  ( 	$chz and	$cib and	$cid  ) 
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
	date = "2021-05-13"

 strings: 
 	$cif = "servers.xml" ascii wide
	$cih = /\\FTPGetter/ ascii wide 
 
 condition: 
  ( 	$cif and	$cih  ) 
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
	date = "2021-05-13"

 strings: 
 	$cik = "NovaFTP.db" ascii wide
	$cim = /\\INSoftware\\NovaFTP/ ascii wide 
 
 condition: 
  (  (  ( 	$cik and	$cim  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cip = /profiles\.xml/ ascii wide 
	$cis = /Software\\FTP Explorer\\FTP Explorer\\Workspace\\MFCToolBar-224/ ascii wide 
	$ciu = /Software\\FTP Explorer\\Profiles/ ascii wide 
	$ciw = /\\FTP Explorer/ ascii wide 
	$ciz = "Password" ascii wide
	$cjb = "Host" ascii wide
	$cjd = "Login" ascii wide
	$cjf = "InitialPath" ascii wide
	$cjh = "PasswordType" ascii wide
	$cjj = "Port" ascii wide
 
 condition: 
  (  (  ( 	$cip and (  ( 	$cis or	$ciu or	$ciw  )  )  )  ) or (  ( 	$ciz and	$cjb and	$cjd and	$cjf and	$cjh and	$cjj  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cjl = /bitkinex\.ds/ ascii wide 
	$cjn = /\\BitKinex/ ascii wide 
 
 condition: 
  ( 	$cjl and	$cjn  ) 
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
	date = "2021-05-13"

 strings: 
 	$cjq = "addrbk.dat" ascii wide
	$cjs = "quick.dat" ascii wide
	$cjv = /installpath/ ascii wide 
	$cjy = /Software\\TurboFTP/ ascii wide 
	$cka = /\\TurboFTP/ ascii wide 
 
 condition: 
  (  (  ( 	$cjq and	$cjs  )  ) or (  ( 	$cjv and (  ( 	$cjy or	$cka  )  )  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$ckc = "NexusFile" ascii wide
	$cke = "ftpsite.ini" ascii wide
 
 condition: 
  ( 	$ckc and	$cke  ) 
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
	date = "2021-05-13"

 strings: 
 	$ckg = /\\RhinoSoft.com/ ascii wide 
	$cki = "FTPVoyager.ftp" ascii wide
	$ckk = "FTPVoyager.qc" ascii wide
 
 condition: 
  ( 	$ckg and	$cki and	$ckk  ) 
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
	date = "2021-05-13"

 strings: 
 	$ckm = "BlazeFtp" ascii wide
	$cko = "site.dat" ascii wide
	$ckr = "LastPassword" ascii wide
	$ckt = "LastAddress" ascii wide
	$ckv = "LastUser" ascii wide
	$ckx = "LastPort" ascii wide
	$ckz = /Software\\FlashPeak\\BlazeFtp\\Settings/ ascii wide 
 
 condition: 
  ( 	$ckm and	$cko and (  ( 	$ckr or	$ckt or	$ckv or	$ckx or	$ckz  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$clc = /FTP Navigator/ ascii wide 
	$cle = /FTP Commander/ ascii wide 
	$clh = "ftplist.txt" ascii wide
 
 condition: 
  (  (  ( 	$clc or	$cle  )  ) and (  ( 	$clh  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cly = /\\Global Downloader/ ascii wide 
	$cma = "SM.arch" ascii wide
 
 condition: 
  ( 	$cly and	$cma  ) 
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
	date = "2021-05-13"

 strings: 
 	$cms = /FastStone Browser/ ascii wide 
	$cmu = "FTPList.db" ascii wide
 
 condition: 
  ( 	$cms and	$cmu  ) 
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
	date = "2021-05-13"

 strings: 
 	$cmw = /UltraFXP/ ascii wide 
	$cmy = /\\sites\.xml/ ascii wide 
 
 condition: 
  ( 	$cmw and	$cmy  ) 
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
	date = "2021-05-13"

 strings: 
 	$cna = "NDSites.ini" ascii wide
	$cnc = /\\NetDrive/ ascii wide 
 
 condition: 
  ( 	$cna and	$cnc  ) 
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
	date = "2021-05-13"

 strings: 
 	$cnf = /Software\\Ghisler\\Total Commander/ ascii wide 
	$cnh = /Software\\Ghisler\\Windows Commander/ ascii wide 
	$cnk = "FtpIniName" ascii wide
	$cnm = "wcx_ftp.ini" ascii wide
	$cno = /\\GHISLER/ ascii wide 
	$cnq = "InstallDir" ascii wide
 
 condition: 
  (  (  ( 	$cnf or	$cnh  )  ) and (  ( 	$cnk or	$cnm or	$cno or	$cnq  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cns = "ServerList.xml" ascii wide
	$cnu = "DataDir" ascii wide
	$cnx = /Software\\MAS-Soft\\FTPInfo\\Setup/ ascii wide 
	$cnz = /FTPInfo/ ascii wide 
 
 condition: 
  ( 	$cns and	$cnu and (  ( 	$cnx or	$cnz  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$coc = /Software\\FlashFXP/ ascii wide 
	$coe = /DataFolder/ ascii wide 
	$cog = /Install Path/ ascii wide 
	$coj = /\\Sites.dat/ ascii wide 
	$col = /\\Quick.dat/ ascii wide 
	$con = /\\History.dat/ ascii wide 
 
 condition: 
  (  (  ( 	$coc and	$coe and	$cog  )  ) or (  ( 	$coj and	$col and	$con  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cop = /\\Sessions/ ascii wide 
	$cor = ".ini" ascii wide
	$cot = /Config Path/ ascii wide 
	$cow = /_VanDyke\\Config\\Sessions/ ascii wide 
	$coy = /Software\\VanDyke\\SecureFX/ ascii wide 
 
 condition: 
  ( 	$cop and	$cor and	$cot and (  ( 	$cow or	$coy  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cpb = /SOFTWARE\\Robo-FTP/ ascii wide 
	$cpe = /\\FTPServers/ ascii wide 
	$cpg = /FTP File/ ascii wide 
	$cpi = "FTP Count" ascii wide
	$cpl = "Password" ascii wide
	$cpn = "ServerName" ascii wide
	$cpp = "UserID" ascii wide
	$cpr = "PortNumber" ascii wide
	$cpt = "InitialDirectory" ascii wide
	$cpv = "ServerType" ascii wide
 
 condition: 
  (  (  ( 	$cpb and (  ( 	$cpe or	$cpg or	$cpi  )  )  )  ) or (  ( 	$cpl and	$cpn and	$cpp and	$cpr and	$cpt and	$cpv  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cpy = ".dat" ascii wide
	$cqa = ".bps" ascii wide
	$cqe = /Software\\BPFTP\\Bullet Proof FTP\\Main/ ascii wide 
	$cqg = /Software\\BulletProof Software\\BulletProof FTP Client\\Main/ ascii wide 
	$cqi = /Software\\BulletProof Software\\BulletProof FTP Client\\Options/ ascii wide 
	$cqk = /Software\\BPFTP\\Bullet Proof FTP\\Options/ ascii wide 
	$cqm = /Software\\BPFTP/ ascii wide 
	$cqp = "LastSessionFile" ascii wide
	$cqr = "SitesDir" ascii wide
 
 condition: 
  (  (  ( 	$cpy and	$cqa  )  ) or (  (  (  ( 	$cqe or	$cqg or	$cqi or	$cqk or	$cqm  )  ) and (  ( 	$cqp or	$cqr  )  )  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$cqt = "ESTdb2.dat" ascii wide
	$cqv = "QData.dat" ascii wide
	$cqx = /\\Estsoft\\ALFTP/ ascii wide 
 
 condition: 
  ( 	$cqt and	$cqv and	$cqx  ) 
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
	date = "2021-05-13"

 strings: 
 	$cra = /Software\\ExpanDrive\\Sessions/ ascii wide 
	$crc = /Software\\ExpanDrive/ ascii wide 
	$crf = /ExpanDrive_Home/ ascii wide 
	$crh = /\\drives\.js/ ascii wide 
 
 condition: 
  (  (  ( 	$cra or	$crc  )  ) and (  ( 	$crf or	$crh  )  )  ) 
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
	date = "2021-05-13"

 strings: 
 	$crj = "GoFTP" ascii wide
	$crl = "Connections.txt" ascii wide
 
 condition: 
  ( 	$crj and	$crl  ) 
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
	date = "2021-05-13"

 strings: 
 	$csd = /SELECT.*FROM.*WHERE/ ascii wide 
 
 condition: 
  ( 	$csd  ) 
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
	date = "2021-05-13"

 strings: 
 	$csf = /SELECT\s+\*\s+FROM\s+CIM_./ ascii wide 
	$csh = /SELECT\s+\*\s+FROM\s+Win32_./ ascii wide 
	$csj = /SELECT\s+\*\s+FROM\s+MSAcpi_./ ascii wide 
 
 condition: 
  ( 	$csf or	$csh or	$csj  ) 
}
