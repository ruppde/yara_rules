rule HKTL_NET_GUID_no_GUID {
    meta:
        description = "Experimental: Hints an c# red/black-team tools missing typelibguid while having content from assemblyinfo.cs (lots of FP, not unusual on legitimate tools either!)"
        reference = "TODO"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-30"
    strings:
		$GuidAttribute = "GuidAttribute"
        $AssemblyInfo0 = "AssemblyTitleAttribute" 
        $AssemblyInfo1 = "AssemblyFileVersionAttribute" 
        $AssemblyInfo2 = "AssemblyDescriptionAttribute" 
        $AssemblyInfo3 = "AssemblyProductAttribute" 
        $AssemblyInfo4 = "AssemblyConfigurationAttribute" 
        $AssemblyInfo5 = "AssemblyCopyrightAttribute"
        $AssemblyInfo6 = "AssemblyCompanyAttribute"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of ( $AssemblyInfo* ) and not $GuidAttribute
}
