// rationale behind the rules:
// * a webshell must always execute some kind of payload (in $payload*). the payload is either:
// ** direct php function like exec or
// ** indirect via eval, self defined functions, callbacks, ...
// * a webshell must always have some way to get the attackers input, e.g. for PHP in $_GET, php://input or $_SERVER (HTTP for headers). these are in the strings $input* (... if they're not obfuscated in some payload, then we look for payload + obfuscation)
// * some additional conditions might be added to reduce false positves

rule php_webshell_generic_tiny {
	meta:
		description = "php webshell having some kind of input and some kind of payload. restricted to small files or would give lots of false positives"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "5146918ca36099c8cae8a87afd8d18b5d1f18f5d"
		date = "2021/01/07"
	strings:
		$phpinput1 = "php://input"
		$phpinput2 = "file_get_contents"
		$input1 = "_GET["
		$input2 = "_POST["
		$input3 = "_REQUEST["
		$input4 = "_SERVER['HTTP_"
		$input5 = "_SERVER[\"HTTP_"
		$payload1 = /\bexec[\t ]*\([^)]/ nocase
		$payload2 = /\bshell_exec[\t ]*\([^)]/ nocase
		$payload3 = /\bpassthru[\t ]*\([^)]/ nocase
		$payload4 = /\bsystem[\t ]*\([^)]/ nocase
		$payload5 = /\bpopen[\t ]*\([^)]/ nocase
		$payload6 = /\bproc_open[\t ]*\([^)]/ nocase
		$payload7 = /\bpcntl_exec[\t ]*\([^)]/ nocase
		$payload8 = /\beval[\t ]*\([^)]/ nocase
		$payload9 = /\bassert[\t ]*\([^)]/ nocase
		$fp1 = "eval(\"return [$serialised_paramete" // elgg
	condition:
		filesize < 1000 and ( all of ( $phpinput*) or any of ( $input* ) ) and any of ( $payload* ) and not any of ( $fp* )
}

rule php_webshell_base64_encoded_payloads {
	meta:
		description = "php webshell containg base64 encoded payload"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:
		$php = "<?"
		$decode = "base64" // avoid having a string at random in a crypto key
		$payload1 = "exec" base64
		$payload2 = "shell_exec" base64
		$payload3 = "passthru" base64
		$payload4 = "system" base64
		$payload5 = "popen" base64
		$payload6 = "proc_open" base64
		$payload7 = "pcntl_exec" base64
		$payload8 = "eval" base64
		$payload9 = "assert" base64
	condition:
		filesize < 300000 and $php and $decode and any of ( $payload* )
}


rule webshell_unknown_1 {
	meta:
		description = "obfuscated php webshell"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "12ce6c7167b33cc4e8bdec29fb1cfc44ac9487d1"
		hash = "cf4abbd568ce0c0dfce1f2e4af669ad2"
		date = "2021/01/07"
	strings:
		$s0 = /^<\?php \$[a-z]{3,30} = '/
		$s1 = "=explode(chr("
		$s2 = "; if (!function_exists('"
		$s3 = " = NULL; for("
	condition:
		all of them
}

rule webshell_generic_php_eval {
	meta:
		description = "Generic PHP webshell which uses any eval/exec function directly on user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "a61437a427062756e2221bfb6d58cd62439d09d9"
		date = "2021/01/07"
	strings:
		// PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
		$s0 = /(exec|shell_exec|passthru|system|popen|proc_open|pcntl_exec|eval|assert)[\t ]*(stripslashes\()?[\t ]*(trim\()?[\t ]*\(\$(_POST|_GET|_REQUEST|_SERVER\['HTTP_)/
	condition:
		any of them
}

rule webshell_php_double_eval_tiny {
	meta:
		description = "PHP webshell which probably hides the input inside an eval()ed obfuscated string"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "aabfd179aaf716929c8b820eefa3c1f613f8dcac"
		date = "2021/01/11"
	strings:
		$payload = /(\beval[\t ]*\([^)]|\bassert[\t ]*\([^)])/ nocase
	condition:
		#payload >= 2 and filesize < 800
}

rule TODO_webshell_generic_php_backticks {
	meta:
		description = "Generic PHP webshell which uses backticks directly on user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:

		$s0 = /`[\t ]*\$(_POST\[|_GET\[|_REQUEST\[|_SERVER\['HTTP_)/
	condition:
		// arg, can't search everywhere because lots of people write comments like "the value of `$_POST['action']`. Default false." :(
		filesize < 200 and any of them
}

rule webshell_generic_php_backticks_obfuscated {
	meta:
		description = "Generic PHP webshell which uses obfuscated backticks directly on user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "b2e234ee2906dd2ad0088b3b63901c28"
		date = "2021/01/07"
	strings:
		$s0 = "<?"
		$s1 = /echo[\t ]*\(?`\$/
	condition:
		all of them
}

rule webshell_generic_asp_eval {
	meta:
		description = "Generic ASP webshell which uses any eval/exec function directly on user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:
		$payload_and_input0 = "eval_r[\t ]*(Request(" nocase
		$payload_and_input1 = "eval[\t ]*request(" nocase
		$payload_and_input2 = "execute[\t ]*request(" nocase
		$payload_and_input4 = "ExecuteGlobal[\t ]*request(" nocase
	condition:
		any of them
}

rule webshell_generic_asp_tiny {
	meta:
		description = "Generic ASP webshell which uses any eval/exec function indirectly on user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:
		$input = "request." nocase
		$payload0 = "eval_r" fullword nocase
		$payload1 = "eval" fullword nocase
		$payload2 = "execute" fullword nocase
	condition:
		filesize < 500 and $input and any of ($payload*)
}

rule webshell_generic_jsp_tiny {
	meta:
		description = "Generic JSP webshell Tiny"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:
		$s0 = "Runtime.getRuntime().exec(" nocase
		$s1 = "request.getParameter" fullword nocase
	condition:
		filesize < 1000 and all of them
}

rule webshell_generic_jsp {
	meta:
		description = "Generic JSP webshell"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:
		$input = "request.getParameter" fullword
		$payload1 = "Runtime.getRuntime().exec(" 
		$payload2 = "ProcessBuilder" fullword
		$susp1 = "cmd" fullword
		$susp2 = "shell" fullword
		$susp3 = "download" fullword
		$susp4 = "upload" fullword
	condition:
		( filesize < 300000 ) and $input and any of ( $payload* ) and any of ( $susp* )
}

rule webshell_generic_jsp_processbuilder {
	meta:
		description = "Generic JSP webshell which uses processbuilder to execute user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:
		$exec = "ProcessBuilder" fullword
		$input = "request.getParameter" fullword
		$start = "start(" 
	condition:
		filesize < 2000 and all of them
}

rule webshell_generic_jsp_reflection {
	meta:
		description = "Generic JSP webshell which uses reflection to execute user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "0a20f64dbb5f4175cd0bb0a81f60546e12aba0d0"
		date = "2021/01/07"
	strings:
		$exec = ".invoke(" 
		$input = "request.get" 
		$class = "Class" 
	condition:
		filesize < 10000 and all of them
}

rule webshell_generic_jsp_classloader {
	meta:
		description = "Generic JSP webshell which uses classloader to execute user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "6b546e78cc7821b63192bb8e087c133e8702a377d17baaeb64b13f0dd61e2347"
		date = "2021/01/07"
	strings:
		$exec = "extends ClassLoader" 
		$input = "request.get"
		$class = "defineClass" fullword
	condition:
		filesize < 10000 and all of them
}

rule webshell_generic_jsp_encoded_shell {
	meta:
		description = "Generic JSP webshell which contains cmd or /bin/bash encoded in ascii ord"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:
		$s0 = /{ ?47, 98, 105, 110, 47, 98, 97, 115, 104/ 
		$s1 = /{ ?99, 109, 100}/ 
		$s2 = /{ ?99, 109, 100, 46, 101, 120, 101/ 
		$s3 = /{ ?47, 98, 105, 110, 47, 98, 97/ 
		$s4 = /{ ?106, 97, 118, 97, 46, 108, 97, 110/
		$s5 = /{ ?101, 120, 101, 99 }/
		$s6 = /{ ?103, 101, 116, 82, 117, 110/
	condition:
		any of them
}

rule webshell_php_in_htaccess {
	meta:
		description = "Use Apache .htaccess to execute php code inside .htaccess"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:
		$s0 = "AddType application/x-httpd-php .htaccess"
	condition:
		any of them
}

rule webshell_func_in_get {
	meta:
		description = "Webshell which sends eval/assert via GET"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "ce739d65c31b3c7ea94357a38f7bd0dc264da052d4fd93a1eabb257f6e3a97a6"
		hash = "d870e971511ea3e082662f8e6ec22e8a8443ca79"
		date = "2021/01/09"
	strings:
		$s0 = /\$_GET\[.{1,30}\]\(\$_GET\[/
		$s1 = /\$_POST\[.{1,30}\]\(\$_GET\[/
		$s2 = /\$_POST\[.{1,30}\]\(\$_POST\[/
		$s3 = /\$_GET\[.{1,30}\]\(\$_POST\[/
		$s4 = /\$_REQUEST\[.{1,30}\]\(\$_REQUEST\[/
		$s5 = /\$_SERVER\[HTTP_.{1,30}\]\(\$_SERVER\[HTTP_/
	condition:
		any of them
}

rule webshell_by_name {
	meta:
		description = "Webshells which contain their name, lousy rule ;)"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/09"
	strings:
		$s0 = "b374k shell"
		$s1 = "b374k/b374k"
		$s2 = "pwnshell"
		$s3 = "My PHP Shell - A very simple web shell"
		$s4 = "<title>My PHP Shell <?echo VERSION"
	condition:
		any of them
}

rule webshell_regeorg_aspx_csharp {
	meta:
		description = "Webshell regeorg aspx c# version"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		reference = "https://github.com/sensepost/reGeorg"
		hash = "c1f43b7cf46ba12cfc1357b17e4f5af408740af7ae70572c9cf988ac50260ce1"
		author = "Arnim Rupp"
		date = "2021/01/11"
	strings:
		$input = "Request.QueryString.Get" fullword nocase
		$s1 = "AddressFamily.InterNetwork" fullword nocase
		$s2 = "Response.AddHeader" fullword nocase
		$s3 = "Request.InputStream.Read" nocase
		$s4 = "Response.BinaryWrite" nocase
		$s5 = "Socket" nocase
		$aspx = "<%"
	condition:
		all of them
}

rule webshell_csharp {
	meta:
		description = "Webshell in c#"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "b6721683aadc4b4eba4f081f2bc6bc57adfc0e378f6d80e2bfa0b1e3e57c85c7"
		date = "2021/01/11"
	strings:
		$input_http = "Request." nocase
		$input_form1 = "<asp:" nocase
		$input_form2 = ".text" nocase
		$exec_proc1 = "new Process" nocase
		$exec_proc2 = "start(" nocase
		$exec_shell1 = "cmd.exe" nocase
		$exec_shell2 = "powershell.exe" nocase
	condition:
		filesize < 300000 and ( $input_http or all of ($input_form*) ) and all of ($exec_proc*) and any of ($exec_shell*)
}

rule webshell_sharpyshell {
	meta:
		description = "Webshell sharpyshell"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		reference = "https://github.com/antonioCoco/SharPyShell"
		date = "2021/01/11"
	strings:
		$input = "Request.Form" nocase
		$payload_reflection1 = "System.Reflection" nocase
		$payload_reflection2 = "Assembly.Load" nocase
		$payload_compile1 = "GenerateInMemory" nocase
		$payload_compile2 = "CompileAssemblyFromSource" nocase
		$payload_invoke = "Invoke" nocase
	condition:
		$input and ( all of ( $payload_reflection* ) or all of ( $payload_compile* ) ) and $payload_invoke
}
