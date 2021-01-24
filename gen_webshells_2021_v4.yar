// work in progress!! still some fp!

// rationale behind the rules:
// * a webshell must always execute some kind of payload (in $payload*). the payload is either:
// ** direct php function like exec or
// ** indirect via eval, self defined functions, callbacks, ...
// * a webshell must always have some way to get the attackers input, e.g. for PHP in $_GET, php://input or $_SERVER (HTTP for headers). these are in the strings $input* (... if they're not obfuscated in some payload, then we look for payload + obfuscation)
// * some additional conditions might be added to reduce false positves


////        ____  _   _ ____    _
////       |  _ \| | | |  _ \  (_)___    ___ _ __ __ _ _____   _
////       | |_) | |_| | |_) | | / __|  / __| '__/ _` |_  / | | |
////       |  __/|  _  |  __/  | \__ \ | (__| | | (_| |/ /| |_| |
////       |_|   |_| |_|_|     |_|___/  \___|_|  \__,_/___|\__, |
////                                                       |___/


private rule php_false_positive {
	meta:
		description = "PHP false positives"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/14"
	strings:
		$ = "eval(\"return [$serialised_paramete" // elgg
	condition:
		any of them
}

/*
TODO: raus?
global private rule exclude_false_positives {
	meta:
		description = "PHP false positives"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/14"
	condition:
		not php_false_positive
}
*/

private rule capa_php {
	meta:
		description = "PHP tags. Use only if needed to reduce false positives because it won't find includer shells anymore. (e.g. <? include 'webshell.txt'?> and the payload in webshell.txt without <? )"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/14"
	strings:
		$ = "<?"
	condition:
		any of them
}

private rule capa_php_new {
	meta:
		description = "PHP tags, only <?= and <?php. Use only if needed to reduce false positives because it won't find includer shells anymore. (e.g. <? include 'webshell.txt'?> and the payload in webshell.txt without <? )"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/14"
	strings:
		$ = "<?="
		$ = "<?php" nocase
	condition:
		any of them
}

private rule capa_php_input {
	meta:
		description = "PHP user input methods, in plain text"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/14"
	strings:
		$ = "php://input"
		$ = "file_get_contents"
		$ = "_GET["
		$ = "_POST["
		$ = "_REQUEST["
		// PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
		$ = "_SERVER['HTTP_"
		$ = "_SERVER[\"HTTP_"
		$ = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/
	condition:
		any of them
}

private rule capa_php_payload {
	meta:
		description = "PHP methods for executing OS commands or eval, in plain text"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/14"
	strings:
		// \([^)] to avoid matching on e.g. eval() in comments
		$ = /\beval[\t ]*\([^)]/ nocase
		$ = /\bexec[\t ]*\([^)]/ nocase
		$ = /\bshell_exec[\t ]*\([^)]/ nocase
		$ = /\bpassthru[\t ]*\([^)]/ nocase
		$ = /\bsystem[\t ]*\([^)]/ nocase
		$ = /\bpopen[\t ]*\([^)]/ nocase
		$ = /\bproc_open[\t ]*\([^)]/ nocase
		$ = /\bpcntl_exec[\t ]*\([^)]/ nocase
		$ = /\bassert[\t ]*\([^)]/ nocase
		$ = /\bpreg_replace[\t ]*\(.{1,1000}\/e/ nocase
		$ = /\bcreate_function[\t ]*\([^)]/ nocase
		$ = /\bReflectionFunction[\t ]*\([^)]/ nocase
		// TODO: $_GET['func_name']($_GET['argument']);
		// TODO: $a(
		// TODO backticks
	condition:
		any of them
}

private rule capa_php_callback {
	meta:
		description = "PHP functions which accept callback functions to execute, in plain text"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/14"
	strings:
		$ = /\bob_start[\t ]*\([^)]/ nocase
		$ = /\barray_diff_uassoc[\t ]*\([^)]/ nocase
		$ = /\barray_diff_ukey[\t ]*\([^)]/ nocase
		$ = /\barray_filter[\t ]*\([^)]/ nocase
		$ = /\barray_intersect_uassoc[\t ]*\([^)]/ nocase
		$ = /\barray_intersect_ukey[\t ]*\([^)]/ nocase
		$ = /\barray_map[\t ]*\([^)]/ nocase
		$ = /\barray_reduce[\t ]*\([^)]/ nocase
		$ = /\barray_udiff_assoc[\t ]*\([^)]/ nocase
		$ = /\barray_udiff_uassoc[\t ]*\([^)]/ nocase
		$ = /\barray_udiff[\t ]*\([^)]/ nocase
		$ = /\barray_uintersect_assoc[\t ]*\([^)]/ nocase
		$ = /\barray_uintersect_uassoc[\t ]*\([^)]/ nocase
		$ = /\barray_uintersect[\t ]*\([^)]/ nocase
		$ = /\barray_walk_recursive[\t ]*\([^)]/ nocase
		$ = /\barray_walk[\t ]*\([^)]/ nocase
		$ = /\bassert_options[\t ]*\([^)]/ nocase
		$ = /\buasort[\t ]*\([^)]/ nocase
		$ = /\buksort[\t ]*\([^)]/ nocase
		$ = /\busort[\t ]*\([^)]/ nocase
		$ = /\bpreg_replace_callback[\t ]*\([^)]/ nocase
		$ = /\bspl_autoload_register[\t ]*\([^)]/ nocase
		$ = /\biterator_apply[\t ]*\([^)]/ nocase
		$ = /\bcall_user_func[\t ]*\([^)]/ nocase
		$ = /\bcall_user_func_array[\t ]*\([^)]/ nocase
		$ = /\bregister_shutdown_function[\t ]*\([^)]/ nocase
		$ = /\bregister_tick_function[\t ]*\([^)]/ nocase
		$ = /\bset_error_handler[\t ]*\([^)]/ nocase
		$ = /\bset_exception_handler[\t ]*\([^)]/ nocase
		$ = /\bsession_set_save_handler[\t ]*\([^)]/ nocase
		$ = /\bsqlite_create_aggregate[\t ]*\([^)]/ nocase
		$ = /\bsqlite_create_function[\t ]*\([^)]/ nocase
	condition:
		any of them
}

private rule capa_php_include {
	meta:
		description = "PHP methods for including code from other files, in plain text"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/14"
	strings:
		$ = /\binclude[_once]?[\t ]*[('"]/ nocase
		$ = /\brequire[_once]?[\t ]*[('"]/ nocase
	condition:
		capa_php and any of them
}


rule php_webshell_generic_tiny {
	meta:
		description = "php webshell having some kind of input and some kind of payload. restricted to small files or would give lots of false positives"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/14"
	condition:
		filesize < 1000 
		and capa_php_input
		and capa_php_payload
		and not php_false_positive
}

rule php_webshell_generic_callback_tiny {
	meta:
		description = "php webshell having some kind of input and using a callback to execute the payload. restricted to small files or would give lots of false positives"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/14"
	condition:
		filesize < 1000 
		and capa_php_input
		and capa_php_callback
		and not php_false_positive
}

rule php_webshell_generic_nano_input {
	meta:
		description = "php webshell having some kind of input and whatever mechanism to execute it. restricted to small files or would give lots of false positives"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "b492336ac5907684c1b922e1c25c113ffc303ffbef645b4e95d36bc50e932033"
		date = "2021/01/13"
	condition:
		filesize < 100 
		and ( capa_php_input or capa_php_callback )
}

rule php_webshell_generic_nano_payload_or_callback {
	meta:
		description = "php webshell having some method to execute code, no check where it comes from. restricted to small files or would give lots of false positives"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/14"
	condition:
		filesize < 100 and ( capa_php_payload or capa_php_callback )
}

rule php_webshell_base64_encoded_payloads {
	meta:
		description = "php webshell containg base64 encoded payload"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:
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
		filesize < 300000 and capa_php and $decode and any of ( $payload* )
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
		description = "Generic PHP webshell which uses any eval/exec function in the same line with user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "a61437a427062756e2221bfb6d58cd62439d09d9"
		date = "2021/01/07"
	strings:
		$s0 = /(exec|shell_exec|passthru|system|popen|proc_open|pcntl_exec|eval|assert)[\t ]*(stripslashes\()?[\t ]*(trim\()?[\t ]*\(\$(_POST|_GET|_REQUEST|_SERVER\[['"]HTTP_)/
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
		filesize < 800
		and capa_php 
		and #payload >= 2
}

private rule capa_php_obfuscation_multi {
	meta:
		description = "PHP obfuscation functions which have to be used multiple times, e.g. for each character"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/14"
	strings:
		$o1 = "ord" fullword nocase
		$o2 = "chr" fullword nocase
		// not excactly a string function but also often used in obfuscation
		$o3 = "goto" fullword nocase
		$o4 = "\\x1"
		$o5 = "\\x2"
		// just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
		$o6 = "\\61"
		$o7 = "\\44"
		$o8 = "\\112"
		$o9 = "\\120"
	condition:
		( #o1+#o2+#o3+#o4+#o5+#o6+#o7+#o8+#o9 ) > 20
}

private rule capa_php_obfuscation_single {
	meta:
		description = "PHP obfuscation functions which can be used on multiple strings"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/14"
	strings:
		$ = "gzinflate" fullword nocase
		$ = "gzuncompress" fullword nocase
		$ = "gzdecode" fullword nocase
		$ = "base64_decode" fullword nocase
		$ = "pack" fullword nocase
	condition:
		any of them
}

rule webshell_php_obfuscated {
	meta:
		description = "PHP webshell obfuscated"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/12"
	condition:
		filesize < 700KB 
		and capa_php 
		and capa_php_obfuscation_multi
		and capa_php_payload
}

rule webshell_php_obfuscated_str_replace {
	meta:
		description = "PHP webshell which eval()s obfuscated string"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/12"
	strings:
		$payload1 = "str_replace" fullword ascii
		$payload2 = "function" fullword ascii
		//$hex  = "\\x"
		$chr1  = "\\61"
		$chr2  = "\\112"
		$chr3  = "\\120"
	condition:
		filesize < 10KB 
		and capa_php 
		and any of ( $payload* ) 
		and ( #chr1 > 10 or #chr2 > 10 or #chr3 > 10 )
}

rule webshell_php_obfuscated_fopo {
	meta:
		description = "PHP webshell which eval()s obfuscated string"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "fbcff8ea5ce04fc91c05384e847f2c316e013207"
		date = "2021/01/12"
	strings:
		$php = "<?"
		$payload = /(\beval[\t ]*\([^)]|\bassert[\t ]*\([^)])/ nocase
		$base64_eval1 =";@eval(" base64
		$base64_eval2 =";@assert(" base64
	condition:
		$php and $payload and 1 of ( $base64_eval* )
}

private rule capa_os_commands {
	meta:
		description = "typical webshell windows commands"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/14"
	strings:
		$ = "net localgroup administrators" nocase
		$ = "net user" nocase
		$ = "cmd /c" nocase
		// linux stuff, case sensitive:
		$ = "/bin/bash"
		$ = "/bin/sh" 
		$ = "/etc/shadow"
		$ = "/etc/passwd"
		$ = "/etc/ssh/sshd_config"
		$ = "/../../etc/"
	condition:
		any of them
}

rule webshell_strings_php {
	meta:
		description = "typical webshell strings, clear hit"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/12"
	strings:
		$ = "\"ht\".\"tp\".\":/\""
		$ = "\"ht\".\"tp\".\"s:"
		// crawler avoid string
		$ = "bot|spider|crawler|slurp|teoma|archive|track|snoopy|java|lwp|wget|curl|client|python|libwww"
		$ = "'ev'.'al'" nocase
		$ = "<?php eval(" nocase
		$ = "eval/*" nocase
		$ = "assert/*" nocase
		// <?=($_=@$_GET[2]).@$_($_GET[1])?>
		$ = /@\$_GET\[\d\]\)\.@\$_\(\$_GET\[\d\]\)/
		$ = /@\$_GET\[\d\]\)\.@\$_\(\$_POST\[\d\]\)/
		$ = /@\$_POST\[\d\]\)\.@\$_\(\$_GET\[\d\]\)/
		$ = /@\$_POST\[\d\]\)\.@\$_\(\$_POST\[\d\]\)/
		$ = /@\$_REQUEST\[\d\]\)\.@\$_\(\$_REQUEST\[\d\]\)/
		$ = "'ass'.'ert'" nocase
		$ = "${'_'.$_}['_'](${'_'.$_}['__'])"
		$ = "array(\"find config.inc.php files\", \"find / -type f -name config.inc.php\")"
		$ = "$_SERVER[\"\\x48\\x54\\x54\\x50"
		$ = "'s'.'s'.'e'.'r'.'t'" nocase
		$ = "'P'.'O'.'S'.'T'"
		$ = "'G'.'E'.'T'"
		$ = "'R'.'E'.'Q'.'U'"
	condition:
		filesize < 700KB 
		and capa_php 
		and any of them
}

rule webshell_strings_php_susp {
	meta:
		description = "typical webshell strings, suspicious"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/12"
	strings:
		$ = "eval(\"?>\"" nocase
	condition:
		filesize < 700KB 
		and capa_php 
		and ( 2 of them or ( 1 of them and capa_php_input ) )
}

rule webshell_strings_asp {
	meta:
		description = "typical webshell strings"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/12"
	strings:
		$asp = "<%"
		$s1 = "net localgroup administrators" nocase
		$take_two1 = "net user" nocase
		$take_two2 = "/add" nocase
	condition:
		filesize < 300KB and $asp and ( 1 of ( $s* ) or 2 of ( $take_two* ) )
}

rule webshell_php_gzinflated {
	meta:
		description = "PHP webshell which directly eval()s obfuscated string"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/12"
	strings:
		$php = "<?"
		$payload1 = "eval(gzinflate(base64_decode("
		$payload2 = "eval(\"?>\".gzinflate(base64_decode("
		$payload3 = "eval(gzuncompress(base64_decode("
		$payload4 = "eval(\"?>\".gzuncompress(base64_decode("
		$payload5 = "eval(gzdecode(base64_decode("
		$payload6 = "eval(\"?>\".gzdecode(base64_decode("
		$payload7 = "eval(base64_decode("
		$payload8 = "eval(pack("
	condition:
		$php and 1 of ( $payload* )
}

rule webshell_php_obfuscated_2 {
	meta:
		description = "PHP webshell which eval()s obfuscated string"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "1d4b374d284c12db881ba42ee63ebce2759e0b14"
		date = "2021/01/13"
	strings:
		// <?php function vUMmFr($MkUOmK) { $MkUOmK=gzinflate(base64_decode($MkUOmK)); for($i=0;$i<strlen($MkUOmK);$i++) { $MkUOmK[$i] = chr(ord($MkUOmK[$i])-1); } return $MkUOmK; }eval
		$php = "<?"
		$obf1 = "function" fullword
		$obf2 = "base64_decode" fullword
		$obf3 = "chr" fullword
		$obf4 = "ord" fullword
		$payload1 = "eval" fullword
		$payload2 = "assert" fullword
	condition:
		$php and 1 of ( $payload* ) and 
			$obf1 in (0..500) and
			$obf2 in (0..500) and
			$obf3 in (0..500) and
			$obf4 in (0..500) 
}

// TODO: findet ./webshell-sample/php/ab771bb715710892b9513b1d075b4e2c0931afb6.php nicht?
rule webshell_php_includer {
	meta:
		description = "PHP webshell which eval()s another included file"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "3a07e9188028efa32872ba5b6e5363920a6b2489"
		date = "2021/01/13"
	strings:
		$payload1 = "eval" fullword
		$payload2 = "assert" fullword
		$include1 = "$_FILE"
		$include2 = "include"
	condition:
		filesize < 200 and capa_php and 1 of ( $payload* ) and  1 of ( $include* )
}

/*

TODO: slowdown
rule webshell_php_dynamix {
	meta:
		description = "PHP webshell using $a($code) for eval"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "65dca1e652d09514e9c9b2e0004629d03ab3c3ef"
		date = "2021/01/13"
	strings:
		$php = "<?"
		$dynamic = /\$[a-zA-Z0-9_]{1,30}\(/
	condition:
		filesize < 200 and $php and $dynamic
}
*/

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

rule webshell_by_string_php {
	meta:
		description = "PHP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/09"
	strings:
		$ = "b374k shell"
		$ = "b374k/b374k"
		$ = "\"b374k"
		$ = "$b374k"
		$ = "b374k "
		$ = "pwnshell"
		$ = "reGeorg" fullword
		$ = "Georg says, 'All seems fine" fullword
		$ = "My PHP Shell - A very simple web shell"
		$ = "<title>My PHP Shell <?echo VERSION"
		$ = "F4ckTeam" fullword
	condition:
		filesize < 100KB and capa_php and any of them
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


////        _    ____  ____           __     ______ ____   ____ ____  ___ ____ _____ 
////       / \  / ___||  _ \     _    \ \   / / __ ) ___| / ___|  _ \|_ _|  _ \_   _|
////      / _ \ \___ \| |_) |  _| |_   \ \ / /|  _ \___ \| |   | |_) || || |_) || |  
////     / ___ \ ___) |  __/  |_   _|   \ V / | |_) |__) | |___|  _ < | ||  __/ | |  
////    /_/   \_\____/|_|       |_|      \_/  |____/____/ \____|_| \_\___|_|    |_|  
                                                                             


rule webshell_generic_asp_eval {
	meta:
		description = "Generic ASP webshell which uses any eval/exec function directly on user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:
		$payload_and_input0 = /eval_r[\t ]*\(Request\(/ nocase
		$payload_and_input1 = /eval[\t ]*request\(/ nocase
		$payload_and_input2 = /execute[\t ]*request\(/ nocase
		$payload_and_input4 = /ExecuteGlobal[\t ]*request\(/ nocase
	condition:
		any of them
}

rule webshell_asp_nano {
	meta:
		description = "Generic ASP webshell which uses any eval/exec function"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/13"
	strings:
		$asp = "<%"
		$payload0 = "eval_r" fullword nocase
		$payload1 = "eval" fullword nocase
		$payload2 = "execute" fullword nocase
		$payload3 = "WSCRIPT.SHELL" fullword nocase
		$payload4 = "Scripting.FileSystemObject" fullword nocase
		$payload5 = /ExecuteGlobal/ fullword nocase
		$payload6 = "cmd /c" nocase
		$payload7 = "cmd.exe" nocase
	condition:
		$asp and filesize < 200 and any of ($payload*)
}

/*
TODO:
rule webshell_vbscript_nano {
	meta:
		description = "Generic very small VBscript webshell "
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "1c7fbad3c4ca83a70efcd19f34838cbde902c631"
		date = "2021/01/13"
	strings:
		$vb1 = "VBScript.Encode"
		$vb2 = "<%"
		$payload0 = "^" 
	condition:
		filesize < 100 and any of ($payload*) and all of ( $vb* )
}
*/

rule webshell_asp_string {
	meta:
		description = "Generic ASP webshell strings"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/13"
		hash ="f72252b13d7ded46f0a206f63a1c19a66449f216"
	strings:
		//$asp = "<%"
		$s1 = "tseuqer lave"
		$s2 = ":eval request("
		$s3 = ":eval request("
	condition:
		// not checking $asp
		any of ($s*)
}

rule webshell_generic_asp_tiny {
	meta:
		description = "Generic ASP webshell which uses any eval/exec function indirectly on user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:
		$asp = "<%"
		$input = "request" nocase
		$payload0 = "eval_r" fullword nocase
		$payload1 = "eval" fullword nocase
		$payload2 = "execute" fullword nocase
		$payload3 = "WSCRIPT.SHELL" fullword nocase
		$payload4 = "Scripting.FileSystemObject" fullword nocase
	condition:
		$asp and filesize < 500 and $input and any of ($payload*)
}


////                 _ ____  ____                ////
////                | / ___||  _ \               ////
////             _  | \___ \| |_) |              ////
////            | |_| |___) |  __/               ////
////             \___/|____/|_|                  ////



private rule capa_jsp {
	meta:
		description = "capa JSP tag"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/24"
	strings:
		$ = "<%"
		$ = "<jsp:"
	condition:
		any of them
} 

private rule capa_jsp_input {
	meta:
		description = "capa JSP input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/24"
	strings:
		// request.getParameter
		$input1 = "getParameter" fullword
		// request.getHeaders
		$input2 = "getHeaders" fullword
		// request.getInputStream
		$input3 = "getInputStream" fullword
	condition:
		any of them
} 

rule webshell_regeorg_jsp {
	meta:
		description = "Webshell regeorg JSP version"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		reference = "https://github.com/sensepost/reGeorg"
		hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
		author = "Arnim Rupp"
		date = "2021/01/24"
	strings:
		$ = "request" fullword
		$ = "getHeader" fullword
		$ = "X-CMD" fullword
		$ = "X-STATUS" fullword
		$ = "socket" fullword
		$ = "FORWARD" fullword
	condition:
		filesize < 300KB and capa_jsp and all of them
}

rule webshell_jsp_http_proxy {
	meta:
		description = "Webshell JSP HTTP proxy"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		hash = "2f9b647660923c5262636a5344e2665512a947a4"
		author = "Arnim Rupp"
		date = "2021/01/24"
	strings:
		$ = "OutputStream" fullword
		$ = "InputStream" 
		$ = "BufferedReader" fullword
		$ = "HttpRequest" fullword
		$ = "openConnection" fullword
		$ = "getParameter" fullword
	condition:
		filesize < 10KB and capa_jsp and all of them
}
rule webshell_jsp_writer_nano {
	meta:
		description = "JSP file writer"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/24"
	strings:
		$payload1 = ".write"
		$payload2 = "getBytes" fullword
		// request.getParameter
		$input1 = "getParameter" fullword
		// request.getHeaders
		$input2 = "getHeaders" fullword
		// request.getInputStream
		$input3 = "getInputStream" fullword
	condition:
		filesize < 200 and 2 of ( $payload* ) and 1 of ( $input* )
}


rule webshell_generic_jsp_tiny {
	meta:
		description = "Generic JSP webshell Tiny"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:
		$payload1 = "ProcessBuilder" fullword
		$payload2 = "URLClassLoader" fullword
		// Runtime.getRuntime().exec(
		$payload_rt1 = "Runtime" fullword
		$payload_rt2 = "getRuntime" fullword
		$payload_rt3 = "exec" fullword
	condition:
		filesize < 2000 and 
		capa_jsp_input and
		( 
			1 of ( $payload* ) or
			all of ( $payload_rt* )
		)
}

rule webshell_generic_jsp {
	meta:
		description = "Generic JSP webshell"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:
		$input = "request.getParameter" fullword
		$payload1 = "ProcessBuilder" fullword
		// Runtime.getRuntime().exec(
		$payload_rt1 = "Runtime" fullword
		$payload_rt2 = "getRuntime" fullword
		$payload_rt3 = "exec" fullword
		$susp1 = "cmd" fullword
		$susp2 = "shell" fullword
		$susp3 = "download" fullword
		$susp4 = "upload" fullword
	condition:
		filesize < 300KB and 
		any of ( $susp* ) and
		$input and  
		( 
			1 of ( $payload* ) or
			all of ( $payload_rt* )
		)
}

rule webshell_generic_jsp_base64 {
	meta:
		description = "Generic JSP webshell with base64 encoded payload"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/24"
	strings:
		$payload1 = "Runtime" base64
		$payload2 = "getRuntime" base64
		$payload3 = "exec"  base64
		$se       = "ScriptEngineFactory"
	condition:
		filesize < 300000 and (
			all of ( $payload* ) or
			$se
		)

}

rule webshell_generic_jsp_processbuilder {
	meta:
		description = "Generic JSP webshell which uses processbuilder to execute user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/07"
	strings:
		$exec = "ProcessBuilder" fullword
		$start = "start" fullword
	condition:
		filesize < 2000 and capa_jsp_input and $exec and $start
}

rule webshell_generic_jsp_reflection {
	meta:
		description = "Generic JSP webshell which uses reflection to execute user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "0a20f64dbb5f4175cd0bb0a81f60546e12aba0d0"
		date = "2021/01/07"
	strings:
		$exec = "invoke" fullword
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

rule webshell_jsp_netspy {
	meta:
		description = "JSP netspy webshell"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/24"
		hash = "94d1aaabde8ff9b4b8f394dc68caebf981c86587"
		hash = "3870b31f26975a7cb424eab6521fc9bffc2af580"
	strings:
		$scan1 = "scan" nocase
		$scan2 = "port" nocase
		$scan3 = "web" fullword nocase
		$scan4 = "proxy" fullword nocase
		$scan5 = "http" fullword nocase
		$scan6 = "https" fullword nocase
		$write1 = "os.write" fullword
		$write2 = "FileOutputStream" fullword
		$write3 = "PrintWriter" fullword
	condition:
		filesize < 30000 and 4 of ( $scan* ) and 1 of ( $write* ) and capa_jsp_input
}

rule webshell_by_string_jsp {
	meta:
		description = "JSP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/09"
	strings:
		$ = "<title>Boot Shell</title>"
		$ = "String oraPWD=\""
		$ = "Owned by Chinese Hackers!"
		$ = "AntSword JSP"
		$ = "JSP Webshell</"
		$ = "motoME722remind2012"
		$ = "EC(getFromBase64(toStringHex(request.getParameter(\"password"
		$ = "http://jmmm.com/web/index.jsp"
		$ = "list.jsp = Directory & File View"
		$ = "jdbcRowSet.setDataSourceName(request.getParameter("
		$ = "Mr.Un1k0d3r RingZer0 Team"
	condition:
		filesize < 100KB and capa_jsp and any of them
}

rule webshell_input_password_write {
	meta:
		description = "JSP uploader with password"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/24"
	strings:
		$pwd1 = "password" nocase
		$pwd2 = "pwd" nocase
		$write1 = "os.write" fullword
		$write2 = "FileOutputStream" fullword
		$write3 = "PrintWriter" fullword
	condition:
		filesize < 10000 and 1 of ( $pwd* ) and 1 of ( $write* ) and capa_jsp_input
}

rule webshell_input_upload_write {
	meta:
		description = "JSP uploader which gets input, writes files and contains \"upload\""
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/24"
	strings:
		$upload = "upload" nocase
		$write1 = "os.write" fullword
		$write2 = "FileOutputStream" fullword
		$input1 = "getParameter" fullword
		// request.getHeaders
		$input2 = "getHeaders" fullword
		// request.getInputStream
		$input3 = "getInputStream" fullword
	condition:
		filesize < 10000 and $upload and 1 of ( $write* ) and 1 of ( $input* ) 
}

/* hunting rule, probaly lots of FP
rule webshell_input_password_sql {
	meta:
		description = "JSP SQL tool with password"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/24"
	strings:
		$pwd1 = "password" nocase
		$pwd2 = "pwd" nocase
		$sql1 = "jdbc" nocase
		$sql2 = "select" fullword nocase
		$sql3 = "sql" fullword nocase
		$sql4 = "createStatement" fullword nocase

	condition:
		filesize < 20000 and 1 of ( $pwd* ) and 3 of ( $sql* ) and capa_jsp_input
}
*/


rule webshell_input_write_nano {
	meta:
		description = "JSP uploader with which contains upload"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/01/24"
	strings:
		$write1 = "os.write" fullword
		$write2 = "FileOutputStream" fullword
		$input1 = "getParameter" fullword
		// request.getHeaders
		$input2 = "getHeaders" fullword
		// request.getInputStream
		$input3 = "getInputStream" fullword
	condition:
		filesize < 1500 and 1 of ( $write* ) and 1 of ( $input* ) 
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

