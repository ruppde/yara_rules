# Arnims YARA rules

## capa2yara

See [capa2yara](capa2yara/README.md)

## Webshells

This is the dev repo for my webshell YARA rules in 
<https://github.com/Neo23x0/signature-base/blob/master/yara/gen_webshells.yar>

Since the rules are included in [Thor](<https://www.nextron-systems.com/thor/>) they are run on all Virustotal uploads with dozens of matches per day:

* <https://www.virustotal.com/gui/search/webshell_php_generic/comments>
* <https://www.virustotal.com/gui/search/webshell_php_generic_callback/comments>
* <https://www.virustotal.com/gui/search/webshell_php_base64_encoded_payloads/comments>
* <https://www.virustotal.com/gui/search/webshell_php_unknown_1/comments>
* <https://www.virustotal.com/gui/search/webshell_php_generic_eval/comments>
* <https://www.virustotal.com/gui/search/webshell_php_double_eval_tiny/comments>
* <https://www.virustotal.com/gui/search/webshell_php_obfuscated/comments>
* <https://www.virustotal.com/gui/search/webshell_php_obfuscated_encoding/comments>
* <https://www.virustotal.com/gui/search/webshell_php_obfuscated_encoding_mixed_dec_and_hex/comments>
* <https://www.virustotal.com/gui/search/webshell_php_obfuscated_tiny/comments>
* <https://www.virustotal.com/gui/search/webshell_php_obfuscated_str_replace/comments>
* <https://www.virustotal.com/gui/search/webshell_php_obfuscated_fopo/comments>
* <https://www.virustotal.com/gui/search/webshell_php_gzinflated/comments>
* <https://www.virustotal.com/gui/search/webshell_php_obfuscated_3/comments>
* <https://www.virustotal.com/gui/search/webshell_php_includer_eval/comments>
* <https://www.virustotal.com/gui/search/webshell_php_includer_tiny/comments>
* <https://www.virustotal.com/gui/search/webshell_php_dynamic/comments>
* <https://www.virustotal.com/gui/search/webshell_php_dynamic_big/comments>
* <https://www.virustotal.com/gui/search/webshell_php_encoded_big/comments>
* <https://www.virustotal.com/gui/search/webshell_php_generic_backticks/comments>
* <https://www.virustotal.com/gui/search/webshell_php_generic_backticks_obfuscated/comments>
* <https://www.virustotal.com/gui/search/webshell_php_by_string_known_webshell/comments>
* <https://www.virustotal.com/gui/search/webshell_php_strings_susp/comments>
* <https://www.virustotal.com/gui/search/webshell_php_in_htaccess/comments>
* <https://www.virustotal.com/gui/search/webshell_php_function_via_get/comments>
* <https://www.virustotal.com/gui/search/webshell_php_writer/comments>
* <https://www.virustotal.com/gui/search/webshell_asp_writer/comments>
* <https://www.virustotal.com/gui/search/webshell_asp_obfuscated/comments>
* <https://www.virustotal.com/gui/search/webshell_asp_generic_eval_on_input/comments>
* <https://www.virustotal.com/gui/search/webshell_asp_nano/comments>
* <https://www.virustotal.com/gui/search/webshell_asp_encoded/comments>
* <https://www.virustotal.com/gui/search/webshell_asp_encoded_aspcoding/comments>
* <https://www.virustotal.com/gui/search/webshell_asp_by_string/comments>
* <https://www.virustotal.com/gui/search/webshell_asp_sniffer/comments>
* <https://www.virustotal.com/gui/search/webshell_asp_generic_tiny/comments>
* <https://www.virustotal.com/gui/search/webshell_asp_generic/comments>
* <https://www.virustotal.com/gui/search/webshell_asp_generic_registry_reader/comments>
* <https://www.virustotal.com/gui/search/webshell_aspx_regeorg_csharp/comments>
* <https://www.virustotal.com/gui/search/webshell_csharp_generic/comments>
* <https://www.virustotal.com/gui/search/webshell_asp_runtime_compile/comments>
* <https://www.virustotal.com/gui/search/webshell_asp_sql/comments>
* <https://www.virustotal.com/gui/search/webshell_asp_scan_writable/comments>
* <https://www.virustotal.com/gui/search/webshell_jsp_regeorg/comments>
* <https://www.virustotal.com/gui/search/webshell_jsp_http_proxy/comments>
* <https://www.virustotal.com/gui/search/webshell_jsp_writer_nano/comments>
* <https://www.virustotal.com/gui/search/webshell_jsp_generic_tiny/comments>
* <https://www.virustotal.com/gui/search/webshell_jsp_generic/comments>
* <https://www.virustotal.com/gui/search/webshell_jsp_generic_base64/comments>
* <https://www.virustotal.com/gui/search/webshell_jsp_generic_processbuilder/comments>
* <https://www.virustotal.com/gui/search/webshell_jsp_generic_reflection/comments>
* <https://www.virustotal.com/gui/search/webshell_jsp_generic_classloader/comments>
* <https://www.virustotal.com/gui/search/webshell_jsp_generic_encoded_shell/comments>
* <https://www.virustotal.com/gui/search/webshell_jsp_netspy/comments>
* <https://www.virustotal.com/gui/search/webshell_jsp_by_string/comments>
* <https://www.virustotal.com/gui/search/webshell_jsp_input_upload_write/comments>
* <https://www.virustotal.com/gui/search/webshell_generic_os_strings/comments>
* <https://www.virustotal.com/gui/search/webshell_in_image/comments>
