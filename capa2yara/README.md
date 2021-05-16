# capa2yara

Rules from Fireeyes https://github.com/fireeye/capa-rules converted to YARA using capa2yara.py (not published yet).

## Advantages:
* YARA is lots faster than CAPA so it's possible to search with these rules on millions of files
* Many tools have integration for YARA rules, just throw them in. 
* The rules and strings can be reused for creating your own YARA rules

## Disadvantages:
* These are less rules than capa (because not all fit into YARA, see stats below) and is less precise because e.g. capas function scopes are applied to the whole file.
* Some rules are incomplete because an optional branch was not supported by YARA. These rules are marked in a comment in meta: (search for "incomplete").

## Stats
* Converted rules              : 403
* Among those are incomplete   : 20
* Unconverted rules            : 149

## Meta data
Rule authors and license stay the same.

att&ck and MBC tags are put into YARA rule tags. All rules are tagged with "CAPA" for easy filtering.

The date = in meta: is the date of converting (there is no date in capa rules).

Minimum YARA version is 3.8.0 plus PE module.

## TODO

All rules which couldn't be converted are in [here](./unsupported_capa_rules.yml)

These are technically possible but not done yet:
* "2 or more" for strings: e.g.:
* - https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-direct-ftp-information.yml 
* - https://github.com/fireeye/capa-rules/blob/master/collection/browser/gather-firefox-profile-information.yml
* count(string    (1 rule: /executable/subfile/pe/contain-an-embedded-pe-file.yml)
* count(match( could be done by creating the referenced rule a 2nd time with the condition, that it hits x times (only 1 rule: ./anti-analysis/anti-disasm/contain-anti-disasm-techniques.yml)
* it would be technically possible to get the "basic blocks" working, but the rules contain mostly other non supported statements in there => not worth the effort.



## Author
arnim rupp
