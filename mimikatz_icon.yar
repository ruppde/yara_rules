rule HKTL_mimikatz_icon {
    meta:
        description = "Detects mimikatz kiwi icon in PE file"
        reference = "https://www.virustotal.com/gui/search/main_icon_dhash%253Ae1cd969ac674f863/files"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        author = "Arnim Rupp"
        date = "2023-02-18"
        score = 65
        hash1 = "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1"
        hash2 = "1c3f584164ef595a37837701739a11e17e46f9982fdcee020cf5e23bad1a0925"
        hash3 = "c6bb98b24206228a54493274ff9757ce7e0cbb4ab2968af978811cc4a98fde85"
        hash4 = "721d3476cdc655305902d682651fffbe72e54a97cd7e91f44d1a47606bae47ab"
        hash5 = "c0f3523151fa307248b2c64bdaac5f167b19be6fccff9eba92ac363f6d5d2595"
    strings:
        // random part grabbed from raw mimikatz kiwi icon in binary
        $kiwi = {5a c4 bf ff 52 c4 c0 ff 5b c7 c2 ff 68 d4 cc ff 6b d6 cb ff 81 e1 d7 ff 85 e5 da ff 85 e7 db ff 8b ea dd ff 9d f0 e5 ff a3 f1 e7 ff a5 ee e5 ff ad f1 ea ff aa f0 e9 ff bc ff f7 ff 73 d2 d8 ff}
    condition:
        uint16(0) == 0x5A4D and 
        $kiwi 
        // filesize not limited because some files like ab96a7267f4ddb5b2fc4f6dc47a95a2dbc7f98559581eedabdd8edcbfb908a68 have 100MB+
}
