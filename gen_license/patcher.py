"""
FortiGate patcher v1.0 (For newer versions [FGTVM64 v7.4.3?])
Disable integrity checks
Copyright (C) 2024  CataLpa

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import re
import sys

def gen_regex_from_sig(sig):
    regex = ""
    _split_sig = sig.split()
    i = 0
    while True:
        if i >= len(_split_sig):
            break
        if _split_sig[i] != "??":
            regex += "\\x"
            regex += _split_sig[i]
            i += 1
        elif _split_sig[i] == "??":
            _dyn_byte_count = 1
            while True:
                i += 1
                if i >= len(_split_sig):
                    break
                if _split_sig[i] == "??":
                    _dyn_byte_count += 1
                else:
                    break
            regex += ".{%d}" % _dyn_byte_count
    return regex

def find_matches(pattern, data):
    matches = []
    for match in re.finditer(pattern, data):
        start = match.start()
        end = match.end()
        match_data = {
            'match': match.group(),
            'start': start,
            'end': end
        }
        matches.append(match_data)
    return matches

def do_patch(data, pos, codes):
    for c in codes:
        data[pos] = c
        pos += 1

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("[*] Usage: python3 %s init" % sys.argv[0])
        exit(0)
    
    init_file = sys.argv[1]
    patch_pattern1 = gen_regex_from_sig("55 BE ?? ?? ?? ?? BF ?? ?? ?? ?? 48 89 E5 41 54 48 ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 ?? ?? 31 C0 E8 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74")
    patch_pattern2 = gen_regex_from_sig("44 8B 07 8B 06 44 0F ?? ?? ?? 0F B7 ?? ?? 44 0F ?? ?? ?? 0F B7 ?? ?? 41 39 C0")
    patch_pattern3 = gen_regex_from_sig("55 48 89 E5 41 57 49 89 F7 41 56 49 89 FE BF ?? ?? ?? ?? 41 55 41 54 53 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 ?? 49 89 C4 E8 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 49 89 C5 48 85 C0 74")
    code1 = [0xC3]    # ret
    code2 = [0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90, 0x90, 0x90]    # mov eax, 0; ret
    code3 = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]    # mov eax, 1; ret
    
    with open(init_file, "rb") as f:
        data = f.read()
    
    p1 = find_matches(patch_pattern1.encode(), data)
    p2 = find_matches(patch_pattern2.encode(), data)
    p3 = find_matches(patch_pattern3.encode(), data)

    if (len(p1) != 1) or (len(p2) != 1) or (len(p3) != 1):
        print("[-] Error: Too many results returned")
        exit(0)
    try:
        print("[*] Patching")
        buffer = list(data)
        do_patch(buffer, p1[0].get("start"), code1)
        do_patch(buffer, p2[0].get("start"), code2)
        do_patch(buffer, p3[0].get("start"), code3)

        with open("./init.patched", "wb") as f:
            f.write(bytes(buffer))
        
        print("[+] Patched!")
    except Exception as e:
        print("[-] Error: %s" % e)
