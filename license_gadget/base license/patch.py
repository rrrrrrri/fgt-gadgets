"""
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
import os
import re
import sys
import gzip
import platform
import subprocess
from capstone import *


def gen_regex_from_sig(code_pattern: str) -> str:
    """
    The gen_regex_from_sig function takes a code pattern and
    converts it into a regular expression
    :param code_pattern: code pattern
    :return: regular expression
    """
    regex = ""
    _split_sig = code_pattern.split()
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


def find_matches(pattern: bytes, source_data: bytes) -> list:
    """
    The find_matches function perform search on source_data
    :param pattern: regular expression
    :param source_data: data to be searched
    :return: result
    """
    matches = []
    for match in re.finditer(pattern, source_data):
        start = match.start()
        end = match.end()
        match_data = {
            'match': match.group(),
            'start': start,
            'end': end
        }
        matches.append(match_data)
    return matches


def do_patch(source_data: list, pos: int, codes: list) -> None:
    """
    The do_patch function perform patch on source_data
    :param source_data: data to be patched
    :param pos: start from pos
    :param codes: target instructions
    :return: None
    """
    for c in codes:
        source_data[pos] = c
        pos += 1


def patch_init(filepath: str) -> bool:
    """
    The patch_init function perform patch on "init"
    :param filepath: init filepath
    :return: bool
    """
    print("[+] Patching init")
    patch_pattern1 = gen_regex_from_sig(
        "55 BE ?? ?? ?? ?? BF ?? ?? ?? ?? 48 89 E5 41 54 48 ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 ?? ?? 31 C0 E8 "
        "?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74")
    patch_pattern2 = gen_regex_from_sig("44 8B 07 8B 06 44 0F ?? ?? ?? 0F B7 ?? ?? 44 0F ?? ?? ?? 0F B7 ?? ?? 41 39 C0")
    patch_pattern3 = gen_regex_from_sig(
        "55 48 89 E5 41 57 49 89 F7 41 56 49 89 FE BF ?? ?? ?? ?? 41 55 41 54 53 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 "
        "74 ?? 49 89 C4 E8 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 49 89 C5 48 85 C0 74")
    code1 = [0xC3]  # ret
    code2 = [0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90, 0x90, 0x90]  # mov eax, 0; ret
    code3 = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]  # mov eax, 1; ret

    with open(filepath, "rb") as f:
        raw_data = f.read()

    p1 = find_matches(patch_pattern1.encode(), raw_data)
    p2 = find_matches(patch_pattern2.encode(), raw_data)
    p3 = find_matches(patch_pattern3.encode(), raw_data)

    if (len(p1) != 1) or (len(p2) != 1) or (len(p3) != 1):
        print("[-] Error: Too many results returned")
        return False
    try:
        buffer = list(raw_data)
        do_patch(buffer, p1[0].get("start"), code1)
        do_patch(buffer, p2[0].get("start"), code2)
        do_patch(buffer, p3[0].get("start"), code3)

        with open("./init.patched", "wb") as f:
            f.write(bytes(buffer))

        print("[+] Saved to ./init.patched")
        return True
    except Exception as e:
        print("[-] Error: %s" % e)
        return False


def patch_flatkc(filepath: str) -> bool:
    """
    The patch_flatkc function perform patch on "flatkc"
    :param filepath: flatkc filepath
    :return: bool
    """
    try:
        print("[*] Patching flatkc")
        subprocess.run(f"cp {filepath} {filepath}.patched", shell=True)
        filepath = f"{filepath}.patched"

        patch_pattern1 = gen_regex_from_sig(
            "56 48 89 F7 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 49 89 E8 49 ?? ?? ?? ?? ?? ?? E8 ?? ?? "
            "?? ?? 5E FF E0")
        patch_pattern2 = gen_regex_from_sig(
            "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 ?? ?? ?? ?? ?? ?? 65 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 ?? ?? 31 C0 48 "
            "?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 77 ??")

        with open(filepath, "rb") as f:
            flatkc_code = f.read()

        p1 = find_matches(patch_pattern1.encode(), flatkc_code)

        if len(p1) != 1:
            print("[-] Error: Too many results returned")
            return False

        gzip_addr = None
        gzip_size = None
        raw_code = p1[0].get("match")

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for instruction in md.disasm(raw_code, p1[0].get("start")):
            if instruction.mnemonic == "lea":
                if instruction.op_str.startswith("rdx"):
                    _rip = instruction.address + instruction.size
                    _tmp = int(instruction.op_str[instruction.op_str.find("0x"):-1], 16)
                    gzip_addr = _rip - _tmp
                    print(f"[+] gzip_addr: {hex(gzip_addr)}")
            elif instruction.mnemonic == "mov":
                if instruction.op_str.startswith("ecx"):
                    gzip_size = int(instruction.op_str[5:], 16)
                    print(f"[+] gzip_size: {hex(gzip_size)}")

        if gzip_addr is None or gzip_size is None:
            print("[-] Error: extract information failed")
            return False

        gzip_data = flatkc_code[gzip_addr: gzip_addr + gzip_size]
        gzip_data_size = len(gzip_data)
        decom_data = gzip.decompress(gzip_data)

        p2 = find_matches(patch_pattern2.encode(), decom_data)
        if len(p2) != 1:
            print("[-] Error: Too many results returned")
            return False

        buffer = list(decom_data)
        do_patch(buffer, p2[0].get("start"), [0xC3])
        with open(".temp", "wb") as f:
            f.write(bytes(buffer))

        subprocess.run("cat ./.temp | gzip -9 > .new_comp", shell=True)
        os.remove("./.temp")
        with open("./.new_comp", "rb") as f:
            comp_data = f.read()

        comp_data_size = len(comp_data)
        if comp_data_size > gzip_data_size:
            print("[-] Error: comp_data_size > gzip_data_size")
            return False

        if comp_data_size < gzip_data_size:
            print("[!] Need to fix bytes")
            diff = gzip_data_size - comp_data_size
            comp_data += b'\x00' * diff

        with open("./.new_comp", "wb") as f:
            f.write(comp_data)

        subprocess.run(f"dd if=/dev/zero of={filepath} bs=1 seek={gzip_addr} count={gzip_size} conv=notrunc", shell=True)
        subprocess.run(f"dd if=.new_comp of={filepath} bs=1 seek={gzip_addr} conv=notrunc", shell=True)
        os.remove(".new_comp")
        print("[+] Saved to flatkc.patched")
        return True
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


if __name__ == "__main__":
    if platform.system() != "Linux":
        print("[-] This tool can only be run on Linux!")
        exit(1)

    if len(sys.argv) != 2:
        print("[*] Usage: python3 %s <filename>" % sys.argv[0])
        exit(0)

    f_path = sys.argv[1]
    if f_path == "init":
        patch_init(f_path)
    elif f_path == "flatkc":
        patch_flatkc(f_path)
    else:
        print(f"[-] Invalid file: {f_path}")
