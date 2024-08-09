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
import magic
import r2pipe
import hashlib
import argparse
import subprocess
from unicorn import *
from unicorn.x86_const import *
# from udbserver import *    # uncomment this line if you want to debug


def pad_size(size):
    return size + 0x4000 - size % 0x4000


def is_elf_file(filepath):
    file_type = magic.Magic(mime=True)
    file_mime_type = file_type.from_file(filepath)
    return file_mime_type == 'application/x-executable'


def do_unpack(filepath):
    try:
        print("[*] Unpacking kernel")
        res = subprocess.Popen(f"vmlinux-to-elf {filepath} ./tmp_fixed_kc", shell=True, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        result = res.stdout.read()
        res.wait()
        res.stdout.close()
        if b"Successfully wrote the new ELF kernel" not in result:
            print(f"[-] {filepath} is not a valid kernel file")
            exit(-1)
    except subprocess.CalledProcessError as e:
        print(f"[-] Error: {e}")
        exit(-1)


class FgtKernel:
    def __init__(self, filepath: str, md5: str, cachepath: str = None):
        self.md5 = md5
        self.filepath = filepath
        self.elf_data = None
        self.cachepath = cachepath
        self.program_info = None
        self.decrypt_params = None

    def unpack(self):
        filepath = self.filepath
        is_elf = is_elf_file(self.filepath)
        if is_elf:
            pass
        else:
            do_unpack(self.filepath)
            filepath = "./tmp_fixed_kc"

        with open(filepath, "rb") as _f:
            self.elf_data = _f.read()

        self.filepath = filepath

    def do_analyse(self):
        try:
            if self.cachepath is not None:
                print("[*] Using cache file")
                with open(self.cachepath, "r") as _f:
                    _data = _f.read()
                self.program_info = eval(_data)
            else:
                print("[*] Do analyse")
                r2 = r2pipe.open(self.filepath)
                r2.cmd("aa")

                _tmp = {"sections": r2.cmdj("iSj")}
                r2.cmd("s sym.fgt_verify_decrypt")
                _tmp["fgt_verify_decrypt_addr"] = r2.cmdj("pdfj")["addr"]

                self.program_info = _tmp

                with open("./%s.cache" % self.md5, "w") as _f:
                    _f.write(str(_tmp))

                print("[+] Cache saved to ./%s" % self.md5)
        except Exception as e:
            print(e)
            exit(-1)

    def get_params(self):
        try:
            params = {}
            for section in self.program_info["sections"]:
                if section["name"] == ".text":
                    params["text_seg_addr"] = section["vaddr"]
                    params["text_seg_size"] = section["vsize"]
                    params["text_seg_paddr"] = section["paddr"]
                elif section["name"] == ".init.text":
                    params["init_text_seg_addr"] = section["vaddr"]
                    params["init_text_seg_size"] = section["vsize"]
                    params["init_text_seg_paddr"] = section["paddr"]
                elif section["name"] == ".init.data":
                    params["init_data_seg_addr"] = section["vaddr"]
                    params["init_data_seg_size"] = section["vsize"]
                    params["init_data_seg_paddr"] = section["paddr"]
                elif section["name"] == ".rodata":
                    params["rodata_seg_addr"] = section["vaddr"]
                    params["rodata_seg_size"] = section["vsize"]
                    params["rodata_seg_paddr"] = section["paddr"]
                elif section["name"] == ".bss":
                    params["bss_seg_addr"] = section["vaddr"]
                    params["bss_seg_size"] = section["vsize"]

            params["fgt_verify_decrypt_addr"] = self.program_info["fgt_verify_decrypt_addr"]

            self.decrypt_params = params
        except Exception as e:
            print(e)
            exit(-1)


def decrypt(_kernel, _enc_data):
    elf_data = _kernel.elf_data
    text_seg_addr = _kernel.decrypt_params["text_seg_addr"]
    text_seg_size = _kernel.decrypt_params["text_seg_size"]
    text_seg_paddr = _kernel.decrypt_params["text_seg_paddr"]

    init_text_seg_addr = _kernel.decrypt_params["init_text_seg_addr"]
    init_text_seg_size = _kernel.decrypt_params["init_text_seg_size"]
    init_text_seg_paddr = _kernel.decrypt_params["init_text_seg_paddr"]

    init_data_seg_addr = _kernel.decrypt_params["init_data_seg_addr"]
    init_data_seg_size = _kernel.decrypt_params["init_data_seg_size"]
    init_data_seg_paddr = _kernel.decrypt_params["init_data_seg_paddr"]

    rodata_seg_addr = _kernel.decrypt_params["rodata_seg_addr"]
    rodata_seg_size = _kernel.decrypt_params["rodata_seg_size"]
    rodata_seg_paddr = _kernel.decrypt_params["rodata_seg_paddr"]

    bss_seg_addr = _kernel.decrypt_params["bss_seg_addr"]
    bss_seg_size = _kernel.decrypt_params["bss_seg_size"]

    func_offset = 0x31
    fgt_verify_decrypt_addr = _kernel.decrypt_params["fgt_verify_decrypt_addr"] + func_offset

    stack_addr = 0x1234000
    stack_size = 0x3000
    enc_map_addr = 0xFFFF000

    emu_end = fgt_verify_decrypt_addr + 0x51

    mu = Uc(UC_ARCH_X86, UC_MODE_64 + UC_MODE_LITTLE_ENDIAN)

    mu.mem_map(text_seg_addr, pad_size(text_seg_size))  # map .text
    mu.mem_map(init_text_seg_addr, pad_size(init_text_seg_size))  # map .init.text
    mu.mem_map(bss_seg_addr, pad_size(bss_seg_size))  # map .bss
    mu.mem_map(init_data_seg_addr, pad_size(init_data_seg_size))  # map .init.data
    mu.mem_map(rodata_seg_addr, pad_size(rodata_seg_size))  # map .rodata
    mu.mem_map(stack_addr, stack_size)  # map stack

    mu.mem_write(text_seg_addr, elf_data[text_seg_paddr:text_seg_size + text_seg_paddr])
    mu.mem_write(init_text_seg_addr, elf_data[init_text_seg_paddr:init_text_seg_size + init_text_seg_paddr])
    mu.mem_write(init_data_seg_addr, elf_data[init_data_seg_paddr:init_data_seg_size + init_data_seg_paddr])
    mu.mem_write(rodata_seg_addr, elf_data[rodata_seg_paddr:rodata_seg_size + rodata_seg_paddr])

    mu.reg_write(UC_X86_REG_RIP, fgt_verify_decrypt_addr)
    mu.reg_write(UC_X86_REG_RBP, stack_addr + 0x1000)
    mu.reg_write(UC_X86_REG_RSP, stack_addr + 0x1000 - 0xc8)
    mu.reg_write(UC_X86_REG_GS_BASE, stack_addr + 0x2000)
    mu.reg_write(UC_X86_REG_R13, enc_map_addr)
    mu.reg_write(UC_X86_REG_R14, len(_enc_data))

    mu.mem_map(enc_map_addr, len(_enc_data) + 0x4000 - len(_enc_data) % 0x4000)  # map enc_data
    mu.mem_write(enc_map_addr, _enc_data)

    # udbserver(mu, 12345, fgt_verify_decrypt_addr)    # uncomment this line if you want to debug

    try:
        print("[*] Emulate start")
        mu.emu_start(fgt_verify_decrypt_addr, emu_end)
        dec_data = mu.mem_read(enc_map_addr, len(_enc_data))
        with open("./dec.gz", "wb") as _f:
            _f.write(dec_data)
        print("[*] Emulate end, file saved to ./dec.gz")
    except Exception as e:
        print("[-] Exception: %s at %s" % (e, hex(mu.reg_read(UC_X86_REG_RIP))))
        print("[-] Give up!")
        exit(-1)


def parse_args():
    parse = argparse.ArgumentParser(description="FortiGate v7.4.x decrypt tool")
    parse.add_argument("-f", "--file", help="Encrypted file path")
    parse.add_argument("-k", "--kernel", help="Kernel file path")
    parse.add_argument("-c", "--cache", help="Cache file path")
    args = parse.parse_args()
    return args


if __name__ == "__main__":
    args = parse_args()
    if args.file and args.kernel:
        enc_file = args.file
        kernel_file = args.kernel
        cache_file = None
        if args.cache:
            cache_file = args.cache

        with open(enc_file, "rb") as f:
            enc_data = f.read()

        kernel = FgtKernel(kernel_file, hashlib.md5(kernel_file.encode()).hexdigest(), cache_file)
        kernel.unpack()
        kernel.do_analyse()
        kernel.get_params()
        decrypt(kernel, enc_data)
    else:
        print("[*] Use -h to get help")
