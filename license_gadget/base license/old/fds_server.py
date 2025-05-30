"""
Copyright (C) 2025  catalpa

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
import socket
import ssl
import threading
import struct
import zlib
from datetime import datetime

def format_current_datetime():
    now = datetime.now()
    return now.strftime('%Y%m%d%H%M')

class FDSReqObj:
    def __init__(self, raw_data):
        self.header_len = 128
        self.header1_len = 48

        self.magic = None
        self.obj_name = None
        self.fixed_str = None
        self.payload_len = None
        self.sys_ver = None
        self.payload_crc32 = None
        self.header_crc32 = None
        self.payload = None

        self.raw_data = raw_data

    def parse_raw_data(self):
        try:
            print("[*] Parsing obj")
            self.payload = self.raw_data[self.header_len:]
            header = self.raw_data[:self.header_len]
            header1 = header[:self.header1_len]
            header2 = header[self.header1_len:]

            self.magic, self.obj_name, self.fixed_str, _ = struct.unpack("4s20s1s23s", header1)
            self.payload_len, _, self.sys_ver, _, self.payload_crc32, self.header_crc32 = struct.unpack("<II8s56sII",
                                                                                                        header2)

            l_payload_crc32 = zlib.crc32(self.payload)
            if l_payload_crc32 != self.payload_crc32:
                print(f"[-] Invalid payload checksum {hex(l_payload_crc32)}, expect: {hex(self.payload_crc32)}")
                exit(0)

            l_header_crc32 = zlib.crc32(header[:-4] + b"H1dN")
            if l_header_crc32 != self.header_crc32:
                print(f"[-] Invalid header checksum {hex(l_header_crc32)}, expect: {hex(self.header_crc32)}")
                exit(0)

            print(f"[+] Magic: {self.magic.decode()}")
            print(f"[+] Name: {self.obj_name[:14].decode()}")
            print(f"[+] Payload length: {self.payload_len}")
            print(f"[+] System version: {self.sys_ver.decode()}")
            print(f"[+] Payload crc32: {hex(self.payload_crc32)}")
            print(f"[+] Header crc32: {hex(self.header_crc32)}")
            print(f"[+] Payload: {self.payload}")
        except:
            raise ()

    def pack_obj(self):
        try:
            print("[*] Packing obj")
            self.raw_data = b""

            self.payload_crc32 = zlib.crc32(self.payload)
            self.payload_len = len(self.payload)

            self.raw_data += struct.pack("4s20s1s23s", self.magic, self.obj_name.ljust(20, b"\x00"), self.fixed_str,
                                         b"\x00" * 23)
            self.raw_data += struct.pack("<II8s56sI", self.payload_len, self.header_len, self.sys_ver, b"\x00" * 56,
                                         self.payload_crc32)

            self.header_crc32 = zlib.crc32(self.raw_data + b"H1dN")

            self.raw_data += struct.pack("<I", self.header_crc32)
            self.raw_data += self.payload
            return self.raw_data
        except:
            raise ()

class FDSReq:
    def __init__(self, raw_data):
        self.header_len = 64
        self.header = None
        self.payload = None

        self.magic = None
        self.sys_ver = None
        self.fixed_int = None
        self.payload_len = None
        self.time_str = None
        self.header_crc32 = None

        self.raw_data = raw_data

    def parse_raw_data(self):
        try:
            print("[*] Parsing data")
            self.payload = self.raw_data[self.header_len:]
            header = self.raw_data[:self.header_len]

            self.magic, self.sys_ver, self.fixed_int, self.payload_len, _, self.time_str, _, self.header_crc32 = struct.unpack(
                "<4s8sIII12s24sI", header)

            l_header_crc32 = zlib.crc32(header[:-4] + b"B1gS")
            if l_header_crc32 != self.header_crc32:
                print(f"[-] Invalid header checksum {hex(l_header_crc32)}, expect: {hex(self.header_crc32)}")
                exit(0)

            print(f"[+] Magic: {self.magic.decode()}")
            print(f"[+] System version: {self.sys_ver.decode()}")
            print(f"[+] Payload length: {self.payload_len}")
            print(f"[+] Header length: {self.header_len}")
            print(f"[+] Time: {self.time_str.decode()}")
            print(f"[+] Header crc32: {hex(self.header_crc32)}")

            self.payload = FDSReqObj(self.payload)
            self.payload.parse_raw_data()
        except:
            raise ()

    def pack_req(self):
        try:
            print("[*] Packing req")
            self.raw_data = b""
            self.payload_len = len(self.payload)
            self.time_str = format_current_datetime().encode()

            self.raw_data += struct.pack("<4s8sIII12s24s", self.magic, self.sys_ver, self.fixed_int, self.payload_len,
                                         self.header_len,
                                         self.time_str, b"\x00" * 24)
            self.header_crc32 = zlib.crc32(self.raw_data + b"B1gS")
            self.raw_data += struct.pack("<I", self.header_crc32)
            self.raw_data += self.payload
            return self.raw_data
        except:
            raise ()

def handle_client(client_socket):
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break

            print("========================")
            obj = FDSReq(data)
            obj.parse_raw_data()

            my_obj = FDSReqObj(None)
            my_obj.payload = b"Protocol=3.0|Response=200|Firmware=FPT033-FW-7.0-0250|SerialNumber=FPT-FGT-DELL1103|Server=FDSG|Persistent=True\r\n\r\n\r\n"
            my_obj.magic = b"FCPR"
            my_obj.obj_name = b"Response Object"
            my_obj.fixed_str = b"0"
            my_obj.sys_ver = b"07000000"

            my_req = FDSReq(None)
            my_req.magic = b"PUTF"
            my_req.sys_ver = b"07000000"
            my_req.fixed_int = 1
            my_req.payload = my_obj.pack_obj()
            res = my_req.pack_req()

            print("[*] Sending response")
            client_socket.sendall(res)
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

def start_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='cert.cer', keyfile='key.key')

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 8890))
    server_socket.listen(5)

    print("[*] Server is listening on port 8890...")

    while True:
        client_socket, client_address = server_socket.accept()
        ssl_client_socket = context.wrap_socket(client_socket, server_side=True)

        client_thread = threading.Thread(target=handle_client, args=(ssl_client_socket,))
        client_thread.start()

if __name__ == "__main__":
    print("[*] FortiGate custom licensing server v0.1")
    print("[!] You shouldn't use this tool in any production environment.")
    start_server()
