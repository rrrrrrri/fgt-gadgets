"""
FortiGate keygen v1.2 (For newer versions [FGTVM64 v7.4.3?])
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

import struct
import base64
import hashlib
from Crypto.Cipher import AES

lic_key_array = {
                    "SERIALNO":       (0x73, 0x0),
                    "CERT":           (0x73, 0x8),
                    "KEY":            (0X73, 0x10),
                    "CERT2":          (0X73, 0x18),
                    "KEY2":           (0X73, 0x20),
                    "CREATEDATE":     (0x73, 0x28),
                    "UUID":           (0x73, 0x30),
                    "CONTRACT":       (0x73, 0x38),
                    "USGFACTORY":     (0x6e, 0x40),
                    "LENCFACTORY":    (0x6e, 0x44),
                    "CARRIERFACTORY": (0x6e, 0x48),
                    "EXPIRY":         (0x6e, 0x4c)
                }

class License:
    fixed_aes_key = b"\x4C\x7A\xD1\x3C\x95\x3E\xB5\xC1\x06\xDA\xFC\xC3\x90\xAE\x3E\xCB"
    fixed_aes_iv =  b"\x4C\x7A\xD1\x3C\x95\x3E\xB5\xC1\x06\xDA\xFC\xC3\x90\xAE\x3E\xCB"
    fixed_rsa_header = b"\x78\x99\xBF\xA5\xEF\x56\xAA\x98\xC1\x0B\x87\x2E\x30\x8E\x54\xF9\x71\xAD\x13\xEA\xAA\xBC\xE2\x0C\xB3\xAE\x65\xAE\xF9\x0E\x9B\xD1\x88\xC7\xFE\xBC\x86\x65\xFE\xE7\x62\xDE\x43\x0B\x02\x15\x36\xC8\xC5\xCD\x0E\xB9\x01\x97\xCE\x82\x27\x0F\x69\x7F\x6A\x29\xEC\x1C"
    
    rsa_header_length = len(fixed_rsa_header)    # 4 bytes
    aes_key = fixed_aes_iv + fixed_aes_key       # 32 bytes  iv + key
    enc_data_length = None
    enc_data = None
    license_data = None

    license_header = "-----BEGIN FGT VM LICENSE-----\r\n"
    license_tail = "-----END FGT VM LICENSE-----\r\n"

    def __init__(self, licensedata):
        self.license_data = licensedata
    
    def encrypt_data(self):
        tmp_buf = b"\x00" * 4 + struct.pack("<I", 0x13A38693) + b"\x00" * 4 + self.license_data   # append magic number
        def encrypt(data, password, iv):
            bs = 16
            pad = lambda s: s + (bs - len(s) % bs) * chr(bs - len(s) % bs).encode()
            cipher = AES.new(password, AES.MODE_CBC, iv)
            data = cipher.encrypt(pad(data))
            return data
        
        self.enc_data = encrypt(tmp_buf, self.aes_key[16:], self.aes_key[:16])
        self.enc_data_length = len(self.enc_data)
    
    def obj_to_license(self):
        buf = b""
        buf += struct.pack("<I", self.rsa_header_length)
        buf += self.fixed_rsa_header
        buf += struct.pack("<I", self.enc_data_length)
        buf += self.enc_data
        return base64.b64encode(buf)

class LicenseDataBlock:
    key_name_length = None    # 1 byte
    key_name = None
    key_flag = None           # 1 byte, 's' for str or 'n' for num
    key_value_length = None   # 2 bytes
    key_value = None

    def __init__(self, keyname, keyvalue):
        self.key_name_length = len(keyname)
        self.key_name = keyname
        self.key_value_length = len(keyvalue)
        self.key_value = keyvalue
        self.key_flag = lic_key_array.get(keyname)[0]
    
    def obj_to_bin(self):
        buf = b""
        buf += struct.pack("<B", self.key_name_length)
        buf += self.key_name.encode()
        buf += struct.pack("<B", self.key_flag)
        if self.key_flag == 0x73:
            buf += struct.pack("<H", (self.key_value_length + 1))
            buf += (self.key_value + "\x00").encode()
        elif self.key_flag == 0x6e:
            buf += struct.pack("<H", 4)
            buf += struct.pack("<I", int(self.key_value))
        return buf

if __name__ == "__main__":
    CERT = """-----BEGIN CERTIFICATE-----
MIIE4zCCA8ugAwIBAgIEAqCC1jANBgkqhkiG9w0BAQsFADCBqzELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1bm55dmFsZTERMA8G
A1UEChMIRm9ydGluZXQxHjAcBgNVBAsTFUNlcnRpZmljYXRlIEF1dGhvcml0eTEb
MBkGA1UEAxMSZm9ydGluZXQtc3ViY2EyMDAxMSMwIQYJKoZIhvcNAQkBFhRzdXBw
b3J0QGZvcnRpbmV0LmNvbTAgFw0yNDA0MDEwNjIzNDlaGA8yMDU2MDUyNjIwNDgz
M1owgZ0xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQH
DAlTdW5ueXZhbGUxETAPBgNVBAoMCEZvcnRpbmV0MRIwEAYDVQQLDAlGb3J0aUdh
dGUxGTAXBgNVBAMMEEZHVk1FVjJBQjdFMDBHNjMxIzAhBgkqhkiG9w0BCQEWFHN1
cHBvcnRAZm9ydGluZXQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEA0xMG5A2Uozw5JzGmFCgw4GfN04eMbfYnEMrHAl+QUk8FIgye+mHURjUPF0g5
mLVty9+6wRwcOLhnYVOaVNaVkn/j/5b6FJCkfaTRLrQgl10x1i7Z01YFYMy1SZqu
wL+Bp93XpFGr3gy+JN1FL47biJrpDDBSoNYtYwXgqh7HiLHMhJEhREyuBuiV+YDv
MELpF33HihNti5WmZ4dtAZDHac89yeCg/8FiwsS1gKNGb24FdUrS9lafMsIbJq8I
Cjs5p6J/zdBRdG4831mWPUJ1kFwQRxKFitAkZnX1BSZ29JoK18HB9Ix9MORAbOH4
69p0fHwK79rRF2rV3R/ynEkCDQIDAQABo4IBFzCCARMwDAYDVR0TAQH/BAIwADAd
BgNVHQ4EFgQUKZ2hvNwRI7TSTD9JsiyZlU9DPIcwgdMGA1UdIwSByzCByIAUmCsl
PDDKLCtW59v8WTOz3D1batehgaukgagwgaUxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
EwpDYWxpZm9ybmlhMRIwEAYDVQQHEwlTdW5ueXZhbGUxETAPBgNVBAoTCEZvcnRp
bmV0MR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxFTATBgNVBAMTDGZv
cnRpbmV0LWNhMjEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmb3J0aW5ldC5jb22C
AiABMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAmUIB3HBeuCsM
7Bk6EmikARnoja6oGBmM0pjjpxzuUM+xhHz6XhhyAxgJ4BG0sOJVQvlLsu0ba0E/
obdnlSodCg3ewCInKl1ve2ti5tuzI6EJe6b2YmcsERotp/N17JH06minhUuUzoOQ
WnarWE389ZGc8S/HYwmaYvYmjhPrUMlloU6sepvhzWu3OXhuHIBzFvY398jFTOWC
OTIscvIZXRPrIaX8E07lVp+XuktQDeSoiDw1w2TaBPIyuSSlKFsEoajLiDrApfSL
CUAKKcZJxugWKZ2oORqj9Grr+0anGtbHkJvmy8aqWV9mQgRO0G84pSIywVEbtO4S
BiHic4Jcxg==
-----END CERTIFICATE-----
"""
    KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA0xMG5A2Uozw5JzGmFCgw4GfN04eMbfYnEMrHAl+QUk8FIgye
+mHURjUPF0g5mLVty9+6wRwcOLhnYVOaVNaVkn/j/5b6FJCkfaTRLrQgl10x1i7Z
01YFYMy1SZquwL+Bp93XpFGr3gy+JN1FL47biJrpDDBSoNYtYwXgqh7HiLHMhJEh
REyuBuiV+YDvMELpF33HihNti5WmZ4dtAZDHac89yeCg/8FiwsS1gKNGb24FdUrS
9lafMsIbJq8ICjs5p6J/zdBRdG4831mWPUJ1kFwQRxKFitAkZnX1BSZ29JoK18HB
9Ix9MORAbOH469p0fHwK79rRF2rV3R/ynEkCDQIDAQABAoIBAG+JI2AJCR1E6pKa
er82CbXbRHldrEhDBZuq+4R2iSXlWboHX07BuVEsIoBUCxN188ICxIXc29DhKMfW
TLw99CXI7OsXlaieUj2OhXcfegViGr6qXTJ+xzLCmZ1+Xo+94r6YzKWo/p/Ergl+
31tlKv7BlRp6wn75DlzAM1rSDvBcxRx4hYKCOQiNKHFAlTFS5C0dVjj+57R24mvW
/V75HMz14wgztI3eEXrawtrig02ABvPyapS0usTwcGb/2mMEHyp8VBUEy66j+rU3
kJvJ45iWw/yQEsP/26el9R9XRZusdtqT/8MLefG43q+Y52DyccKnG2PJHvtQJgFj
DxC2VWECgYEA/pvKnCRecWMALKY/1K+NAvrq9i2OOdYTSKtpu/ObzcjfD+ixj73j
V9Pi6QZ95BkPUIhoT47xG1lpAjfRpCDJwor2esWHdIuBVR3mljFnJuFday5e4iyq
mn4kZMBjmjUcg70jU6OS7VUbQm5/dOQjgN+0WcUa+xSEGq0xrlfe/OkCgYEA1DpU
RBhbBjDamlFcmWumRJ0c8GBv79DuFiDgVaouON5a5piFMEc43Gg1caEddzaBzTlH
21N44vPPhpBYkkbgi/2TnR4Kc97d+lLOzjKtS5rZJbYYr/iQxdcCRrqELxzPJ/ki
GUDyXpDUUkiipLg6N6ob9KbABcMJ97IsfbTclYUCgYBySahXEpQ6PYBUioPYiry3
e76Aps5S899QHXGm5qEnbGWElKUvqsMkJ36Rr1JPU1hmg/Se0cE0z5utXTUDgZxP
cWVWkthM3lo9xOA+xwpQj5UJiZUZ3YbvNnRLrXiIPhMAp6P15VUMp8lGtqcL52Rw
cvpX2XxU/E6YUuocImF8EQKBgA6iQwM7BrPDlJ9FcvQlRx6+EqvEipNnvbMK600c
4fkL5Aq4g56TmqkgCmdea7C3snWbOIg4FkLX+vxVYbYcawlcH9yaoK/isz26jgYL
2oU3FTgTeVpQ8nKh48dKvyicfPBNrns9TjkVFX7jAUwIZANImIrjIKSFEV/iCk1U
tk0dAoGALvo1adk0KU9lbo77b4Z43MsEAv0qv002AYcc1PQu5JJy5xiSonxyVwVB
pNmRGpAEa83WFkuxr4F6CTbdqsuYcoxh4JXRDqdmL8RYbzTKpMhAUWiFBOVE8yq3
j+aou7+lDhcvI/pon8c6PPlYM4tW1yVhgPnq/1Ddrcod7AjzXaQ=
-----END RSA PRIVATE KEY-----
"""
    CERT2 = """-----BEGIN CERTIFICATE-----
MIIDyjCCArKgAwIBAgIEAqCC1zANBgkqhkiG9w0BAQsFADCBoDELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1bm55dmFsZTERMA8G
A1UEChMIRm9ydGluZXQxHjAcBgNVBAsTFUNlcnRpZmljYXRlIEF1dGhvcml0eTEQ
MA4GA1UEAxMHc3VwcG9ydDEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmb3J0aW5l
dC5jb20wHhcNMjQwNDAxMDYyMzQ5WhcNMzgwMTE4MjIzNDM5WjCBnTELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcMCVN1bm55dmFsZTER
MA8GA1UECgwIRm9ydGluZXQxEjAQBgNVBAsMCUZvcnRpR2F0ZTEZMBcGA1UEAwwQ
RkdWTUVWMkFCN0UwMEc2MzEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmb3J0aW5l
dC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC724xmbW9wGpeU
at5EvTeRFfgB0RNPC/ifhD1tgIcZDxkxchU9L3i4i+mKzhKznUp5JiEdOFzb8Ne1
dI0XwLnsMWO9/4WzjfSIy+m24lKU3Qw3+gzDKweH4JmIIy9p5aUpl9snICXe28p+
b7fxSgAmtCD1wtktzmXfqSJwJZuJfhMS8pMK4VKqWty/AFce5ow7zasGRkweh8dH
56+kvOoqNupeE13K/fPO20s9V4zeCS4lsc7356vnambUn4hR2dNF95jfxO0ZiBf6
omdmV4aCd3iqS9J1/c8TkSPhMIRKeA/CtH4vESyI0YEDrVgb5Jb4kCsyNCtOTPZg
YbmnYUCFAgMBAAGjDTALMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEBADi4
ahfLbIarzUVJODKuzmF+AcMRMv/WT2yjvbCnw2V7L16uUt26eH3HemhHhGD50mD8
Ku/+REjOlBLwpdnYoLA2fra6ElIE0NWdUXMve8IYciOoSDgVy4g0XAD2+e05MxTM
hXsO4pzUO4hiO+hyoum/bSohCalc0oPguQTh1cbHtCpwfYQALdPBWPNGnH57EWyP
ZkM7tO1AHtRjLx35iajJ6+1SJXLSduYeRItfJ4xwRjkDSQBhogd8wiYxOgPRd0/c
6nSkuAjOlWwZfIJuZa6iIJr8JmKKrMM4ShjW4e6Ohad6wlryirobiinuHcFfO8yc
FOe06lPf0YRVjzPDIcg=
-----END CERTIFICATE-----
"""
    KEY2 = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAu9uMZm1vcBqXlGreRL03kRX4AdETTwv4n4Q9bYCHGQ8ZMXIV
PS94uIvpis4Ss51KeSYhHThc2/DXtXSNF8C57DFjvf+Fs430iMvptuJSlN0MN/oM
wysHh+CZiCMvaeWlKZfbJyAl3tvKfm+38UoAJrQg9cLZLc5l36kicCWbiX4TEvKT
CuFSqlrcvwBXHuaMO82rBkZMHofHR+evpLzqKjbqXhNdyv3zzttLPVeM3gkuJbHO
9+er52pm1J+IUdnTRfeY38TtGYgX+qJnZleGgnd4qkvSdf3PE5Ej4TCESngPwrR+
LxEsiNGBA61YG+SW+JArMjQrTkz2YGG5p2FAhQIDAQABAoIBAFslnSudcXJdFKrI
Z2vGuw1EMX8AKHQ0BL+w8/ULZYE9GCYrii6Tt+kiyX+1mNFZQeciHvMEg9mbM64x
DLw3oH3/QLvRHNgPylQNTCqWCSd9UQ5f3o1bdV3yFcw99iVVbRuPOJ/1Myq8TbWn
EwKZuxUMVOmpTqKxADDS6YisVpkQo5JbJRoWkT3xqEb45ZMrcR92pdqHYpIK0Zw2
L9iwgPMd3Vjn7E0w2wQsNx/x9pE/oBJBPClTctKTTzn+mChlOgJpUZnazZAh9Abj
e/usZeaNsHCroMOFuVRmU4K7clwmqcxARMYPnVCpgHV4Nx9TYzJeGw7woObSiWwX
1vGji4ECgYEA6Psz/44XxfvgPXN9aadVI5V3swQbFUf/mMt7D+speH4JMEo4udVK
YYg6gKNCVK+LlBdXhOQyyKodYqra8xeIcDFYhdi3r1ddneXtO7wkLHhmCY2WZRC3
VZ8WVRaBraODB3WGlr8FhtUci+6Ly6EnM1LQtTAJs7UGU4Njn+sqmpECgYEAzmsI
T1XbL6yi28SFnLd/2wtsfAAQzHWGRK6RA17z/gy7zdP8Fwd8BOEMjJv5YCb4OKRg
lO3Sk/BNPkeSz7/SU2Jl0RkVEkKpMg0tEo2VvHYETZ4qVG3F5V4BLTxFt9pciMDF
wBlFR7LIUZADavWjuBIBPaTwnYGkqvUSCsfueLUCgYAnVQFaS2rICdW5ih3KEG3X
LAyhNDg+R4FnEjMcZN8DcIOsm1soRFHiVVVLEkTIdzphLe+gh8XrCo0bcyyzjW2D
Q1Fmh0e7Wkx7s61xQDn7J/hR9I1HUqMg2VKz2rDZ15jvUW//UxBjyuae2Q7Qucwc
ZgbGD+4TYKRIxQ20mcb/gQKBgQCJtwcYRyOxLvCIxxiNci+vKHP8Vt7eShqGgCDn
qtYGTOCPdjrd8nRfnPYOaZF7AQTiZWi6c+DmKpCeWIouaMAeOavMUXupbygK6JeF
pUidL++3CSscoRBC8vC+CVRKUTkjU9mbTEDYkQLsx7RADBpqmDiTtBOEQhZmqJKc
9r63cQKBgQCtVWdp68swDFoHIdLtZBhSuZZXAv+59j9DuO6aywZbjpjk4NeJB9WR
+vv4bE2kMH4WUq23s1A1e1VX6/khlR1bF8x3xXpt8rrXma3LNHEQuJNZobsnz5jl
4F+1Qhqc2UgaJUyoUE7fd+g1a6OQ3TOFeFZ5zmzgzdFNgtNhqJn77w==
-----END RSA PRIVATE KEY-----
"""
    license_data_list = [
                            LicenseDataBlock("SERIALNO", "FGVM320000000000"),
                            LicenseDataBlock("CERT", CERT),
                            LicenseDataBlock("KEY", KEY),
                            LicenseDataBlock("CERT2", CERT2),
                            LicenseDataBlock("KEY2", KEY2),
                            LicenseDataBlock("CREATEDATE", "Mon Jan  1 06:00:00 2024"),
                            LicenseDataBlock("UUID", "00000000000000000000000000000000")
                        ]
    license_data = b""
    for obj in license_data_list:
        license_data += obj.obj_to_bin()
    
    _lic = License(license_data)
    _lic.encrypt_data()
    raw_license = _lic.obj_to_license().decode()
    
    n = 0
    lic = ""
    while True:
        if n >= len(raw_license):
            break
        lic += raw_license[n:n + 64]
        lic += "\r\n"
        n += 64
    
    with open("./License.lic", "w") as f:
        f.write(_lic.license_header + lic + _lic.license_tail)

    print("[+] Saved to ./License.lic")
