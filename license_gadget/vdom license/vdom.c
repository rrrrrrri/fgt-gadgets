/*
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
*/
#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/des.h>

// #define DEBUG
// #define TEST

unsigned char dec_char_list[] = {
    0x41, 0x42, 0x30, 0x43, 0x44, 0x31, 0x45, 0x47, 0x32, 0x48, 
    0x49, 0x33, 0x4A, 0x4B, 0x34, 0x4D, 0x4E, 0x35, 0x4F, 0x50, 
    0x36, 0x51, 0x53, 0x37, 0x54, 0x55, 0x38, 0x56, 0x57, 0x39, 
    0x59, 0x5A
};
unsigned char enc_char_list[] = {
    0x41, 0x42, 0x30, 0x43, 0x44, 0x31, 0x45, 0x47, 0x32, 0x48, 
    0x49, 0x33, 0x4A, 0x4B, 0x34, 0x4D, 0x4E, 0x35, 0x4F, 0x50, 
    0x36, 0x51, 0x53, 0x37, 0x54, 0x55, 0x38, 0x56, 0x57, 0x39, 
    0x59, 0x5A
};
unsigned char raw_ks2[] = { 0xC4, 0x1C, 0xCB, 0xAB, 0x3D, 0xBF, 0xEA, 0x9B };
unsigned char raw_ks3[] = { 0x38, 0x9D, 0x10, 0x51, 0x8C, 0xBA, 0x1A, 0xC7 };

int check_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ? 0 : -1;
}

int derive_iv_from_serial(char* serial_num, DES_cblock* ivec) {
    unsigned char input[] = {0x29, 0x48, 0x13, 0xDE, 0x14, 0x96, 0xEC, 0xCC};
    unsigned char output[8] = {0};
    DES_key_schedule ks;
    DES_string_to_key(serial_num, ivec);
    if (DES_key_sched((const_DES_cblock*) ivec, &ks)) {
        return -1;
    }
    DES_ncbc_encrypt(input, output, 8, &ks, ivec, 0);
    memcpy(ivec, output, 8);
    return 0;
}

int encrypt_vdom_license(unsigned int vdom_num, char* serial_num, char* license_key) {
    if (vdom_num > 0xffff) {
        printf("[-] Invalid vdom_num\n");
        return -1;
    }
    if (strlen(serial_num) != 16) {
        printf("[-] Invalid serial number length\n");
        return -1;
    }

    unsigned char raw_buf[16] = {0};
    raw_buf[0] = (vdom_num >> 8) & 0xff;
    raw_buf[1] = vdom_num & 0xff;
    unsigned long init_crc = crc32(0, 0, 0);
    unsigned long raw_crc = crc32(init_crc, raw_buf, 2);
    raw_buf[2] = (raw_crc >> 8) & 0xff;
    raw_buf[3] = (raw_crc >> 16) & 0xff;
    raw_buf[4] = (raw_crc >> 24) & 0xff;

#ifdef DEBUG
    printf("[*] raw_buf: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", raw_buf[i]);
    }
    printf("\n");
#endif

    DES_cblock ivec;
    DES_key_schedule ks1, ks2, ks3;
    if (derive_iv_from_serial(serial_num, &ivec)) {
        printf("[-] IV failed\n");
        return -1;
    }
    DES_set_key_unchecked((const_DES_cblock*)&ivec, &ks1);    
    if (DES_key_sched(raw_ks2, &ks2)) {
        return -1;
    }
    if (DES_key_sched(raw_ks3, &ks3)) {
        return -1;
    }

    unsigned char middle_buf[16] = {0};
    DES_ede3_cbc_encrypt(raw_buf, middle_buf, 8, &ks1, &ks2, &ks3, &ivec, 1);

    middle_buf[8] ^= serial_num[8] & 0xf0;
    middle_buf[9] ^= serial_num[9] & 0xf0;

#ifdef DEBUG
    printf("[*] middle_buf: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", middle_buf[i]);
    }
    printf("\n");
#endif

    int middle_cur = 0;
    int license_cur = 0;
    int middle = 0;
    int step = 0;
    int finish = 0;
    int _tmp = 0;
    int _tmp2 = 0;
    while (middle_cur != 10) {
        while (1) {
            _tmp = license_cur + 1;
            char* cur_license = &license_key[license_cur];
            int char_list_cur = middle >> 3;
            if (step > 4) {
                middle = middle << 5;
                step -= 5;
                *cur_license = enc_char_list[char_list_cur & 0x1f];
            }
            else {
                _tmp2 = middle_cur;
                step += 3;
                ++middle_cur;
                unsigned char ch = middle_buf[_tmp2];
                middle = ch << (8 - step);
                *cur_license = enc_char_list[((ch >> step) | char_list_cur) & 0x1f];
            }
            license_cur += 2;
            if (license_cur % 6 != 0) {
                break;
            }
            license_key[_tmp] = '-';
            if (middle_cur == 10) {
                finish = 1;
            }
        }
        if (finish) {
            break;
        }
        license_cur = _tmp;
    }

    if (step) {
        license_key[license_cur] = enc_char_list[middle >> (8 - step)];
        license_cur += 1;
    }
    license_key[license_cur] = 0;
    return 0;
}

// ONLY FOR TEST
#ifdef TEST
int decrypt_vdom_license(char* serial_num, char* license_key) {
    if (strlen(serial_num) != 16 || strlen(license_key) != 19) {
        printf("[-] Invalid params\n");
        return -1;
    }

    int cur_lic = 0;
    int step = 0;
    int middle = 0;
    int target_cur = 0;
    unsigned char middle_buf[16] = {0};

    while (cur_lic < 19) {
        char ch = license_key[cur_lic];
        cur_lic++;

        if (ch == '-') {
            continue;
        }

        if (check_char(ch) != 0) {
            printf("[-] Invalid char: %c\n", ch);
            return -1;
        }

        int char_list_cur = -1;
        for (int i = 0; i < sizeof(dec_char_list); i++) {
            if (dec_char_list[i] == ch) {
                char_list_cur = i;
                break;
            }
        }
        if (char_list_cur == -1) {
            printf("[-] Invalid license_key\n");
            return -1;
        }

        if (step <= 2) {
            int shift_amount = 3 - step;
            middle |= char_list_cur << shift_amount;
            step += 5;
        } else {
            middle_buf[target_cur++] = (unsigned char)((char_list_cur >> (step - 3)) | middle);
            step -= 3;
            middle = char_list_cur << (8 - step);
        }
    }

#ifdef DEBUG
    printf("[*] middle_buf: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", middle_buf[i]);
    }
    printf("\n");
#endif

    DES_cblock ivec;
    DES_key_schedule ks1, ks2, ks3;
    unsigned char target_buf[16] = {0};
    if (derive_iv_from_serial(serial_num, &ivec)) {
        printf("[-] IV failed\n");
        return -1;
    }

    DES_set_key_unchecked((const_DES_cblock*)&ivec, &ks1);
    if (DES_key_sched(raw_ks2, &ks2)) {
        return -1;
    }
    if (DES_key_sched(raw_ks3, &ks3)) {
        return -1;
    }
    DES_ede3_cbc_encrypt(middle_buf, target_buf, 8, &ks1, &ks2, &ks3, &ivec, 0);

#ifdef DEBUG
    printf("[*] target_buf: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", target_buf[i]);
    }
    printf("\n");
#endif

    middle_buf[8] ^= serial_num[8] & 0xf0;
    middle_buf[9] ^= serial_num[9] & 0xf0;
    unsigned long init_crc = crc32(0, 0, 0);
    unsigned long final_crc = crc32(init_crc, target_buf, 2);
    unsigned long final_target = 0;
    final_target |= target_buf[4];
    final_target = final_target << 8;
    final_target |= target_buf[3];
    final_target = final_target << 8;
    final_target |= target_buf[2];
    if (final_target != (final_crc >> 8)) {
        printf("[-] Invalid key\n");
        printf("    crc: %lx\n", final_crc >> 8);
        printf("    cal: %lx\n", final_target);
        return -1;
    }
    printf("[+] Check passed!\n");
    int vdom_num = (target_buf[0] << 8) | target_buf[1];
    printf("    VDOMs: %d\n", vdom_num);
    return vdom_num;
}
#endif

int main(int argc, char* argv[]) {
    printf("[*] FortiGate VDOM keygen v0.2\n");
    if (argc != 3) {
        printf("Usage: ./vdom serial_num vdom_num\n");
        return 0;
    }
    char *endptr;
    char serial_num[256] = {0};
    memcpy(serial_num, argv[1], sizeof(serial_num));
    char license[256] = {0};
    if (encrypt_vdom_license(strtol(argv[2], &endptr, 10), serial_num, license) == -1) {
        return 0;
    }

#ifdef TEST
    decrypt_vdom_license(serial_num, license);
#endif

    printf("[+] License is: %s\n", license);
    return 0;
}
