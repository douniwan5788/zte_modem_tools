#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from typing import BinaryIO, List

from struct import pack, unpack
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


# for (i=0
#      i != 64
#      + +i)
# {
#     if ((unsigned int)(i - 5) <= 15)
#     {
#         v13 = &place_holder[index_pre10++]
#         * (v13 - 640) = hardcode_key[i] + 3
#         // prefix_key
#     }
#     v19 = i - 7
#     v20 = (unsigned int)(i - 7) > 31
#     if ((unsigned int)(i - 7) <= 31)
#     {
#         v13 = &place_holder[v16++]
#         v19 = hardcode_key[i]
#     }
#     if (!v20)
#     * (v13 - 576) = v19 + 1
# }


def ascii_offset(s, offset):
    l = []
    for b in s:
        l.append(b + offset)
    return bytes(l)


def dump(hardcoded, hardcodefiles: List[BinaryIO]):
    aes_key_phrase = ascii_offset(hardcoded[5:21], 3) + hardcoded[64:]
    aes_iv_phrase = ascii_offset(hardcoded[7:39], 1)

    aes_key = SHA256.new(aes_key_phrase).digest()
    aes_iv = SHA256.new(aes_iv_phrase).digest()[:16]
    # print(aes_key.hex(), aes_iv.hex())

    for f in hardcodefiles:
        print(f"\ndecrypting {f.name}")
        header = f.read(4*15)
        magic1, magic2, *_ = unpack(">" + 'I'*15, header)
        if magic1 != 0x01020304 or magic2 != 0x00000003:
            print(f"{f.name} is not a hardcode config file, skip")
            continue
        has_next = True
        with open(f'{f.name}.txt', "wb") as t:
            aes_chiper = AES.new(aes_key, mode=AES.MODE_CBC, iv=aes_iv)

            while has_next:
                plaintext_length, chiphertext_length, has_next = unpack(">III", f.read(4*3))
                plaintext = aes_chiper.decrypt(f.read(chiphertext_length))[:plaintext_length]
                t.write(plaintext)


def parseArgs():
    parser = argparse.ArgumentParser(prog='zte_hardcode_dump', epilog='https://github.com/douniwan5788/zte_modem_tools',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('hardcode', help='the /etc/hardcode file which contains root key',
                        type=argparse.FileType('rb'))
    parser.add_argument('hardcodefile', nargs="+", help='config files under /etc/hardcodefile',
                        type=argparse.FileType('rb'))
    return parser.parse_args()


def main():
    args = parseArgs()
    # print(args)

    dump(args.hardcode.readline().strip(), args.hardcodefile)
    print('done')


if __name__ == '__main__':
    main()
