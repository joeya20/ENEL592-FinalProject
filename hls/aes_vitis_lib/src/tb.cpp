/*
 * Copyright 2019 Xilinx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>

#include "aes.hpp"

using namespace std;



// top DUT
void dut(ap_uint<128> & ciphertext, ap_uint<256> cipherkey, ap_uint<128> plaintext) {
	ap_uint<128> outArr[10];
	xf::security::aesEnc<256> cipher;
    cipher.updateKey(cipherkey);
    dut_label24:for (int i = 0; i < 10; i++) {
        cipher.process(plaintext, cipherkey, outArr[i]);
    }
    ciphertext = outArr[0];
}


int main() {
    std::cout << "This is an example test for AES256, mentioned in Appendix C.3, "
                 "NIST.FIPS.197.pdf"
              << std::endl;

    ap_uint<8> plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    ap_uint<8> cipherkey[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    ap_uint<8> ciphertext[16] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                                 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};

    ap_uint<256>* ck = (ap_uint<256>*)cipherkey;

	std::cout << "PT: " <<  *(ap_uint<128>*)plaintext << std::endl;
	std::cout << "CP: " <<  *(ap_uint<128>*)ciphertext << std::endl;




    ap_uint<128>* pt = (ap_uint<128>*)plaintext;
    ap_uint<128> cp;
    dut(cp, *ck, *pt);
    ap_uint<128>* golden = (ap_uint<128>*)ciphertext;
    if (cp == *golden) {
        std::cout << "\nAES256 test PASS\n" << std::endl;
        std::cout << cp << "    -    " <<  *golden << std::endl;
        return 0;
    } else {
        std::cout << "\nAES256 test FAIL\n" << std::endl;
        std::cout << cp << "    -    " <<  *golden << std::endl;

        return 1;
    }

    return 0;
}
