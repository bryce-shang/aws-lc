#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

/usr/bin/go build -o /home/ubuntu/bryce-shang/aws-lc/test_build_dir/acvptool boringssl.googlesource.com/boringssl/util/fipstools/acvp/acvptool

acvp_bin='/home/ubuntu/bryce-shang/aws-lc/test_build_dir/acvptool'
wrapper='/home/ubuntu/bryce-shang/aws-lc/test_build_dir/util/fipstools/acvp/modulewrapper/modulewrapper'
#test_vector='/home/ubuntu/bryce-shang/aws-lc/util/fipstools/acvp/acvptool/test/vectors/ACVP-AES-GCM'
#test_vector='/tmp/atsec/AESASM_--183471-592459-testvector-request.json'
# ACVP-AES-KW
#test_vector='/tmp/atsec/AESASM_--183471-592467-testvector-request.json'
#test_vector='/tmp/atsec/AESASM_ASM_--183478-592497-testvector-request.json'
#test_vector='/tmp/atsec/AESASM_ASM_--183478-592500-testvector-request.json'
#test_vector='/home/ubuntu/bryce-shang/aws-lc/util/fipstools/acvp/acvptool/test/vectors/ACVP-AES-GCM'
#test_vector='/tmp/atsec/KAS-ECC-SSC_SHA_ASM_--183532-592881-testvector-request.json'
#test_vector='/tmp/atsec/ACVP-TDES-CBC_TDES_C_--183459-592411-testvector-request.json'
test_vector='/tmp/atsec/KAS-FFC-SSC_183512_592674_testvector-request.json'
${acvp_bin} -wrapper ${wrapper} -json ${test_vector} > actual.json
