#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

export CC=clang-7
export CXX=clang++-7
source tests/ci/common_posix_setup.sh

run_build -DFIPS=1 -DCMAKE_BUILD_TYPE=Release

#cd /home/ubuntu/bryce-shang/aws-lc && \
#/usr/bin/go build -o /home/ubuntu/bryce-shang/aws-lc/test_build_dir/acvptool boringssl.googlesource.com/boringssl/util/fipstools/acvp/acvptool && \
#/usr/bin/go build -o /home/ubuntu/bryce-shang/aws-lc/test_build_dir/testmodulewrapper boringssl.googlesource.com/boringssl/util/fipstools/acvp/acvptool/testmodulewrapper && \
#cd util/fipstools/acvp/acvptool/test && \
#/usr/bin/go run check_expected.go \
#-tool /home/ubuntu/bryce-shang/aws-lc/test_build_dir/acvptool \
#-module-wrappers modulewrapper:/home/ubuntu/bryce-shang/aws-lc/test_build_dir/util/fipstools/acvp/modulewrapper/modulewrapper,testmodulewrapper:/home/ubuntu/bryce-shang/aws-lc/test_build_dir/testmodulewrapper \
#-tests tests.json

#acvp_bin='/home/ubuntu/bryce-shang/aws-lc/test_build_dir/acvptool'
#wrapper='/home/ubuntu/bryce-shang/aws-lc/test_build_dir/util/fipstools/acvp/modulewrapper/modulewrapper'
#test_vector='/home/ubuntu/bryce-shang/aws-lc/util/fipstools/acvp/acvptool/test/vectors/ACVP-AES-GCM'
#${acvp_bin} -wrapper ${wrapper} -json ${test_vector}
