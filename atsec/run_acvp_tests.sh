#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

export CC=clang-7
export CXX=clang++-7

tmp_os=$(uname -a)

if [[ "${tmp_os}" == *"Ubuntu"* ]]; then
  (source tests/ci/common_posix_setup.sh && run_build -DFIPS=1 -DCMAKE_BUILD_TYPE=Release)

  # why CMake does not keep the built acvptool and testmodulewrapper.
  # after `rm -rf test_build_dir`, these two cannot be found under test_build_dir
  /usr/bin/go build -o /home/ubuntu/bryce-shang/aws-lc/test_build_dir/acvptool boringssl.googlesource.com/boringssl/util/fipstools/acvp/acvptool && \
  /usr/bin/go build -o /home/ubuntu/bryce-shang/aws-lc/test_build_dir/testmodulewrapper boringssl.googlesource.com/boringssl/util/fipstools/acvp/acvptool/testmodulewrapper
fi

#bash -c "nohup sh -c 'sudo ./atsec/run_acvp_tests.sh' &"
rm -f /tmp/atsectool && go build -o /tmp/atsectool boringssl.googlesource.com/boringssl/atsec

if [[ "${tmp_os}" == *"Ubuntu"* ]]; then
  tv='/home/ubuntu/atsec/002/testvectors'
  /tmp/atsectool --in=${tv} --compress=true
  cat /tmp/atsec/awslc-test.json

  (cd util/fipstools/acvp/acvptool/test && \
      /usr/bin/go run check_expected.go \
      -tool /home/ubuntu/bryce-shang/aws-lc/test_build_dir/acvptool \
      -module-wrappers modulewrapper:/home/ubuntu/bryce-shang/aws-lc/test_build_dir/util/fipstools/acvp/modulewrapper/modulewrapper,testmodulewrapper:/home/ubuntu/bryce-shang/aws-lc/test_build_dir/testmodulewrapper \
      -tests /tmp/atsec/awslc-test.json)
fi

if [[ "${tmp_os}" == *"Darwin"* ]]; then
  /tmp/atsectool
fi
#
#
#
#==========================================================================================================================================
#source tests/ci/common_posix_setup.sh

#run_build -DFIPS=1 -DCMAKE_BUILD_TYPE=Release

#cd /home/ubuntu/bryce-shang/aws-lc && \
#/usr/bin/go build -o /home/ubuntu/bryce-shang/aws-lc/test_build_dir/acvptool boringssl.googlesource.com/boringssl/util/fipstools/acvp/acvptool && \
#/usr/bin/go build -o /home/ubuntu/bryce-shang/aws-lc/test_build_dir/testmodulewrapper boringssl.googlesource.com/boringssl/util/fipstools/acvp/acvptool/testmodulewrapper && \
#cd util/fipstools/acvp/acvptool/test && \
#/usr/bin/go run check_expected.go \
#-tool /home/ubuntu/bryce-shang/aws-lc/test_build_dir/acvptool \
#-module-wrappers modulewrapper:/home/ubuntu/bryce-shang/aws-lc/test_build_dir/util/fipstools/acvp/modulewrapper/modulewrapper,testmodulewrapper:/home/ubuntu/bryce-shang/aws-lc/test_build_dir/testmodulewrapper \
#-tests tests.json
##
#acvp_bin='/home/ubuntu/bryce-shang/aws-lc/test_build_dir/acvptool'
#wrapper='/home/ubuntu/bryce-shang/aws-lc/test_build_dir/util/fipstools/acvp/modulewrapper/modulewrapper'
##test_vector='/home/ubuntu/bryce-shang/aws-lc/util/fipstools/acvp/acvptool/test/vectors/ACVP-AES-GCM'
#test_vector='/tmp/atsec/AESASM_--183471-592461-testvector-request.json'
#/tmp/atsec/AESASM_--183471-592459-testvector-expected.json.bz2
#${acvp_bin} -wrapper ${wrapper} -json ${test_vector}
#
#/usr/bin/go build -o /home/ubuntu/bryce-shang/aws-lc/test_build_dir/acvptool boringssl.googlesource.com/boringssl/util/fipstools/acvp/acvptool
#
