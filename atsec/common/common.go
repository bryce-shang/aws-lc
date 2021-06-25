package common

import (
	"encoding/json"
	"strings"
)

// looksLikeHeaderElement returns true iff element looks like it's a header,
// not a test. Some ACVP files contain a header as the first element that
// should be duplicated into the response, and some don't. If the element
// contains a "acvVersion" field then we guess that it's a header.
func LooksLikeHeaderElement(element json.RawMessage) bool {
	var headerFields struct {
		ACVVERSION string `json:"acvVersion"`
	}
	if err := json.Unmarshal(element, &headerFields); err != nil {
		return false
	}
	return len(headerFields.ACVVERSION) > 0
}

func ToLowerCase(val string) string {
	return strings.ToLower(val)
}

func ToLowerCasePointer(p *string) *string {
	if p == nil {
		return nil
	}
	str := *p
	lowerStr := ToLowerCase(str)
	return &lowerStr
}

// TODO: investigate below failures.
var FilesToSkip = [][]string{
	// failed to process input file: while processing vector set #1: 1 wrapper CMAC-AES operation failed: EOF
	// Test failed for "/tmp/atsec/in__out/AESASM_--183471-592469-testvector-request.json.bz2": Failed to process "/tmp/atsec/in__out/AESASM_--183471-592469-testvector-request.json.bz2"
	{"183471", "592469"},
	// Test failed for "/tmp/atsec/in__out/AESASM_--183491-592566-testvector-request.json.bz2": Failed to process "/tmp/atsec/in__out/AESASM_--183491-592566-testvector-request.json.bz2"
	{"183491", "592566"},
	// Test failed for "/tmp/atsec/in__out/AESASM_--183514-592670-testvector-request.json.bz2": Failed to process "/tmp/atsec/in__out/AESASM_--183514-592670-testvector-request.json.bz2"
	{"183514", "592670"},
	// Test failed for "/tmp/atsec/in__out/AESASM_--183554-592966-testvector-request.json.bz2": Failed to process "/tmp/atsec/in__out/AESASM_--183554-592966-testvector-request.json.bz2"
	{"183554", "592966"},
	// TODO: this seems relate to "ivGen": "internal". Next step: check the request file difference between
	// /home/ubuntu/bryce-shang/aws-lc/util/fipstools/acvp/acvptool/test/vectors/ACVP-AES-GCM and below
	// while processing vector set #1: aloha as expected 1 results from "AES-GCM/seal"
	// Test failed for "/tmp/atsec/in__out/AESASM_ASM_--183478-592500-testvector-request.json.bz2": Failed to process "/tmp/atsec/in__out/AESASM_ASM_--183478-592500-testvector-request.json.bz2"
	{"183478", "592500"},
	// Test failed for "/tmp/atsec/in__out/AESASM_ASM_--183478-592497-testvector-request.json.bz2": Failed to process "/tmp/atsec/in__out/AESASM_ASM_--183478-592497-testvector-request.json.bz2"
	{"183478", "592497"},
	// TODO: need to investigate how to support prediction-resistance mode for 'ctrDRBG'
	// failed to process input file: while processing vector set #1: Test group 2 specifies prediction-resistance mode, which is not supported
	// Test failed for "/tmp/atsec/in__out/AESASM_ASM_--183478-592503-testvector-request.json.bz2": Failed to process "/tmp/atsec/in__out/AESASM_ASM_--183478-592503-testvector-request.json.bz2"
	{"183478", "592503"},
	// invalid data format. reported in the quip doc
	{"183667", "593733"},
	{"185283", "603191"},
	{"185283", "603192"},
	{"185283", "603193"},
	{"185283", "603199"},
	// Do not remove until atsec responds why the data is missing.
	// CMAC-AES, expected test vector does not exist.
	{"183678", "593837"},
	{"183642", "593540"},
	{"183675", "593804"},
	{"183632", "593482"},
	{"183668", "593757"},
	{"183679", "593838"},
	{"183633", "593488"},
// 	// Below are ECDSA keygen
// 	{"183509", "592639"},
// 	{"183512", "592665"},
// 	{"183524", "592722"},
// 	{"183512", "592665"},
// 	// Below are ECDSA sigGen
// 	{"183512", "592642"},
// 	{"183512", "-"},
}

func SkipKnwonFailedFiles(filename string) bool {
	for _, e := range FilesToSkip {
		if strings.Contains(filename, e[0]) && strings.Contains(filename, e[1]) {
			return true
		}
	}
	return false
}
