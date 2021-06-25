package subprocess

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"boringssl.googlesource.com/boringssl/atsec/common"
)

// TODO:
// 1. test aarch. Done. All tests passed when below unsupported algorithms are filtered out.
// 2. Provide more details on each module errors. Documented in the comments.
// 3. document how this tool works. Will do after meeting on how to address UnsupportedAlgos.
// 4. Take a look at bssl repo. Done. I didn't find useful commit. Latest commits happened 2 month ago.

// Overall, there are three modules - FIPS crypto(c) module, wrapper(c++) module, and acvptool(golang) module
// Note:
// 1. below "unsupport" may hide other "unsupport" because it blocks further investigation.test
// 2. if acvp tool does not support the parameter (like tweak mode), it may imply the FIPS module may not support that.

// Some references
// https://tools.ietf.org/id/draft-celi-block-ciph-00.html
var UnsupportedAlgos = []string{
	// Investigated: This acvp algorithm id is not supported by acvptool, but crypto module has this algorithm.
	// In https://github.com/usnistgov/ACVP, this is marked "DEMO only". So is this needed?
	// bssl acvptool does not support these algorithm Ids.
	// awslc does not request these algorithm Ids.
	// Possibly, we can skip it. Added Q6 to atsec.
	"ACVP-AES-GCM-SIV",
	// Investigated: This acvp algorithm id is not supported by acvptool, but old cavp supports the validation.
	// Possibly, we can skip it. Added Q6 to atsec.
	"CMAC-TDES",
	// Investigated: This acvp algorithm id is not supported by acvptool, but crypto module has this algorithm.
	// Possibly, we can skip it. Added Q6 to atsec.
	"ACVP-AES-OFB",
	// Investigated: This acvp algorithm id is not supported by acvptool, but crypto module has this algorithm.
	// sample: 183466/592442/testvector-request.json
	// Possibly, we can skip it. Added Q6 to atsec.
	"ACVP-AES-CFB128",
	// Investigated: This acvptool needs to support another tweak mode 'hex'. How? needs to read related spec.
	// Current acvptool only supports tweak mode 'number'. Ensure that configuration specifies a 'number' tweak.
	// tweak hex vs number: https://tools.ietf.org/id/draft-celi-block-ciph-00.html
	// sample: 183542-592824-testvector-request.json.bz2"
	"ACVP-AES-XTS",
	// Investigated: acvp needs to support |"ivGen": "internal" "ivGenMode": "8.2.1"|.
	// bssl acvp only supports |"ivGen": "external"|. Based on the bssl test data, this seems "iv" is provided in each test.
	// atsec data provides |"ivGen": "internal" "ivGenMode": "8.2.1"|.
	// The `internal` may mean generate iv internally, and the mode may tell the generated iv to be a specific number for deterministic.
	// https://pages.nist.gov/ACVP/draft-celi-acvp-symmetric.html
	"ACVP-AES-GCM",
	// Investigated: Current acvp RSA can only process |"testType": "GDT"|. But the data includes |"testType": "KAT"|.
	// GDT here means 'please generate data'. KAT may mean 'known answer test'.
	// Test input file may have both GDT and KAT test cases. This mix blocks further investigation.
	// https://github.com/awslabs/aws-lc/blob/main/util/fipstools/acvp/acvptool/subprocess/rsa.go#L129-L130
	"RSA",
	// Investigated: |AES_CMAC| only support key len 128 and 256. Below test case uses key with len 192
	// awslc code https://github.com/awslabs/aws-lc/blob/736fce4b11417ea07ae0df06913d7e87a3cd58ca/crypto/cmac/cmac.c#L84-L96
	// Sample data (from 183678-593837, tgId: 4, tcId: 25)
	// "key": "3E69D905D2B20C5F8C4C04D4DFE51612FCB4EF6403F40139",
	// "message": "CFEBF2CA19C04272DAFBA4D6C6588C23"
	"CMAC-AES",
	// Investigated: FIPS module does not support prediction-resistance mode.
	// test vector: 183492/592555
	// related error: Test group 2 specifies prediction-resistance mode, which is not supported.
	"ctrDRBG",
	// Investigated:
	//   1. for keyGen: bssl test input sample only include keyVerify and sigVerify test inputs.test
	//      the test input only uses curve id. Added Q4 to the atsec quip.
	//   2. for sigGen: failed because sigGen needs key from keyGen. When generated key is fixed, this test should pass
	//      https://github.com/awslabs/aws-lc/blob/736fce4b11417ea07ae0df06913d7e87a3cd58ca/util/fipstools/acvp/acvptool/subprocess/ecdsa.go#L143-L153
	//   3. for sigVer: after adding SHA-1, the tests passed. But some test vectors do not have expected test result, which should exist.
	//      ECDSA_183509_592643
	//      bssl modulewrapper HashFromName function does not support ECDSA with SHA-1, why?
	//      https://github.com/awslabs/aws-lc/blob/5abcc01890e722992583ba5fbeafbc6c57eaa0ce/util/fipstools/acvp/modulewrapper/modulewrapper.cc#L1483-L1495
	//   4. for keyVer: it works. but some test vectors do not have expected test result, which should exist.
	// Added Q5 issue5 to the atsec quip.
	"ECDSA",
	// Investigated: test type VAT(Validation test) passed, but AFT(Algorithm Functional Test) has diff results. How to verify the AFT result? This may be a question to Atsec.
	// In this algorithm, the diff result is related to 'EC_KEY_generate_key_fips', which is similar to ECDSA keyGen.
	"KAS-ECC-SSC",
	// Investigated: it seems awslc acvp needs to support other domainParameterGenerationMode, 'MODP-6144'.
	// Only "FB"/"FC" mode, acvp test vector provides p, q and g.
	// https://pages.nist.gov/ACVP/draft-hammett-acvp-kas-ssc-ffc.html
	// Need to check how domainParameterGenerationMode provides p, q and g.
	// 
	// This is found by debugging below test input.
	// The test input KAS-FFC-SSC_183512_592674 failed when modulewrapper calls DH_generate_key(dh.get()).
	// https://github.com/awslabs/aws-lc/blob/5abcc01890e722992583ba5fbeafbc6c57eaa0ce/util/fipstools/acvp/modulewrapper/modulewrapper.cc#L1834
	"KAS-FFC-SSC",
}

// Skip processing the file if the algorithm id also exists in UnsupportedAlgos.
// SupportedAlgos and UnsupportedAlgos may have some overlap (same algoirthm id).
var SupportedAlgos = []string{
	"ACVP-AES-CBC",
	"ACVP-AES-ECB",
	"ACVP-AES-CTR",
	// TODO: investigate why there is not expected test vector for 'ACVP-AES-KW'
	// under testvectors/Amazon_Web_Services__Inc_/AWS-LC_Cryptographic_Module__AES_C_/TBD/183635/593498/testvector-request.json
	"ACVP-AES-KW",
	"CMAC-AES",
	"ACVP-AES-GCM",
	"ctrDRBG",
	"ACVP-AES-XTS",
	"SHA-1",
	"SHA2-224",
	"SHA2-256",
	"SHA2-384",
	"SHA2-512",
	"HMAC-SHA-1",
	"HMAC-SHA2-224",
	"HMAC-SHA2-256",
	"HMAC-SHA2-384",
	"HMAC-SHA2-512",
	"ECDSA",
	"KAS-ECC-SSC",
	"KAS-FFC-SSC",
	"kdf-components",
	"ACVP-TDES-CBC",
	"ACVP-TDES-ECB",
	"RSA",
}

func IsKeyGen(elements []json.RawMessage) bool {
	for _, element := range elements {
		var commonFields struct {
			Mode string `json:"mode"`
		}
		if err := json.Unmarshal(element, &commonFields); err != nil {
			return false
		}
		mode := commonFields.Mode
		return mode == "keyGen" || mode == "keyVer" || mode == "sigGen"
	}
	return false
}

func ShouldSkip(filename string, elements []json.RawMessage) (string, bool) {
	algo := ""
	for _, element := range elements {
		var commonFields struct {
			Algo string `json:"algorithm"`
		}
		if err := json.Unmarshal(element, &commonFields); err != nil {
			log.Fatal("IsKnownUnsupportedAlgo unmarshal failed", err)
		}
		if algo == "" {
			algo = commonFields.Algo
		} else if algo != commonFields.Algo {
			log.Fatal("There are two algorithms in one file")
		}
	}

	for _, element := range UnsupportedAlgos {
		if element == algo {
			return algo, true
		}
	}

	for _, element := range SupportedAlgos {
		if element == algo {
			return algo, false
		}
	}
	log.Printf("warn: Algorithm '%s' not supported yet. Skip file %s", algo, filename)
	return algo, true
}

func ProcessExpectedTestDataWithBsslFormat(filename string, result *bytes.Buffer) error {
	jsonBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	var elements []json.RawMessage
	if err := json.Unmarshal(jsonBytes, &elements); err != nil {
		return err
	}

	// There must be at least one element in the file.
	if len(elements) < 1 {
		return errors.New("JSON input is empty")
	}

	var header json.RawMessage
	if common.LooksLikeHeaderElement(elements[0]) {
		header, elements = elements[0], elements[1:]
		if len(elements) == 0 {
			return errors.New("JSON input is empty")
		}
	}

	(*result).WriteString("[")

	if header != nil {
		headerBytes, err := json.MarshalIndent(header, "", "    ")
		if err != nil {
			return err
		}
		(*result).Write(headerBytes)
		(*result).WriteString(",")
	}

	for i, element := range elements {
		var commonFields struct {
			Algo string `json:"algorithm"`
			ID   uint64 `json:"vsId"`
		}
		if err := json.Unmarshal(element, &commonFields); err != nil {
			return fmt.Errorf("failed to extract common fields from vector set #%d", i+1)
		}

		algo := commonFields.Algo
		var processErr error
		var testGroupsData interface{}
		switch algo {
		case "ACVP-TDES-ECB":
			testGroupsData, processErr = ProcessExpectedBlock(element)
			break
		case "ACVP-AES-CBC":
			testGroupsData, processErr = ProcessExpectedBlock(element)
			break
		case "ACVP-AES-ECB":
			testGroupsData, processErr = ProcessExpectedBlock(element)
			break
		case "ACVP-AES-CTR":
			testGroupsData, processErr = ProcessExpectedBlock(element)
			break
		case "ACVP-TDES-CBC":
			testGroupsData, processErr = ProcessExpectedBlock(element)
			break
		case "RSA":
			testGroupsData, processErr = ProcessExpectedRSA(element)
			break
		case "ACVP-AES-KW":
			testGroupsData, processErr = ProcessExpectedAEAD(element)
			break
		case "ACVP-AES-GCM":
			testGroupsData, processErr = ProcessExpectedAEAD(element)
			break
		case "CMAC-AES":
			testGroupsData, processErr = ProcessExpectedKeyedMac(element)
			break
		case "ctrDRBG":
			testGroupsData, processErr = ProcessExpectedDRBG(element)
			break
		case "ACVP-AES-XTS":
			testGroupsData, processErr = ProcessExpectedXTS(element)
			break
		case "SHA-1":
			testGroupsData, processErr = ProcessExpectedHash(element)
			break
		case "SHA2-224":
			testGroupsData, processErr = ProcessExpectedHash(element)
			break
		case "SHA2-256":
			testGroupsData, processErr = ProcessExpectedHash(element)
			break
		case "SHA2-384":
			testGroupsData, processErr = ProcessExpectedHash(element)
			break
		case "SHA2-512":
			testGroupsData, processErr = ProcessExpectedHash(element)
			break
		case "HMAC-SHA-1":
			testGroupsData, processErr = ProcessExpectedHMAC(element)
			break
		case "HMAC-SHA2-224":
			testGroupsData, processErr = ProcessExpectedHMAC(element)
			break
		case "HMAC-SHA2-256":
			testGroupsData, processErr = ProcessExpectedHMAC(element)
			break
		case "HMAC-SHA2-384":
			testGroupsData, processErr = ProcessExpectedHMAC(element)
			break
		case "HMAC-SHA2-512":
			testGroupsData, processErr = ProcessExpectedHMAC(element)
			break
		case "ECDSA":
			testGroupsData, processErr = ProcessExpectedECDSA(element)
			break
		case "KAS-ECC-SSC":
			testGroupsData, processErr = ProcessExpectedKAS(element)
			break
		case "KAS-FFC-SSC":
			testGroupsData, processErr = ProcessExpectedKASDH(element)
			break
		case "kdf-components":
			testGroupsData, processErr = ProcessExpectedKDFComponents(element)
			break
		default:
			return fmt.Errorf("No treatment to algo %s %s", algo, filename)
		}

		if processErr != nil {
			return fmt.Errorf("while processing vector set #%d: %s", i+1, processErr)
		}

		group := map[string]interface{}{
			"vsId":       commonFields.ID,
			"testGroups": testGroupsData,
		}
		replyBytes, err := json.MarshalIndent(group, "", "    ")
		if err != nil {
			return err
		}

		if i != 0 {
			(*result).WriteString(",")
		}
		(*result).Write(replyBytes)
	}

	(*result).WriteString("]\n")

	return nil
}
