package subprocess

// TODO: RSA has thee mode: keyGen, sigGen and verify.
import (
	"encoding/json"
	// 	"boringssl.googlesource.com/boringssl/atsec/common"
)

type rsaTestVectorSet struct {
	Mode string `json:"mode"`
}

type rsaKeyGenTestGroupResponse struct {
	ID    uint64                  `json:"tgId"`
	Tests []rsaKeyGenTestResponse `json:"tests"`
}

type rsaKeyGenTestResponse struct {
	ID uint64 `json:"tcId"`
	E  string `json:"e"`
	P  string `json:"p"`
	Q  string `json:"q"`
	N  string `json:"n"`
	D  string `json:"d"`
}

type rsaSigGenTestGroupResponse struct {
	ID    uint64                  `json:"tgId"`
	N     string                  `json:"n"`
	E     string                  `json:"e"`
	Tests []rsaSigGenTestResponse `json:"tests"`
}

type rsaSigGenTestResponse struct {
	ID  uint64 `json:"tcId"`
	Sig string `json:"signature"`
}

type rsaSigVerTestGroupResponse struct {
	ID    uint64                  `json:"tgId"`
	Tests []rsaSigVerTestResponse `json:"tests"`
}

type rsaSigVerTestResponse struct {
	ID     uint64 `json:"tcId"`
	Passed bool   `json:"testPassed"`
}

// func (o *xtsTestResponse) Format() {
// 	o.PlaintextHex = common.ToLowerCase(o.PlaintextHex)
// 	o.CiphertextHex = common.ToLowerCase(o.CiphertextHex)
// }

// func processKeyGen(element json.RawMessage) (interface{}, error) {
//     var testGroups struct {
// 		Groups []rsaKeyGenTestGroupResponse `json:"testGroups"`
// 	}
// }
//
// func processSigGen(element json.RawMessage) (interface{}, error) {
// }
//
// func processSigVer(element json.RawMessage) (interface{}, error) {
// }

func ProcessExpectedRSA(element json.RawMessage) (interface{}, error) {
	return nil, nil
	//     var parsed rsaTestVectorSet
	// 	if err := json.Unmarshal(element, &parsed); err != nil {
	// 		return nil, err
	// 	}
	//
	// 	switch parsed.Mode {
	// 	case "keyGen":
	// 		return processKeyGen(element)
	// 	case "sigGen":
	// 		return processSigGen(element)
	// 	case "sigVer":
	// 		return processSigVer(element)
	// 	default:
	// 		return nil, fmt.Errorf("Unknown RSA mode %q", parsed.Mode)
	// 	}
}
