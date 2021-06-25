package subprocess

import (
	"encoding/json"

	"boringssl.googlesource.com/boringssl/atsec/common"
)

type keyedMACTestGroupResponse struct {
	ID    uint64                 `json:"tgId"`
	Tests []keyedMACTestResponse `json:"tests"`
}

type keyedMACTestResponse struct {
	ID     uint64 `json:"tcId"`
	MACHex string `json:"mac,omitempty"`
	Passed *bool  `json:"testPassed,omitempty"`
}

func (o *keyedMACTestResponse) Format() {
	o.MACHex = common.ToLowerCase(o.MACHex)
}

// CMAC-AES
func ProcessExpectedKeyedMac(element json.RawMessage) ([]keyedMACTestGroupResponse, error) {
	var testGroups struct {
		Groups []keyedMACTestGroupResponse `json:"testGroups"`
	}

	if err := json.Unmarshal(element, &testGroups); err != nil {
		return nil, err
	}

	for i, group := range testGroups.Groups {
		for j, test := range group.Tests {
			test.Format()
			group.Tests[j] = test
		}
		testGroups.Groups[i] = group
	}

	return testGroups.Groups, nil
}
