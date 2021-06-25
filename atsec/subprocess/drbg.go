package subprocess

import (
	"encoding/json"

	"boringssl.googlesource.com/boringssl/atsec/common"
)

type drbgTestGroupResponse struct {
	ID    uint64             `json:"tgId"`
	Tests []drbgTestResponse `json:"tests"`
}

type drbgTestResponse struct {
	ID     uint64 `json:"tcId"`
	OutHex string `json:"returnedBits,omitempty"`
}

func (o *drbgTestResponse) Format() {
	o.OutHex = common.ToLowerCase(o.OutHex)
}

func ProcessExpectedDRBG(element json.RawMessage) ([]drbgTestGroupResponse, error) {
	var testGroups struct {
		Groups []drbgTestGroupResponse `json:"testGroups"`
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
