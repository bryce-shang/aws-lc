package subprocess

import (
	"encoding/json"

	"boringssl.googlesource.com/boringssl/atsec/common"
)

type xtsTestGroupResponse struct {
	ID    uint64            `json:"tgId"`
	Tests []xtsTestResponse `json:"tests"`
}

type xtsTestResponse struct {
	ID            uint64 `json:"tcId"`
	PlaintextHex  string `json:"pt,omitempty"`
	CiphertextHex string `json:"ct,omitempty"`
}

func (o *xtsTestResponse) Format() {
	o.PlaintextHex = common.ToLowerCase(o.PlaintextHex)
	o.CiphertextHex = common.ToLowerCase(o.CiphertextHex)
}

func ProcessExpectedXTS(element json.RawMessage) ([]xtsTestGroupResponse, error) {
	var testGroups struct {
		Groups []xtsTestGroupResponse `json:"testGroups"`
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
