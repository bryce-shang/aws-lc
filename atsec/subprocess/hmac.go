package subprocess

import (
	"encoding/json"

	"boringssl.googlesource.com/boringssl/atsec/common"
)

type hmacTestGroupResponse struct {
	ID    uint64             `json:"tgId"`
	Tests []hmacTestResponse `json:"tests"`
}

type hmacTestResponse struct {
	ID     uint64 `json:"tcId"`
	MACHex string `json:"mac,omitempty"`
}

func (o *hmacTestResponse) Format() {
	o.MACHex = common.ToLowerCase(o.MACHex)
}

func ProcessExpectedHMAC(element json.RawMessage) ([]hmacTestGroupResponse, error) {
	var testGroups struct {
		Groups []hmacTestGroupResponse `json:"testGroups"`
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
