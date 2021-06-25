package subprocess

import (
	"encoding/json"

	"boringssl.googlesource.com/boringssl/atsec/common"
)

type ecdsaTestGroupResponse struct {
	ID    uint64              `json:"tgId"`
	Tests []ecdsaTestResponse `json:"tests"`
	QxHex string              `json:"qx,omitempty"`
	QyHex string              `json:"qy,omitempty"`
}

type ecdsaTestResponse struct {
	ID     uint64 `json:"tcId"`
	DHex   string `json:"d,omitempty"`
	QxHex  string `json:"qx,omitempty"`
	QyHex  string `json:"qy,omitempty"`
	RHex   string `json:"r,omitempty"`
	SHex   string `json:"s,omitempty"`
	Passed *bool  `json:"testPassed,omitempty"` // using pointer so value is not omitted when it is false
}

func (o *ecdsaTestResponse) Format() {
	o.DHex = common.ToLowerCase(o.DHex)
	o.QxHex = common.ToLowerCase(o.QxHex)
	o.QyHex = common.ToLowerCase(o.QyHex)
	o.RHex = common.ToLowerCase(o.RHex)
	o.SHex = common.ToLowerCase(o.SHex)
}

func ProcessExpectedECDSA(element json.RawMessage) ([]ecdsaTestGroupResponse, error) {
	var testGroups struct {
		Groups []ecdsaTestGroupResponse `json:"testGroups"`
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
