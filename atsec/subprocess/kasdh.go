package subprocess

import (
	"encoding/json"

	"boringssl.googlesource.com/boringssl/atsec/common"
)

type kasDHTestGroupResponse struct {
	ID    uint64              `json:"tgId"`
	Tests []kasDHTestResponse `json:"tests"`
}

type kasDHTestResponse struct {
	ID             uint64 `json:"tcId"`
	LocalPublicHex string `json:"ephemeralPublicIut,omitempty"`
	ResultHex      string `json:"z,omitempty"`
	Passed         *bool  `json:"testPassed,omitempty"`
}

func (o *kasDHTestResponse) Format() {
	o.LocalPublicHex = common.ToLowerCase(o.LocalPublicHex)
	o.ResultHex = common.ToLowerCase(o.ResultHex)
}

func ProcessExpectedKASDH(element json.RawMessage) ([]kasDHTestGroupResponse, error) {
	var testGroups struct {
		Groups []kasDHTestGroupResponse `json:"testGroups"`
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
