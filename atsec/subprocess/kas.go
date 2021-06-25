package subprocess

import (
	"encoding/json"

	"boringssl.googlesource.com/boringssl/atsec/common"
)

type kasTestGroupResponse struct {
	ID    uint64            `json:"tgId"`
	Tests []kasTestResponse `json:"tests"`
}

type kasTestResponse struct {
	ID uint64 `json:"tcId"`

	EphemeralXHex string `json:"ephemeralPublicIutX,omitempty"`
	EphemeralYHex string `json:"ephemeralPublicIutY,omitempty"`

	StaticXHex string `json:"staticPublicIutX,omitempty"`
	StaticYHex string `json:"staticPublicIutY,omitempty"`

	ResultHex string `json:"z,omitempty"`
	Passed    *bool  `json:"testPassed,omitempty"`
}

func (o *kasTestResponse) Format() {
	o.EphemeralXHex = common.ToLowerCase(o.EphemeralXHex)
	o.EphemeralYHex = common.ToLowerCase(o.EphemeralYHex)
	o.StaticXHex = common.ToLowerCase(o.StaticXHex)
	o.StaticYHex = common.ToLowerCase(o.StaticYHex)
	o.ResultHex = common.ToLowerCase(o.ResultHex)
}

func ProcessExpectedKAS(element json.RawMessage) ([]kasTestGroupResponse, error) {
	var testGroups struct {
		Groups []kasTestGroupResponse `json:"testGroups"`
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
