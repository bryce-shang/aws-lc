package subprocess

import (
	"encoding/json"

	"boringssl.googlesource.com/boringssl/atsec/common"
)

type tlsKDFTestGroupResponse struct {
	ID    uint64               `json:"tgId"`
	Tests []tlsKDFTestResponse `json:"tests"`
}

type tlsKDFTestResponse struct {
	ID              uint64 `json:"tcId"`
	MasterSecretHex string `json:"masterSecret"`
	KeyBlockHex     string `json:"keyBlock"`
}

func (o *tlsKDFTestResponse) Format() {
	o.MasterSecretHex = common.ToLowerCase(o.MasterSecretHex)
	o.KeyBlockHex = common.ToLowerCase(o.KeyBlockHex)
}

func ProcessExpectedKDFComponents(element json.RawMessage) ([]tlsKDFTestGroupResponse, error) {
	var testGroups struct {
		Groups []tlsKDFTestGroupResponse `json:"testGroups"`
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
