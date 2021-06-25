package subprocess

import (
	"encoding/json"

	"boringssl.googlesource.com/boringssl/atsec/common"
)

type hashTestGroupResponse struct {
	ID    uint64             `json:"tgId"`
	Tests []hashTestResponse `json:"tests"`
}

type hashTestResponse struct {
	ID         uint64          `json:"tcId"`
	DigestHex  string          `json:"md,omitempty"`
	MCTResults []hashMCTResult `json:"resultsArray,omitempty"`
}

type hashMCTResult struct {
	DigestHex string `json:"md"`
}

func (o *hashTestResponse) Format() {
	o.DigestHex = common.ToLowerCase(o.DigestHex)
}

func (o *hashMCTResult) Format() {
	o.DigestHex = common.ToLowerCase(o.DigestHex)
}

func ProcessExpectedHash(element json.RawMessage) ([]hashTestGroupResponse, error) {
	var testGroups struct {
		Groups []hashTestGroupResponse `json:"testGroups"`
	}

	if err := json.Unmarshal(element, &testGroups); err != nil {
		return nil, err
	}

	for i, group := range testGroups.Groups {
		for j, test := range group.Tests {
			test.Format()
			for k, mctResult := range test.MCTResults {
				mctResult.Format()
				test.MCTResults[k] = mctResult
			}
			group.Tests[j] = test
		}
		testGroups.Groups[i] = group
	}

	return testGroups.Groups, nil
}
