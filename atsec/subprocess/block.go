package subprocess

import (
	"encoding/json"

	"boringssl.googlesource.com/boringssl/atsec/common"
)

type blockCipherTestGroupResponse struct {
	ID    uint64                    `json:"tgId"`
	Tests []blockCipherTestResponse `json:"tests"`
}

type blockCipherTestResponse struct {
	ID            uint64                 `json:"tcId"`
	CiphertextHex string                 `json:"ct,omitempty"`
	PlaintextHex  string                 `json:"pt,omitempty"`
	MCTResults    []blockCipherMCTResult `json:"resultsArray,omitempty"`
}

func (b *blockCipherTestResponse) Format() {
	b.PlaintextHex = common.ToLowerCase(b.PlaintextHex)
	b.CiphertextHex = common.ToLowerCase(b.CiphertextHex)
}

type blockCipherMCTResult struct {
	KeyHex        string `json:"key,omitempty"`
	PlaintextHex  string `json:"pt"`
	CiphertextHex string `json:"ct"`
	IVHex         string `json:"iv,omitempty"`

	// 3DES tests serialise the key differently.
	Key1Hex string `json:"key1,omitempty"`
	Key2Hex string `json:"key2,omitempty"`
	Key3Hex string `json:"key3,omitempty"`
}

func (b *blockCipherMCTResult) Format() {
	b.KeyHex = common.ToLowerCase(b.KeyHex)
	b.PlaintextHex = common.ToLowerCase(b.PlaintextHex)
	b.CiphertextHex = common.ToLowerCase(b.CiphertextHex)
	b.IVHex = common.ToLowerCase(b.IVHex)
	b.Key1Hex = common.ToLowerCase(b.Key1Hex)
	b.Key2Hex = common.ToLowerCase(b.Key2Hex)
	b.Key3Hex = common.ToLowerCase(b.Key3Hex)
}

// ACVP-AES-CBC
func ProcessExpectedBlock(element json.RawMessage) ([]blockCipherTestGroupResponse, error) {
	var testGroups struct {
		Groups []blockCipherTestGroupResponse `json:"testGroups"`
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
