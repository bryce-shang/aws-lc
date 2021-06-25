package subprocess

import (
	"encoding/json"

	"boringssl.googlesource.com/boringssl/atsec/common"
)

type aeadTestGroupResponse struct {
	ID    uint64             `json:"tgId"`
	Tests []aeadTestResponse `json:"tests"`
}

// TODO: why Bssl use pointer?
// because when the result is about encryption, there is no plain text.
// when the result is decryption, there is testPassed but no cipher text.
// overall, mixed results from ACVP server.
type aeadTestResponse struct {
	ID            uint64  `json:"tcId"`
	CiphertextHex *string `json:"ct,omitempty"`
	TagHex        string  `json:"tag,omitempty"`
	PlaintextHex  *string `json:"pt,omitempty"`
	Passed        *bool   `json:"testPassed,omitempty"`
}

func (b *aeadTestResponse) Format() {
	if b.CiphertextHex != nil {
		// encrypt result
		b.CiphertextHex = common.ToLowerCasePointer(b.CiphertextHex)
	} else {
		// decrypt result
		if b.Passed != nil {
			// 183471/592467/testvector-expected.json from atsec only shows |"testPassed": false| when pt is empty.
		} else {
			b.PlaintextHex = common.ToLowerCasePointer(b.PlaintextHex)
			// bssl always generates explict Passed flag for this test result.
			// see aead.go code.
			tmp := true
			b.Passed = &tmp
		}
	}
	b.TagHex = common.ToLowerCase(b.TagHex)
}

// ACVP-AES-KW
func ProcessExpectedAEAD(element json.RawMessage) ([]aeadTestGroupResponse, error) {
	var testGroups struct {
		Groups []aeadTestGroupResponse `json:"testGroups"`
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
