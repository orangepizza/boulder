//go:build integration

package integration

import (
	"fmt"
	"strings"
	"testing"

	"github.com/eggsampler/acme/v3"

	"github.com/letsencrypt/boulder/test"
)

// TestTooBigOrderError tests that submitting an order with more than 100
// identifiers produces the expected problem result.
func TestTooBigOrderError(t *testing.T) {
	t.Parallel()

	var idents []acme.Identifier
	for i := range 101 {
		idents = append(idents, acme.Identifier{Type: "dns", Value: fmt.Sprintf("%d.example.com", i)})
	}

	_, err := authAndIssue(nil, nil, idents, true, "")
	test.AssertError(t, err, "authAndIssue failed")

	var prob acme.Problem
	test.AssertErrorWraps(t, err, &prob)
	test.AssertEquals(t, prob.Type, "urn:ietf:params:acme:error:malformed")
	test.AssertContains(t, prob.Detail, "Order cannot contain more than 100 identifiers")
}

// TestAccountEmailError tests that registering a new account, or updating an
// account, with invalid contact information produces the expected problem
// result to ACME clients.
func TestAccountEmailError(t *testing.T) {
	t.Parallel()

	// The registrations.contact field is VARCHAR(191). 175 'a' characters plus
	// the prefix "mailto:" and the suffix "@a.com" makes exactly 191 bytes of
	// encoded JSON. The correct size to hit our maximum DB field length.
	var longStringBuf strings.Builder
	longStringBuf.WriteString("mailto:")
	for range 175 {
		longStringBuf.WriteRune('a')
	}
	longStringBuf.WriteString("@a.com")

	createErrorPrefix := "Error creating new account :: "
	updateErrorPrefix := "Unable to update account :: invalid contact: "

	testCases := []struct {
		name               string
		contacts           []string
		expectedProbType   string
		expectedProbDetail string
	}{
		{
			name:               "empty contact",
			contacts:           []string{"mailto:valid@valid.com", ""},
			expectedProbType:   "urn:ietf:params:acme:error:invalidContact",
			expectedProbDetail: `empty contact`,
		},
		{
			name:               "empty proto",
			contacts:           []string{"mailto:valid@valid.com", " "},
			expectedProbType:   "urn:ietf:params:acme:error:unsupportedContact",
			expectedProbDetail: `only contact scheme 'mailto:' is supported`,
		},
		{
			name:               "empty mailto",
			contacts:           []string{"mailto:valid@valid.com", "mailto:"},
			expectedProbType:   "urn:ietf:params:acme:error:invalidContact",
			expectedProbDetail: `unable to parse email address`,
		},
		{
			name:               "non-ascii mailto",
			contacts:           []string{"mailto:valid@valid.com", "mailto:cpu@l̴etsencrypt.org"},
			expectedProbType:   "urn:ietf:params:acme:error:invalidContact",
			expectedProbDetail: `contact email contains non-ASCII characters`,
		},
		{
			name:               "too many contacts",
			contacts:           []string{"a", "b", "c", "d"},
			expectedProbType:   "urn:ietf:params:acme:error:malformed",
			expectedProbDetail: `too many contacts provided: 4 > 3`,
		},
		{
			name:               "invalid contact",
			contacts:           []string{"mailto:valid@valid.com", "mailto:a@"},
			expectedProbType:   "urn:ietf:params:acme:error:invalidContact",
			expectedProbDetail: `unable to parse email address`,
		},
		{
			name:               "forbidden contact domain",
			contacts:           []string{"mailto:valid@valid.com", "mailto:a@example.com"},
			expectedProbType:   "urn:ietf:params:acme:error:invalidContact",
			expectedProbDetail: "contact email has forbidden domain \"example.com\"",
		},
		{
			name:               "contact domain invalid TLD",
			contacts:           []string{"mailto:valid@valid.com", "mailto:a@example.cpu"},
			expectedProbType:   "urn:ietf:params:acme:error:invalidContact",
			expectedProbDetail: `contact email has invalid domain: Domain name does not end with a valid public suffix (TLD)`,
		},
		{
			name:               "contact domain invalid",
			contacts:           []string{"mailto:valid@valid.com", "mailto:a@example./.com"},
			expectedProbType:   "urn:ietf:params:acme:error:invalidContact",
			expectedProbDetail: "contact email has invalid domain: Domain name contains an invalid character",
		},
		{
			name: "too long contact",
			contacts: []string{
				longStringBuf.String(),
			},
			expectedProbType:   "urn:ietf:params:acme:error:invalidContact",
			expectedProbDetail: `too many/too long contact(s). Please use shorter or fewer email addresses`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// First try registering a new account and ensuring the expected problem occurs
			var prob acme.Problem
			_, err := makeClient(tc.contacts...)
			if err != nil {
				test.AssertErrorWraps(t, err, &prob)
				test.AssertEquals(t, prob.Type, tc.expectedProbType)
				test.AssertEquals(t, prob.Detail, createErrorPrefix+tc.expectedProbDetail)
			} else {
				t.Errorf("expected %s type problem for %q, got nil",
					tc.expectedProbType, strings.Join(tc.contacts, ","))
			}

			// Next try making a client with a good contact and updating with the test
			// case contact info. The same problem should occur.
			c, err := makeClient("mailto:valid@valid.com")
			test.AssertNotError(t, err, "failed to create account with valid contact")
			_, err = c.UpdateAccount(c.Account, tc.contacts...)
			if err != nil {
				test.AssertErrorWraps(t, err, &prob)
				test.AssertEquals(t, prob.Type, tc.expectedProbType)
				test.AssertEquals(t, prob.Detail, updateErrorPrefix+tc.expectedProbDetail)
			} else {
				t.Errorf("expected %s type problem after updating account to %q, got nil",
					tc.expectedProbType, strings.Join(tc.contacts, ","))
			}
		})
	}
}

func TestRejectedIdentifier(t *testing.T) {
	t.Parallel()

	// When a single malformed name is provided, we correctly reject it.
	idents := []acme.Identifier{
		{Type: "dns", Value: "яџ–Х6яяdь}"},
	}
	_, err := authAndIssue(nil, nil, idents, true, "")
	test.AssertError(t, err, "issuance should fail for one malformed name")
	var prob acme.Problem
	test.AssertErrorWraps(t, err, &prob)
	test.AssertEquals(t, prob.Type, "urn:ietf:params:acme:error:rejectedIdentifier")
	test.AssertContains(t, prob.Detail, "Domain name contains an invalid character")

	// When multiple malformed names are provided, we correctly reject all of
	// them and reflect this in suberrors. This test ensures that the way we
	// encode these errors across the gRPC boundary is resilient to non-ascii
	// characters.
	idents = []acme.Identifier{
		{Type: "dns", Value: "o-"},
		{Type: "dns", Value: "ш№Ў"},
		{Type: "dns", Value: "р±y"},
		{Type: "dns", Value: "яџ–Х6яя"},
		{Type: "dns", Value: "яџ–Х6яя`ь"},
	}
	_, err = authAndIssue(nil, nil, idents, true, "")
	test.AssertError(t, err, "issuance should fail for multiple malformed names")
	test.AssertErrorWraps(t, err, &prob)
	test.AssertEquals(t, prob.Type, "urn:ietf:params:acme:error:rejectedIdentifier")
	test.AssertContains(t, prob.Detail, "Domain name contains an invalid character")
	test.AssertContains(t, prob.Detail, "and 4 more problems")
}
