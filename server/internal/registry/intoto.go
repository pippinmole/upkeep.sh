package registry

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// in-toto statements (https://in-toto.io/Statement/v0.1 and v1) wrap an
// attestation's predicate with the subjects it is about. BuildKit stores
// them unsigned; signed ones come in a DSSE envelope whose payload is the
// statement. Signatures aren't verified: the statement is fetched by
// digest from the image's own index, which is what we trust anyway.

type statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate json.RawMessage `json:"predicate"`

	// DSSE envelope fields.
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
}

// unwrapStatement returns the SBOM format and document of an in-toto
// statement (or DSSE envelope around one) whose predicate is an SBOM
// about manifestDigest. format is "" when b isn't such a statement: not a
// statement at all, a predicate that isn't an SBOM, or subjects that don't
// include manifestDigest (a statement without subjects is accepted: its
// location in the image's index already ties it to the manifest).
func unwrapStatement(b []byte, manifestDigest string) (format string, doc []byte, err error) {
	var st statement
	if err := json.Unmarshal(b, &st); err != nil {
		return "", nil, fmt.Errorf("attestation: %w", err)
	}
	if st.PayloadType != "" && st.Payload != "" {
		if !strings.Contains(st.PayloadType, "in-toto") {
			return "", nil, nil
		}
		payload, err := base64.StdEncoding.DecodeString(st.Payload)
		if err != nil {
			return "", nil, fmt.Errorf("attestation: DSSE payload: %w", err)
		}
		if err := json.Unmarshal(payload, &st); err != nil {
			return "", nil, fmt.Errorf("attestation: DSSE statement: %w", err)
		}
	}
	if !strings.Contains(st.Type, "in-toto.io/Statement") || len(st.Predicate) == 0 {
		return "", nil, nil
	}
	format = sbomPredicate(st.PredicateType)
	if format == "" {
		return "", nil, nil
	}
	if len(st.Subject) > 0 {
		want, _ := strings.CutPrefix(manifestDigest, "sha256:")
		found := false
		for _, s := range st.Subject {
			if strings.EqualFold(s.Digest["sha256"], want) {
				found = true
				break
			}
		}
		if !found {
			return "", nil, nil
		}
	}
	return format, st.Predicate, nil
}
