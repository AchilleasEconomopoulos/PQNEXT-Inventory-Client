package main

import (
	"encoding/json"
	"regexp"
	"testing"
)

func TestMergeCBOMsAssignsFreshSerialNumber(t *testing.T) {
	first := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","serialNumber":"urn:uuid:00000000-0000-4000-8000-000000000001","version":1,"metadata":{"timestamp":"2026-09-25T00:00:00Z"}}`)
	second := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:00000000-0000-4000-8000-000000000002","version":1}`)
	serialPattern := regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for _, docs := range [][][]byte{{first}, {first, second}} {
		serials := make([]string, 2)
		for i := range serials {
			merged, err := mergeCBOMs(docs)
			if err != nil {
				t.Fatal(err)
			}
			var result struct {
				SpecVersion  string          `json:"specVersion"`
				SerialNumber string          `json:"serialNumber"`
				Metadata     json.RawMessage `json:"metadata"`
			}
			if err := json.Unmarshal(merged, &result); err != nil {
				t.Fatal(err)
			}
			if result.SpecVersion != "1.7" || len(result.Metadata) == 0 {
				t.Fatalf("first CBOM version or metadata was not preserved: %s", merged)
			}
			if !serialPattern.MatchString(result.SerialNumber) ||
				result.SerialNumber == "urn:uuid:00000000-0000-4000-8000-000000000001" ||
				result.SerialNumber == "urn:uuid:00000000-0000-4000-8000-000000000002" {
				t.Fatalf("merged serial number=%q", result.SerialNumber)
			}
			serials[i] = result.SerialNumber
		}
		if serials[0] == serials[1] {
			t.Fatalf("two merged CBOMs have the same serial number %q", serials[0])
		}
	}
}
