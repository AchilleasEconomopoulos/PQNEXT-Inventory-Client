package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// mergeCBOMs merges several CycloneDX JSON documents into one.
//
// The first document is the base: its specVersion, metadata, and every other
// top-level field are preserved as-is. Components and dependencies from all
// documents are combined into it, de-duplicated by bom-ref (falling back to
// name+version+purl, then a content hash, for components).
//
// This is a STRUCTURAL merge. It intentionally does not reconcile
// metadata.tools across differing spec versions, and it only understands the
// "ref"/"dependsOn" shape of dependency entries. See README "Merge limitations".
func mergeCBOMs(docs [][]byte) ([]byte, error) {
	if len(docs) == 0 {
		return nil, fmt.Errorf("no documents to merge")
	}

	// Base document as a generic object so we preserve every top-level field.
	base := map[string]json.RawMessage{}
	if err := json.Unmarshal(docs[0], &base); err != nil {
		return nil, fmt.Errorf("parsing base CBOM: %w", err)
	}

	var components []json.RawMessage
	seenComp := map[string]bool{}

	deps := map[string]*dependency{} // ref -> merged dependency
	var depOrder []string            // preserves first-seen order

	addComponents := func(raw json.RawMessage) {
		if len(raw) == 0 {
			return
		}
		var list []json.RawMessage
		if err := json.Unmarshal(raw, &list); err != nil {
			return
		}
		for _, c := range list {
			k := componentKey(c)
			if seenComp[k] {
				continue
			}
			seenComp[k] = true
			components = append(components, c)
		}
	}

	addDependencies := func(raw json.RawMessage) {
		if len(raw) == 0 {
			return
		}
		var list []dependency
		if err := json.Unmarshal(raw, &list); err != nil {
			return
		}
		for _, d := range list {
			if d.Ref == "" {
				continue
			}
			existing, ok := deps[d.Ref]
			if !ok {
				cp := d
				deps[d.Ref] = &cp
				depOrder = append(depOrder, d.Ref)
				continue
			}
			existing.DependsOn = unionStrings(existing.DependsOn, d.DependsOn)
		}
	}

	for _, doc := range docs {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(doc, &obj); err != nil {
			return nil, fmt.Errorf("parsing CBOM: %w", err)
		}
		addComponents(obj["components"])
		addDependencies(obj["dependencies"])
	}

	// Write the merged slices back into the base document.
	if len(components) > 0 {
		b, err := json.Marshal(components)
		if err != nil {
			return nil, err
		}
		base["components"] = b
	}
	if len(depOrder) > 0 {
		ordered := make([]*dependency, 0, len(depOrder))
		for _, ref := range depOrder {
			ordered = append(ordered, deps[ref])
		}
		b, err := json.Marshal(ordered)
		if err != nil {
			return nil, err
		}
		base["dependencies"] = b
	}

	return json.MarshalIndent(base, "", "  ")
}

// dependency is the common CycloneDX dependency shape.
type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// componentKey returns a stable de-duplication key for a component.
func componentKey(raw json.RawMessage) string {
	var c struct {
		BOMRef  string `json:"bom-ref"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Purl    string `json:"purl"`
	}
	_ = json.Unmarshal(raw, &c)
	if c.BOMRef != "" {
		return "ref:" + c.BOMRef
	}
	if c.Name != "" || c.Version != "" || c.Purl != "" {
		return "nvp:" + c.Name + "|" + c.Version + "|" + c.Purl
	}
	// Fall back to a content hash so identical anonymous components collapse.
	sum := sha1.Sum(raw)
	return "sha1:" + hex.EncodeToString(sum[:])
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
