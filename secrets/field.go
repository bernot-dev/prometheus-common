// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"go.yaml.in/yaml/v2"
)

// Field is a secret configuration value: either a plain string or a reference
// to a secret provider. The zero value means "not configured".
//
// Field is a handle whose copies share state; compare Fields with Equal.
type Field struct {
	c *cell
}

// cell is the state shared by all copies of a Field.
type cell struct {
	// inline holds the plain-string form.
	inline string
	// provider is the key of the provider mapping, for example "file".
	provider string
	// cfg is the provider's configuration as canonical JSON (object keys are
	// sorted), which makes equal configurations compare equal.
	cfg string
}

// Inline returns a Field holding a plain string, the programmatic equivalent
// of writing the string in the configuration.
func Inline(s string) Field {
	if s == "" {
		return Field{}
	}
	return Field{c: &cell{inline: s}}
}

// IsZero reports whether the Field is not configured. It also makes
// `omitempty` work for YAML and `omitzero` for JSON.
func (f Field) IsZero() bool {
	return f.c == nil
}

// Equal reports whether both Fields are configured the same way.
func (f Field) Equal(o Field) bool {
	if f.c == nil || o.c == nil {
		return f.c == o.c
	}
	return f.c.inline == o.c.inline && f.c.provider == o.c.provider && f.c.cfg == o.c.cfg
}

// Provider returns the name of the configured provider, or "" for a plain
// string or an unconfigured Field.
func (f Field) Provider() string {
	if f.c == nil {
		return ""
	}
	return f.c.provider
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (f *Field) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		*f = Inline(s)
		return nil
	}
	var m map[string]any
	if err := unmarshal(&m); err != nil {
		return fmt.Errorf("secret must be a string or a mapping with a single provider key: %w", err)
	}
	if len(m) != 1 {
		return fmt.Errorf("secret provider mapping must have exactly one key, got %d", len(m))
	}
	for name, cfg := range m {
		if name == "" {
			return errors.New("secret provider name must not be empty")
		}
		b, err := json.Marshal(stringKeys(cfg))
		if err != nil {
			return fmt.Errorf("secret provider %q config: %w", name, err)
		}
		*f = Field{c: &cell{provider: name, cfg: string(b)}}
	}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler. JSON is a subset of YAML, so the
// same rules apply.
func (f *Field) UnmarshalJSON(b []byte) error {
	return yaml.Unmarshal(b, f)
}

// MarshalYAML implements yaml.Marshaler. Plain strings are redacted; provider
// configurations are emitted unchanged.
func (f Field) MarshalYAML() (any, error) {
	switch {
	case f.c == nil:
		return nil, nil
	case f.c.provider != "":
		var cfg any
		if err := yaml.Unmarshal([]byte(f.c.cfg), &cfg); err != nil {
			return nil, err
		}
		return map[string]any{f.c.provider: cfg}, nil
	}
	return "<secret>", nil
}

// MarshalJSON implements json.Marshaler with the same policy as MarshalYAML.
func (f Field) MarshalJSON() ([]byte, error) {
	switch {
	case f.c == nil:
		return []byte("null"), nil
	case f.c.provider != "":
		return json.Marshal(map[string]json.RawMessage{f.c.provider: json.RawMessage(f.c.cfg)})
	}
	return json.Marshal("<secret>")
}

// SetDirectory joins a relative path of the file provider with dir. Fields
// that do not use the file provider are left unchanged.
func (f *Field) SetDirectory(dir string) {
	if f.Provider() != fileProvider {
		return
	}
	path, err := f.filePath()
	if err != nil || filepath.IsAbs(path) {
		return
	}
	if b, err := json.Marshal(filepath.Join(dir, path)); err == nil {
		f.c.cfg = string(b)
	}
}

// stringKeys converts the map[any]any values produced by yaml.v2 into
// map[string]any so that they can be encoded as JSON.
func stringKeys(v any) any {
	switch v := v.(type) {
	case map[any]any:
		m := make(map[string]any, len(v))
		for k, val := range v {
			m[fmt.Sprint(k)] = stringKeys(val)
		}
		return m
	case []any:
		for i, val := range v {
			v[i] = stringKeys(val)
		}
	}
	return v
}
