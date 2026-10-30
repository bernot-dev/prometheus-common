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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v2"
)

// holder is a minimal owner struct, as config packages would embed Field.
type holder struct {
	Name     string `yaml:"name,omitempty" json:"name,omitempty"`
	Password Field  `yaml:"password,omitempty" json:"password,omitzero"`
}

func parseYAML(t *testing.T, in string) Field {
	t.Helper()
	var h holder
	require.NoError(t, yaml.UnmarshalStrict([]byte(in), &h))
	return h.Password
}

func TestFieldUnmarshal(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		yaml, json   string // Either may be empty to skip that decoder.
		wantInline   string
		wantProvider string
		wantErr      string
	}{
		{name: "plain string", yaml: "password: hunter2\n", json: `{"password":"hunter2"}`, wantInline: "hunter2"},
		{name: "numeric scalar keeps its text", yaml: "password: 12345\n", json: `{"password":12345}`, wantInline: "12345"},
		{name: "yaml 1.1 boolean keeps its text", yaml: "password: yes\n", wantInline: "yes"},
		{name: "null is zero", yaml: "password: null\n", json: `{"password":null}`},
		{name: "empty string is zero", yaml: "password: \"\"\n", json: `{"password":""}`},
		{name: "absent is zero", yaml: "name: x\n", json: `{"name":"x"}`},
		{name: "file provider", yaml: "password:\n  file: /run/secrets/pw\n", json: `{"password":{"file":"/run/secrets/pw"}}`, wantProvider: "file"},
		{name: "provider with mapping config", yaml: "password:\n  kubernetes: {namespace: ns, name: app, key: pw}\n", json: `{"password":{"kubernetes":{"namespace":"ns","name":"app","key":"pw"}}}`, wantProvider: "kubernetes"},
		{name: "provider with scalar config", yaml: "password:\n  vault: secret/data/app#pw\n", json: `{"password":{"vault":"secret/data/app#pw"}}`, wantProvider: "vault"},
		{name: "provider with empty config", yaml: "password:\n  kubernetes: {}\n", json: `{"password":{"kubernetes":{}}}`, wantProvider: "kubernetes"},
		{name: "provider with null config", yaml: "password:\n  kubernetes:\n", json: `{"password":{"kubernetes":null}}`, wantProvider: "kubernetes"},
		{name: "sequence is rejected", yaml: "password: [a, b]\n", json: `{"password":["a","b"]}`, wantErr: "must be a string or a mapping with a single provider key"},
		{name: "empty mapping is rejected", yaml: "password: {}\n", json: `{"password":{}}`, wantErr: "exactly one key, got 0"},
		{name: "two providers are rejected", yaml: "password:\n  file: /x\n  kubernetes: {name: a}\n", json: `{"password":{"file":"/x","kubernetes":{"name":"a"}}}`, wantErr: "exactly one key, got 2"},
		{name: "empty provider name is rejected", yaml: "password:\n  \"\": /x\n", json: `{"password":{"":"/x"}}`, wantErr: "provider name must not be empty"},
		{name: "owner stays strict", yaml: "password: x\nbogus: 1\n", wantErr: "field bogus not found"},
	} {
		decoders := map[string]func() (holder, error){
			"yaml": func() (h holder, err error) { return h, yaml.UnmarshalStrict([]byte(tc.yaml), &h) },
			"json": func() (h holder, err error) { return h, json.Unmarshal([]byte(tc.json), &h) },
		}
		for _, enc := range []string{"yaml", "json"} {
			if (enc == "yaml" && tc.yaml == "") || (enc == "json" && tc.json == "") {
				continue
			}
			t.Run(tc.name+"/"+enc, func(t *testing.T) {
				t.Parallel()
				h, err := decoders[enc]()
				if tc.wantErr != "" {
					require.ErrorContains(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
				require.Equal(t, tc.wantInline == "" && tc.wantProvider == "", h.Password.IsZero())
				require.Equal(t, tc.wantProvider, h.Password.Provider())
				if tc.wantInline != "" {
					v, err := h.Password.Fetch(t.Context())
					require.NoError(t, err)
					require.Equal(t, tc.wantInline, v)
				}
			})
		}
	}
}

func TestFieldEqual(t *testing.T) {
	t.Parallel()
	a := parseYAML(t, "password:\n  kubernetes:\n    namespace: ns\n    name: app\n    key: pw\n    port: 8200\n")
	b := parseYAML(t, "password:\n  kubernetes: {port: 8200, key: pw, name: app, namespace: ns}\n")
	require.Truef(t, a.Equal(b), "same provider config in a different key order must be equal")
	require.False(t, a.Equal(parseYAML(t, "password:\n  kubernetes: {port: 8201, key: pw, name: app, namespace: ns}\n")))
	require.False(t, a.Equal(parseYAML(t, "password:\n  vault: {port: 8200, key: pw, name: app, namespace: ns}\n")))
	require.False(t, a.Equal(Field{}))
	require.True(t, Field{}.Equal(Inline("")))
	require.True(t, Inline("x").Equal(parseYAML(t, "password: x\n")))
	require.False(t, Inline("x").Equal(Inline("y")))

	var j holder
	require.NoError(t, json.Unmarshal([]byte(`{"password":{"kubernetes":{"port":8200,"key":"pw","name":"app","namespace":"ns"}}}`), &j))
	require.Truef(t, a.Equal(j.Password), "JSON and YAML forms of the same config must be equal")
}

func TestFieldCopiesShareState(t *testing.T) {
	t.Parallel()
	original := parseYAML(t, "password:\n  file: pw\n")
	copied := original
	copied.SetDirectory("/etc/prometheus")
	require.Equal(t, "file "+filepath.Join("/etc/prometheus", "pw"), original.Description())
	require.True(t, original.Equal(copied))
}

func TestFieldMarshal(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		in       holder
		wantYAML string
		wantJSON string
	}{
		{name: "plain string is redacted", in: holder{Name: "x", Password: Inline("hunter2")}, wantYAML: "name: x\npassword: <secret>\n", wantJSON: `{"name":"x","password":"<secret>"}`},
		{name: "zero is omitted", in: holder{Name: "x"}, wantYAML: "name: x\n", wantJSON: `{"name":"x"}`},
		{name: "scalar provider config", in: holder{Password: parseYAML(t, "password:\n  file: /run/pw\n")}, wantYAML: "password:\n  file: /run/pw\n", wantJSON: `{"password":{"file":"/run/pw"}}`},
		{
			name:     "mapping provider config is emitted unchanged",
			in:       holder{Password: parseYAML(t, "password:\n  kubernetes:\n    key: pw\n    name: app\n    nested:\n      list: [1, two]\n")},
			wantYAML: "password:\n  kubernetes:\n    key: pw\n    name: app\n    nested:\n      list:\n      - 1\n      - two\n",
			wantJSON: `{"password":{"kubernetes":{"key":"pw","name":"app","nested":{"list":[1,"two"]}}}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := yaml.Marshal(tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.wantYAML, string(out))
			j, err := json.Marshal(tc.in)
			require.NoError(t, err)
			require.JSONEq(t, tc.wantJSON, string(j))

			// Provider configurations round-trip through both encodings.
			if tc.in.Password.Provider() != "" {
				var y, k holder
				require.NoError(t, yaml.UnmarshalStrict(out, &y))
				require.NoError(t, json.Unmarshal(j, &k))
				require.True(t, tc.in.Password.Equal(y.Password))
				require.True(t, tc.in.Password.Equal(k.Password))
			}
		})
	}
}

func TestFieldSetDirectory(t *testing.T) {
	t.Parallel()
	joined := filepath.Join("/etc/prometheus", "secrets/pw")
	for _, tc := range []struct {
		name, in, want string
	}{
		{name: "relative file path is joined", in: "password:\n  file: secrets/pw\n", want: "password:\n  file: " + joined + "\n"},
		{name: "absolute file path is unchanged", in: "password:\n  file: /run/pw\n", want: "password:\n  file: /run/pw\n"},
		{name: "other providers are unchanged", in: "password:\n  kubernetes: relative\n", want: "password:\n  kubernetes: relative\n"},
		{name: "plain string is unchanged", in: "password: relative\n", want: "password: <secret>\n"},
		{name: "invalid file config is left for Fetch to report", in: "password:\n  file: {path: relative}\n", want: "password:\n  file:\n    path: relative\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := holder{Password: parseYAML(t, tc.in)}
			h.Password.SetDirectory("/etc/prometheus")
			out, err := yaml.Marshal(h)
			require.NoError(t, err)
			require.Equal(t, tc.want, string(out))
		})
	}
	var zero Field
	zero.SetDirectory("/etc/prometheus")
	require.True(t, zero.IsZero())
}
