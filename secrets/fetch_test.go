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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFetchInline(t *testing.T) {
	t.Parallel()
	f := parseYAML(t, "password: hunter2\n")
	v, err := f.Fetch(t.Context())
	require.NoError(t, err)
	require.Equal(t, "hunter2", v)
	require.True(t, f.Immutable())
	require.Equal(t, "inline", f.Description())
}

func TestFetchFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "pw")
	require.NoError(t, os.WriteFile(path, []byte("  hunter2\n\n"), 0o600))

	// A relative path is resolved against the directory set with SetDirectory.
	f := parseYAML(t, "password:\n  file: pw\n")
	f.SetDirectory(dir)
	require.False(t, f.Immutable())
	require.Equal(t, "file "+path, f.Description())

	v, err := f.Fetch(t.Context())
	require.NoError(t, err)
	require.Equalf(t, "hunter2", v, "surrounding whitespace is trimmed like config.FileSecret")

	// The file is read on every Fetch: a rotated value is visible immediately.
	require.NoError(t, os.WriteFile(path, []byte("rotated"), 0o600))
	v, err = f.Fetch(t.Context())
	require.NoError(t, err)
	require.Equal(t, "rotated", v)

	require.NoError(t, os.Remove(path))
	_, err = f.Fetch(t.Context())
	require.ErrorContains(t, err, "unable to read file "+path)
}

func TestFetchErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, in, wantErr string
	}{
		{name: "not configured", in: "name: x\n", wantErr: "not configured"},
		{name: "file with mapping config", in: "password:\n  file: {path: /x}\n", wantErr: `secret provider "file" expects the path of the file`},
		{name: "file with empty config", in: "password:\n  file:\n", wantErr: `secret provider "file" expects the path of the file`},
		{name: "other providers need a manager", in: "password:\n  kubernetes: {namespace: ns, name: app, key: pw}\n", wantErr: `secret provider "kubernetes" is not available without a secrets manager`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseYAML(t, tc.in).Fetch(t.Context())
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}
