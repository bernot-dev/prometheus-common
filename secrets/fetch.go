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
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v2"
)

// fileProvider is the key of the built-in file provider. Its configuration is
// the path of the file holding the secret.
const fileProvider = "file"

// Fetch returns the secret. Plain strings are returned as is and the built-in
// file provider reads its file on every call, so rotated files are picked up
// without coordination. Fields using any other provider return an error until
// a component that knows the provider supplies their value.
//
// Together with Description and Immutable this gives Field the method set of
// the config package's SecretReader interface.
func (f Field) Fetch(context.Context) (string, error) {
	switch {
	case f.c == nil:
		return "", errors.New("secret is not configured")
	case f.c.provider == "":
		return f.c.inline, nil
	case f.c.provider == fileProvider:
		path, err := f.filePath()
		if err != nil {
			return "", err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("unable to read file %s: %w", path, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", fmt.Errorf("secret provider %q is not available without a secrets manager", f.c.provider)
}

// Description describes where the secret comes from, for logs and errors. It
// never contains the secret value.
func (f Field) Description() string {
	switch {
	case f.c == nil:
		return "unconfigured secret"
	case f.c.provider == "":
		return "inline"
	case f.c.provider == fileProvider:
		path, _ := f.filePath()
		return "file " + path
	}
	return f.c.provider + " secret"
}

// Immutable reports whether the value can never change, which is only true
// for plain strings.
func (f Field) Immutable() bool {
	return f.c != nil && f.c.provider == ""
}

// filePath returns the configured path of the file provider.
func (f Field) filePath() (string, error) {
	var path string
	if err := yaml.UnmarshalStrict([]byte(f.c.cfg), &path); err != nil || path == "" {
		return "", errors.New(`secret provider "file" expects the path of the file, for example "file: /run/secrets/password"`)
	}
	return path, nil
}
