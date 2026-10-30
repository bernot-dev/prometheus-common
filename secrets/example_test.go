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

package secrets_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v2"

	"github.com/prometheus/common/secrets"
)

// BasicAuth shows how a configuration struct embeds a Field: the same YAML
// key accepts a plain string or a provider.
type BasicAuth struct {
	Username string        `yaml:"username"`
	Password secrets.Field `yaml:"password,omitempty"`
}

func Example() {
	check := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	fetch := func(f secrets.Field) {
		password, err := f.Fetch(context.Background())
		check(err)
		fmt.Printf("%s from %s (immutable=%t)\n", password, f.Description(), f.Immutable())
	}

	// A plain string is used as is and never revealed when marshaling.
	var cfg BasicAuth
	check(yaml.UnmarshalStrict([]byte("username: admin\npassword: hunter2\n"), &cfg))
	fetch(cfg.Password)
	out, err := yaml.Marshal(cfg)
	check(err)
	fmt.Print(string(out))

	// The built-in file provider reads the file on every Fetch. Relative paths
	// are resolved against the configuration's directory.
	dir, err := os.MkdirTemp("", "secrets-example")
	check(err)
	defer os.RemoveAll(dir)
	check(os.WriteFile(filepath.Join(dir, "password"), []byte("hunter2\n"), 0o600))

	check(yaml.UnmarshalStrict([]byte("username: admin\npassword:\n  file: password\n"), &cfg))
	cfg.Password.SetDirectory(dir)
	password, err := cfg.Password.Fetch(context.Background())
	check(err)
	fmt.Printf("%s (immutable=%t)\n", password, cfg.Password.Immutable())
	// Output:
	// hunter2 from inline (immutable=true)
	// username: admin
	// password: <secret>
	// hunter2 (immutable=false)
}
