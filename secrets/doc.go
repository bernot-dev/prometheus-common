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

// Package secrets implements the configuration surface for secret providers
// as described in PROM-47
// (https://github.com/prometheus/proposals/blob/main/proposals/0047-secret_providers.md).
//
// EXPERIMENTAL: this package is new and its API may change in a minor release
// until it is declared stable.
//
// A Field is embedded in configuration structs wherever a secret can be
// configured. In YAML (and JSON) it accepts either a plain string or a mapping
// with exactly one key naming a secret provider:
//
//	password: hunter2
//
//	password:
//	  file: /run/secrets/password
//
// The value under the provider key is the provider's own configuration: a
// scalar for simple providers such as file, or a mapping for providers that
// need several settings.
//
// Fetch returns the secret. Plain strings and the built-in file provider are
// resolved by the Field itself, so they work in any program. Other providers
// are served by a component that knows them and supplies their values to the
// Fields of a configuration; this package does not include one yet, and such
// Fields return an error from Fetch until one does.
//
// A Field is a small handle: copies made after it was unmarshaled share the
// same underlying state, which is what lets such a component supply a value
// to every copy at once. Compare Fields with Equal, not ==.
//
// When marshaled, a plain string is redacted as "<secret>" while provider
// configurations, which contain no secret material, are emitted unchanged.
//
// Provider configurations are decoded generically before the provider is
// known, so unquoted scalars that YAML 1.1 interprets as booleans or numbers
// (for example n, yes, on or 0123) must be quoted inside them. Plain string
// secrets are not affected.
package secrets
