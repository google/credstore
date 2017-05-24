/*

Copyright 2017 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Scope struct {
	Name    string `yaml:"name"`
	Service string `yaml:"service"`
	Method  string `yaml:"method"`
}

type Authorization struct {
	Client string `yaml:"client"`
	Scope  string `yaml:"scope"`
	Via    string `yaml:"via"`
}

type Config struct {
	Scopes         []Scope         `yaml:"scopes"`
	Clients        []string        `yaml:"clients"`
	Authorizations []Authorization `yaml:"authorizations"`
}

func LoadConfig(fileName string) (*Config, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c Config) FindClient(name string) bool {
	for _, cli := range c.Clients {
		if cli == name {
			return true
		}
	}
	return false
}

func (c Config) FindAuthorization(client, target string) string {
	for _, a := range c.Authorizations {
		if a.Client == client && a.Via == target {
			return a.Scope
		}
	}
	return ""
}

func (c Config) FindScope(name string) *Scope {
	for _, s := range c.Scopes {
		if s.Name == name {
			return &s
		}
	}
	return nil
}
