/*
Copyright 2017 The Kubernetes Authors.

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

package flag

import (
	"reflect"
	"testing"
)

func TestStrToUInt16(t *testing.T) {
	csFlag := NewCipherSuitesFlag()

	tests := []struct {
		flag           string
		expected       []uint16
		expected_error bool
	}{
		{
			// Happy case
			flag:           "TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_RC4_128_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			expected:       []uint16{5, 47, 49169, 49171},
			expected_error: false,
		},
		{
			// One flag only
			flag:           "TLS_RSA_WITH_RC4_128_SHA",
			expected:       []uint16{5},
			expected_error: false,
		},
		{
			// Empty flag
			flag:           "",
			expected:       nil,
			expected_error: false,
		},
		{
			// Duplicated flag
			flag:           "TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_RC4_128_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_RC4_128_SHA",
			expected:       []uint16{5, 47, 49169, 49171, 5},
			expected_error: false,
		},
		{
			// Invalid flag
			flag:           "foo",
			expected:       nil,
			expected_error: true,
		},
	}

	for i, test := range tests {
		uIntFlags, err := csFlag.StrToUInt16(test.flag)
		if reflect.DeepEqual(uIntFlags, test.expected) == false {
			t.Errorf("%d: expected %+v, got %+v", i, test.expected, uIntFlags)
		}
		if test.expected_error && err == nil {
			t.Errorf("%d: expecting error, got %+v", i, err)
		}
	}
}
