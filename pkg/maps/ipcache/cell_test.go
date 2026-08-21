// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"testing"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

func TestConfigMapMax(t *testing.T) {
	logger := hivetest.Logger(t)
	newHive := func() *hive.Hive {
		return hive.New(Cell)
	}
	type stringTest struct {
		name    string
		setFlag bool
		value   uint32
		wantErr bool
		want    int
	}

	testCases := []stringTest{
		{
			name:    "default",
			setFlag: false,
			wantErr: false,
			want:    DefaultMaxEntries,
		},
		{
			name:    "valid value",
			setFlag: true,
			value:   2097152,
			wantErr: false,
			want:    2097152,
		},
		{
			name:    "invalid value",
			setFlag: true,
			value:   1000,
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			MaxEntries = DefaultMaxEntries
			h := newHive()
			if tc.setFlag {
				h.Viper().Set("bpf-ipcache-map-max", tc.value)
			}
			err := h.Populate(logger)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, MaxEntries)
		})
	}

}
