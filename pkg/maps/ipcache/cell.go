// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

// Cell provides the configuration for sizing the ipcache BPF map
var Cell = cell.Module(
	"ipcache-map",
	"Configuration for sizing the ipcache BPF map",

	cell.Invoke(func(c Config) error {
		if c.IPCacheMapMax < DefaultMaxEntries {
			return fmt.Errorf("ipcache map: bpf-ipcache-map-max cannot be less than %d (%d)",
				DefaultMaxEntries, c.IPCacheMapMax)
		}
		MaxEntries = int(c.IPCacheMapMax)
		return nil
	}),
	cell.Config(defaultConfig),
)

type Config struct {
	IPCacheMapMax uint32 `mapstructure:"bpf-ipcache-map-max"`
}

func (c Config) Flags(fs *pflag.FlagSet) {
	// ~84 B/entry is the per-leaf footprint (node header + 20 B key data + 24 B value)
	// as reported on pre-6.13 kernels; post-6.13 leaves are 68 B, and densely
	// populated tries add ~1 intermediate node per entry (~2x total at scale).
	fs.Uint32("bpf-ipcache-map-max", defaultConfig.IPCacheMapMax,
		"Maximum number of entries in the ipcache BPF map (one entry per routable IP/prefix; ~84 bytes of kernel memory per entry)")
}

var defaultConfig = Config{
	IPCacheMapMax: DefaultMaxEntries,
}
