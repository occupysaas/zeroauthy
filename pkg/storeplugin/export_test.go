package storeplugin

import "github.com/zeroauthy/zeroauthy/pkg/store"

// PidForTest returns the plugin process id behind a store from Open.
func PidForTest(s store.Store) int { return s.(*opened).client.ReattachConfig().Pid }
