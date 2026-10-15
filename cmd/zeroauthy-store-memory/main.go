// Command zeroauthy-store-memory is the sample storage plugin: the in-memory
// driver served over the plugin protocol. It is for tests and as a template
// for plugin authors; its data is lost when it exits.
package main

import (
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storeplugin"
)

func main() { storeplugin.Serve(memory.New()) }
