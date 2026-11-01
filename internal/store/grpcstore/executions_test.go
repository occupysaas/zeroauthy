package grpcstore

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

func TestExecutionConsole(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	storetest.ExecutionConsole(t, c)
}
