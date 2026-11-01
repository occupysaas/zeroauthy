// event-validator deliberately uses the production validator and frozen catalog.
package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/zeroauthy/zeroauthy/internal/eventrules"
)

func main() {
	if len(os.Args) == 5 && os.Args[1] == "seed-source" {
		if err := seedSource(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 4096), 4<<20)
	for s.Scan() {
		if err := eventrules.ValidateEvent(s.Bytes()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := s.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
