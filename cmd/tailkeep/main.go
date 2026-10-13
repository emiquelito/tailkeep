// Command tailkeep is a placeholder entry point. Its subcommands are not
// implemented yet; it prints a usage line and exits.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "usage: tailkeep [serve|doctor|check]  (not implemented yet)")
	os.Exit(2)
}
