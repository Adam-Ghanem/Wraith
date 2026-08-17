// Package buildinfo holds link-time release metadata only.
package buildinfo

import "fmt"

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func String() string {
	return fmt.Sprintf("wraith %s (commit %s, built %s)", Version, Commit, Date)
}
