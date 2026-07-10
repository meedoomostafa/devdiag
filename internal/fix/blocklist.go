package fix

import "strings"

// Blocklist provides secondary dangerous-command detection.
// The primary safety gate is the allowlisted registry; this is defense in depth.

// IsBlockedCommand returns true if a command + args combination is dangerous.
func IsBlockedCommand(bin string, args []string) bool {
	if isBlockedBin(bin) {
		return true
	}
	for _, a := range args {
		if isBlockedArg(a) {
			return true
		}
	}
	return isBlockedArg(strings.Join(args, " "))
}
