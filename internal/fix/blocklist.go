package fix

// Blocklist provides secondary dangerous-command detection.
// The primary safety gate is the allowlisted registry; this is defense in depth.

// IsBlockedCommand returns true if a command + args combination is dangerous.
func IsBlockedCommand(bin string, args []string) bool {
	if isBlockedBin(bin) {
		return true
	}
	joined := joinArgs(args)
	return isBlockedArg(joined)
}

func joinArgs(args []string) string {
	out := ""
	for _, a := range args {
		out += a + " "
	}
	return out
}
