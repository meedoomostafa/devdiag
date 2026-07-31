package redact

import (
	"os"
	"regexp"
	"strings"
)

// Level controls redaction aggressiveness.
type Level string

const (
	LevelDefault Level = "default"
	LevelStrict  Level = "strict"
	LevelOff     Level = "off"
)

// defaultRuleNames lists the redaction rules applied at LevelDefault, in the
// order RedactString applies them (redactEnvValues covers env_values and
// secret_key_values). Consumers (e.g. capsule manifests) must derive rule
// listings from RuleNames so they cannot drift from the engine; when adding a
// rule to RedactString, add its name here in the same position.
var defaultRuleNames = []string{
	"pem_private_keys",
	"env_values",
	"secret_key_values",
	"cli_secret_flags",
	"secret_named_assignments",
	"interpolation_defaults",
	"quoted_key_material",
	"url_credentials",
	"bearer_tokens",
	"jwt_tokens",
	"home_directory",
	"evidence_secret_sources",
}

// RuleNames returns the names of the redaction rules active at the given
// level. It returns nil for LevelOff.
func RuleNames(level Level) []string {
	switch level {
	case LevelOff:
		return nil
	case LevelStrict:
		names := make([]string, 0, len(defaultRuleNames)+1)
		names = append(names, defaultRuleNames...)
		return append(names, "strict_long_tokens")
	default:
		return append([]string(nil), defaultRuleNames...)
	}
}

// Whitespace classes for the assignment rule family.
//
// Go's \s covers only [\t\n\f\r ], but strings.TrimSpace - and therefore the
// key classifier - also treats the vertical tab, NEL, and NBSP as space. That
// mismatch let "KEY\v=secret" defeat every assignment rule while the key was
// still read as secret-named. These are single constants so the "=" family
// cannot drift apart again, which is the failure the idempotence invariant
// was added to catch.
const (
	ws      = `[\s\v\x{85}\x{A0}]`
	wsDelim = `[\s\v\x{85}\x{A0}'"` + "`" + `\[]`
	// valueHardBounds lists every character that terminates an unquoted value
	// extent in the "=" family. It must stay in step with notWsDelim: Go's \s
	// covers tab, newline, form feed, carriage return, and space, and the class
	// adds the vertical tab, NEL, and NBSP. Kept as a string so tests can assert
	// against the same set instead of restating it and drifting - omitting the
	// form feed from a restated copy produced a false leak report.
	valueHardBounds = "\t\n\v\f\r \u0085\u00a0"

	// notWsDelim is the unquoted value extent. Whitespace is the only hard
	// bound: quotes, backticks, and brackets are consumed, because stopping at
	// them left the tail of any secret containing one visible
	// ("API_TOKEN=abc]def" masked only "abc"). Surrounding structure is
	// restored afterwards by splitValueTail rather than by narrowing the
	// extent, which is what the earlier leading-delimiter-run workaround tried
	// to do and could not generalise.
	notWsDelim = `[^\s\v\x{85}\x{A0}]`
	bareValue  = notWsDelim + `*`
)

var (
	// userInfoPattern matches URLs with embedded credentials.
	userInfoPattern = regexp.MustCompile(`(\w+://)([^@]+)@`)
	// jwtPattern matches JWTs (eyJ prefix) in default mode.
	jwtPattern = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b`)
	// strictTokenPattern matches long hex/base64 strings; used only in strict mode.
	strictTokenPattern = regexp.MustCompile(`\b([a-fA-F0-9]{40,}|[A-Za-z0-9+/]{40,}=*)\b`)
	// quotedKeyMaterialPattern matches long base64-like material echoed by tools
	// in quoted diagnostics, such as malformed multiline .env key material.
	quotedKeyMaterialPattern = regexp.MustCompile(`"([A-Za-z0-9+/]{32,}=*)"`)
	// envValuePattern matches KEY=VALUE assignments in logs, shell args, JSON-
	// quoted command arrays, and Go slice-formatted args while preserving
	// surrounding delimiters. Values that are themselves quoted (KEY="a b" or
	// KEY='a b') are consumed entirely, including embedded whitespace.
	envValuePattern = regexp.MustCompile(`(?m)(^|` + wsDelim + `)([A-Z_][A-Z0-9_]*` + ws + `*=` + ws + `*)("[^"]*"` + notWsDelim + `*|'[^']*'` + notWsDelim + `*|` + bareValue + `)`)
	// bearerTokenPattern matches Bearer credentials in Authorization headers
	// or header-like log fragments, case-insensitively.
	bearerTokenPattern = regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+`)
	// secretKeyValuePattern matches KEY=VALUE assignments whose key name
	// indicates secret material regardless of case (db_password=, api_key=,
	// auth_token=, ...). The uppercase-only envValuePattern misses these, and
	// lowercase diagnostics (exit_code=1) must stay untouched, so this pattern
	// is scoped to secret-bearing key names only.
	secretKeyValuePattern = regexp.MustCompile(`(?im)(^|` + wsDelim + `)([A-Z0-9_]*(?:password|passwd|secret|token|api_?key|credential|auth_)[A-Z0-9_]*` + ws + `*=` + ws + `*)("[^"]*"` + notWsDelim + `*|'[^']*'` + notWsDelim + `*|` + bareValue + `)`)
	// cliSecretPattern matches common CLI flag patterns that carry secrets.
	// Covers: --password=secret, --password secret, --token=abc, --api-key=xyz, etc.
	// Quoted values ("multi word" / 'multi word') are consumed entirely.
	// Case-insensitive via (?i:...).
	cliSecretPattern = regexp.MustCompile(`(?i)(--(?:password|token|api[-_]key|client[-_]secret|secret|auth[-_]token)(?:=|\s+))("[^"]*"|'[^']*'|[^\s]+)`)
	// secretKeyNamePattern classifies variable/key names as secret-bearing.
	// Substring matches cover compact spellings (NPMTOKEN, GITHUBTOKEN,
	// PRIVATEKEY) as well as delimited ones (API_TOKEN, PRIVATE_KEY, CI_JOB_JWT).
	// KEY and AUTH match only as standalone segments so SSH_KEY/DEPLOY_KEY/
	// SIGNING_KEY are caught while AUTHOR, OAUTH_ENABLED, and KEYBOARD-style
	// names stay classified as non-secret diagnostics; masking a benign
	// CACHE_KEY is an accepted trade-off against leaking a deploy key.
	secretKeyNamePattern = regexp.MustCompile(`(?i)(password|passwd|secret|credential|token|api_?key|private_?key|access_?key|jwt|(?:^|_)key(?:_|$)|(?:^|_)auth(?:_|$))`)
	// blockScalarHeaderPattern matches a mapping key whose value is a YAML
	// block scalar indicator ("|" or ">", with chomping and indentation
	// indicators in either order) and nothing else but an optional comment.
	// Requiring end-of-line after the indicator is what keeps shell pipelines
	// ("cmd: | grep x") and markdown tables from being treated as blocks.
	// Group 1 is the whole prefix through the colon, so the masked line keeps
	// the original indentation, sequence dash, quoting, and colon spacing.
	// Group 2 is the text before the key, whose display width gives the key's
	// column. Group 3 is the key name. Keys may be plain, double-quoted, or
	// single-quoted; omitting the single-quoted form leaked whole blocks.
	blockScalarHeaderPattern = regexp.MustCompile(`^(([ \t]*(?:-[ \t]+)*['"]?)([A-Za-z_][A-Za-z0-9_.-]*)['"]?[ \t]*:[ \t]*)[|>][0-9+-]*[ \t]*(?:#.*)?$`)
	// pemPrivateKeyMarker matches PEM private key openings of any algorithm,
	// including the PGP "... PRIVATE KEY BLOCK" form. It deliberately does not
	// match BEGIN CERTIFICATE: certificates are public, and masking them would
	// destroy diagnostic value with no confidentiality gain.
	pemPrivateKeyMarker = regexp.MustCompile(`(?i)-{4,5} ?BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-{4,5}`)
	// pemPrivateKeyBlockPattern matches a whole PEM private key block with no
	// surrounding structure, as produced by "cat id_rsa" or a base64-decoded
	// Kubernetes secret. The END marker is optional so a truncated block still
	// fails closed: without it the match runs to end of input rather than
	// emitting the remaining key material.
	pemPrivateKeyBlockPattern = regexp.MustCompile(`(?is)-{4,5} ?BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-{4,5}.*?(?:-{4,5} ?END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-{4,5}|\z)`)
	// mappingEntryPattern recognises a line that opens a mapping entry, used
	// to tell a sibling field apart from malformed block content sitting at
	// the same column inside a compact sequence entry.
	mappingEntryPattern = regexp.MustCompile(`^[ \t]*(?:-[ \t]+)*['"]?[A-Za-z_][A-Za-z0-9_.-]*['"]?[ \t]*:`)
	// keySeparators folds non-underscore key separators onto "_" so the
	// segment-anchored alternatives in secretKeyNamePattern see them.
	keySeparators = strings.NewReplacer(".", "_", "-", "_")
)

// homeDir caches the user's home directory.
var homeDir = os.Getenv("HOME")

// redactURL replaces credentials in URLs.
func redactURL(input string) string {
	return userInfoPattern.ReplaceAllStringFunc(input, func(match string) string {
		parts := userInfoPattern.FindStringSubmatch(match)
		if len(parts) >= 3 {
			userInfo := parts[2]
			if idx := strings.Index(userInfo, ":"); idx != -1 {
				user := userInfo[:idx]
				return parts[1] + user + ":<redacted>@"
			}
		}
		return parts[1] + "<redacted>@"
	})
}

// redactJWT replaces JWTs in default mode.
func redactJWT(input string) string {
	return jwtPattern.ReplaceAllString(input, "<jwt>")
}

// redactBearerTokens replaces Bearer credentials in Authorization headers.
func redactBearerTokens(input string) string {
	return bearerTokenPattern.ReplaceAllString(input, "${1}<redacted>")
}

// redactStrictTokens replaces long hex/base64 strings in strict mode.
func redactStrictTokens(input string) string {
	return strictTokenPattern.ReplaceAllString(input, "<token>")
}

// redactQuotedKeyMaterial replaces long quoted base64-like tokens that often
// come from PEM/JWK/key material echoed in tool error messages.
func redactQuotedKeyMaterial(input string) string {
	return quotedKeyMaterialPattern.ReplaceAllString(input, `"<token>"`)
}

// redactHome replaces home directory paths.
func redactHome(input string) string {
	if homeDir == "" {
		return input
	}
	return strings.ReplaceAll(input, homeDir, "~")
}

// valueClosers are the closing delimiters that may end a value but usually
// belong to the structure around it. Note that ">" is deliberately absent: the
// redaction marker itself ends with ">", so giving it back would rewrite
// "<redacted>" into "<redacted>>" and then "<redacted>>>", growing without
// bound and breaking the engine's idempotence contract.
const valueClosers = "'\"" + "`" + ")]}"

// splitValueTail returns the part of a captured value that must be re-emitted
// after the redaction marker so surrounding structure survives.
//
// Values are now consumed through quotes and brackets, so the structure they
// carry has to be handed back explicitly: a maximal trailing run of closing
// delimiters. A quoted value's core is never split, because the quoted
// alternatives capture their own quotes and giving the closing quote back would
// turn `{"token": <redacted>, ...}` into `{"token": <redacted>"`.
//
// Only a run of closing delimiters is handed back, and deliberately nothing
// else. Handing back a following query parameter was tried and abandoned: the
// returned text is itself rewritten by later rules - strict mode collapses a
// long token and its "=" padding - so the next pass no longer recognised the
// structure and masked the whole tail instead, breaking idempotence three
// separate ways under fuzzing. Restoring that structure belongs in a final pass
// after all rewriting rules have run, not inside one of them. Tracked
// separately; the cost until then is that a sibling query parameter is masked
// along with the secret, which over-redacts rather than leaks.
//
// When nothing would remain to mask - a value made only of closing delimiters -
// the whole value is masked instead of being handed back as structure, which is
// what the extent already did before this rule existed.
func splitValueTail(value string) (tail string, contentful bool) {
	core, rest := "", value
	if len(value) > 1 && (value[0] == '"' || value[0] == '\'') {
		if j := closingQuote(value); j != -1 {
			core, rest = value[:j+1], value[j+1:]
		}
	}

	end := len(rest)
	for end > 0 && strings.IndexByte(valueClosers, rest[end-1]) != -1 {
		end--
	}
	// The value is nothing but closing delimiters, so there is no content to
	// mask and the caller has to decide whether they are the value or the
	// structure around it.
	if core == "" && end == 0 {
		return rest, false
	}
	return rest[end:], true
}

// closingQuote returns the index of the quote that closes the quoted value
// starting at index 0, or -1 when it is unterminated.
//
// Inside a double-quoted value a backslash escapes the next byte, so a
// backslash-quote pair does not end the value. Treating it as the terminator
// split the value early and left a dangling quote in the output, which also
// made an escaped quote inside a JSON string produce invalid JSON. Single quotes
// carry no escape in shell, so they are matched literally.
func closingQuote(value string) int {
	quote := value[0]
	for i := 1; i < len(value); i++ {
		if quote == '"' && value[i] == '\\' {
			i++
			continue
		}
		if value[i] == quote {
			return i
		}
	}
	return -1
}

// openingDelimiters are the characters that open a bracketed or quoted region.
// When one of them immediately precedes an assignment, a closing delimiter at
// the end of the value belongs to that region rather than to the value.
const openingDelimiters = "([{'\"" + "`"

// maskedAssignment renders a redacted assignment, deciding what to do when the
// captured value holds no maskable content.
//
// A value made only of closing delimiters is ambiguous on its own:
// "API_TOKEN=]]]]" is a value, while the "]" in "args=[API_KEY=]" closes the
// bracket opened in the prefix and marks an empty value. Consuming the latter
// produced malformed output where the engine had previously left the input
// alone, so the prefix decides. Distinguishing the two exactly needs the
// position of the opening delimiter, which is why the general fix lives in the
// final-pass rework rather than here.
func maskedAssignment(match, prefix, head, value string) string {
	tail, contentful := splitValueTail(value)
	if !contentful {
		if prefix != "" && strings.IndexByte(openingDelimiters, prefix[0]) != -1 {
			return match
		}
		return prefix + head + "<redacted>"
	}
	return prefix + head + "<redacted>" + tail
}

// redactEnvValues replaces values in KEY=VALUE patterns.
func redactEnvValues(input string) string {
	result := maskEnvAssignment(input, envValuePattern)
	return maskEnvAssignment(result, secretKeyValuePattern)
}

// maskEnvAssignment masks the value of a three-group assignment pattern, whose
// third capture is the value. Unlike redactWithAssignmentPattern there is no
// key-name gate: these patterns encode the key selection in the regex itself.
func maskEnvAssignment(input string, pattern *regexp.Regexp) string {
	return pattern.ReplaceAllStringFunc(input, func(match string) string {
		parts := pattern.FindStringSubmatch(match)
		if len(parts) < 4 || parts[3] == "" {
			return match
		}
		return maskedAssignment(match, parts[1], parts[2], parts[3])
	})
}

// redactCLISecrets replaces values after common secret-bearing CLI flags.
func redactCLISecrets(input string) string {
	return cliSecretPattern.ReplaceAllString(input, "${1}<redacted>")
}

// interpolationOpenPattern locates a ${VAR<op>... opening whose variable name
// indicates secret material. The value is scanned manually so nested ${...}
// stay inside the masked region.
//
// Every POSIX parameter-expansion operator that carries a literal operand is
// matched, not just ":-" and "-". The others were owned by no rule at all: this
// one skipped them, and the assignment rules cannot reach inside "${...}"
// because "{" is deliberately not a key boundary, so ${API_TOKEN:=secret} and
// ${API_TOKEN:+secret} leaked at both redaction levels.
//
// Substring expansion is intentionally excluded. "${VAR:3:4}" has a digit after
// the colon, which [-=+?] does not match, so slicing syntax is left alone.
//
// An optional array subscript is skipped between the name and the operator.
// Without it the name class stopped at "[", the whole opening failed to match,
// and "${API_TOKEN[0]:-secret}" emitted its operand verbatim. The subscript is
// non-capturing so group 1 remains the base name used for classification, which
// keeps "${NODE_VERSION[0]:-20}" benign.
var interpolationOpenPattern = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(?:\[[^\]]*\])?(:?[-=+?])`)

// redactInterpolationDefaults masks literal fallback values in secret-named
// variable interpolations such as ${API_TOKEN:-realvalue}. The default is
// consumed through the matching outer brace (tracking nested ${...}) so that
// ${A_TOKEN:-${B}-suffix} does not leak the suffix.
func redactInterpolationDefaults(input string) string {
	locs := interpolationOpenPattern.FindAllStringSubmatchIndex(input, -1)
	if locs == nil {
		return input
	}
	var b strings.Builder
	last := 0
	for _, m := range locs {
		start, end := m[0], m[1]
		if start < last {
			continue
		}
		varName := input[m[2]:m[3]]
		if !IsSecretKeyName(varName) {
			continue
		}
		closing := findBalancedClose(input, end)
		if closing == -1 || closing == end {
			continue
		}
		b.WriteString(input[last:end])
		b.WriteString("<redacted>")
		last = closing
	}
	if last == 0 {
		return input
	}
	b.WriteString(input[last:])
	return b.String()
}

// findBalancedClose returns the index of the '}' that closes the
// interpolation whose default value starts at start, accounting for nested
// ${...} groups. Returns -1 when unbalanced.
func findBalancedClose(input string, start int) int {
	depth := 0
	for i := start; i < len(input); i++ {
		switch {
		case input[i] == '\\':
			// A backslash escapes the next byte, so "\}" is a literal brace
			// inside the operand rather than its terminator. Treating it as the
			// terminator ended the operand early and left the remainder of the
			// value visible.
			i++
		case input[i] == '$' && i+1 < len(input) && input[i+1] == '{':
			depth++
		case input[i] == '}':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

// camelBoundary matches a lowercase/digit followed by an uppercase letter,
// i.e. a camelCase word boundary.
var camelBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// acronymBoundary splits an acronym from a following word: "SSHKey" ->
// "SSH_Key", "TLSKey" -> "TLS_Key". Without it, all-caps prefixes hide the
// standalone "key"/"auth" segment from the classifier.
var acronymBoundary = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)

// normalizeKeyName inserts underscores at camelCase boundaries so that
// segment-anchored rules (standalone "key"/"auth") work on camelCase names:
// "sshKey" -> "ssh_Key", "deployKey" -> "deploy_Key". Without this, camelCase
// secret names common in JS/JSON configs slip past segment anchoring while
// their SCREAMING_SNAKE equivalents are caught.
func normalizeKeyName(key string) string {
	// "." and "-" are segment separators in Kubernetes secret keys (tls.key),
	// Helm values, and Java-style properties exactly as "_" is in env vars.
	// Without this the segment-anchored key/auth alternatives missed tls.key
	// and ssh.private-key, so those values survived intact.
	key = keySeparators.Replace(key)
	key = acronymBoundary.ReplaceAllString(key, "${1}_${2}")
	return camelBoundary.ReplaceAllString(key, "${1}_${2}")
}

// IsSecretKeyName reports whether a variable/key name denotes secret
// material. This is the single classifier used by BOTH the evidence-source
// path and the KEY=VALUE content path; keeping one list is deliberate,
// because the two drifted once (standalone key/auth were taught to the
// source path only, so a mixed-case Key=... survived in log text).
func IsSecretKeyName(key string) bool {
	// Both forms are checked: camel normalization must only ADD matches.
	// Splitting can break a word apart ("keY" -> "ke_Y"), so the raw name is
	// tested too.
	return secretKeyNamePattern.MatchString(key) ||
		secretKeyNamePattern.MatchString(normalizeKeyName(key))
}

// assignmentPattern matches generic KEY=VALUE tokens. The key is classified
// by IsSecretKeyName rather than being baked into the regex, so content
// redaction can never fall behind the source classifier again.
var assignmentPattern = regexp.MustCompile(`(?m)(^|` + wsDelim + `)([A-Za-z_][A-Za-z0-9_.-]*)(["']?` + ws + `*=` + ws + `*)("[^"]*"` + notWsDelim + `*|'[^']*'` + notWsDelim + `*|` + bareValue + `)`)

// colonValueTail bounds a colon-assigned value at the flow delimiters that end
// it in YAML and JSON. Quoted values carry the same tail so that a stray
// character after the closing quote ("token:\"\"0") is consumed in one pass:
// leaving it behind made the next pass treat "<redacted>0" as a bare value and
// mask it again, breaking the engine's idempotence contract.
//
// Consequence, verified and accepted: a trailing comment after a quoted value
// is consumed too ("token: \"abc\" # note" becomes "token: <redacted>"). That
// is the fail-toward-redaction choice, since a comment beside a secret often
// restates it. Flow delimiters still bound the value, so ",", "}", "]", and a
// newline all keep surrounding structure and sibling entries intact.
const colonValueTail = `[^\n,]*`

var colonAssignmentPattern = regexp.MustCompile(`(?m)(^|` + wsDelim + `)([A-Za-z_][A-Za-z0-9_.-]*)(["']?` + ws + `*:` + ws + `*)("[^"]*"` + colonValueTail + `|'[^']*'` + colonValueTail + `|` + `\]*` + colonValueTail + `)`)

// redactSecretNamedAssignments masks the value of any KEY=VALUE or
// KEY: VALUE (YAML/JSON/properties) whose key name is classified as
// secret-bearing.
//
// Accepted trade-off, in line with the project's fail-toward-redaction
// policy: benign metadata whose key happens to be secret-named (cache_key,
// auth_method, key-value) is masked rather than risk leaking a deploy key.
func redactSecretNamedAssignments(input string) string {
	// Block scalars are handled first: the colon rule would consume the "|"
	// indicator and destroy the signal needed to find the block body.
	out := redactYAMLBlockScalars(input)
	out = redactWithAssignmentPattern(out, assignmentPattern)
	return redactWithAssignmentPattern(out, colonAssignmentPattern)
}

// redactPEMPrivateKeys masks PEM private key blocks anywhere in the input,
// independent of any surrounding key/value structure.
//
// This is the unstructured counterpart to redactYAMLBlockScalars: command
// output captured by repro and log files packaged into capsules carry key
// material with no YAML header to key off. Certificates are deliberately
// untouched - they are public, and masking them would cost diagnostic value
// for no confidentiality gain.
func redactPEMPrivateKeys(input string) string {
	// Guard on the armour dashes rather than "-----BEGIN": the pattern is
	// case-insensitive, so a case-sensitive guard would let a lowercase
	// "-----begin rsa private key-----" skip the rule entirely. Four dashes,
	// because RFC 4716 / ssh.com armour uses
	// "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----".
	if !strings.Contains(input, "----") {
		return input
	}
	return pemPrivateKeyBlockPattern.ReplaceAllString(input, "<redacted>")
}

// indentWidth measures leading whitespace. Tabs count as 8 so that a
// tab-indented body always reads as deeper than a space-indented header:
// tabs are invalid YAML indentation, but this scanner ingests arbitrary
// scanned text and must fail toward redaction rather than terminate the
// block early and emit the body verbatim.
func indentWidth(line string) int {
	width := 0
	for _, r := range line {
		switch r {
		case ' ':
			width++
		case '\t':
			width += 8
		default:
			return width
		}
	}
	return width
}

// leadingWhitespace returns the indentation characters of a line.
func leadingWhitespace(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}

// displayWidth measures the printed width of a prefix, counting a tab as 8.
// Unlike indentWidth it does not stop at the first non-whitespace character,
// because a sequence dash and an opening quote both shift the key's column.
func displayWidth(prefix string) int {
	width := 0
	for _, r := range prefix {
		if r == '\t' {
			width += 8
			continue
		}
		width++
	}
	return width
}

// trimCR splits a trailing carriage return off a line so patterns anchored
// with $ still match on CRLF input, and the ending can be restored verbatim.
func trimCR(line string) (body, ending string) {
	if strings.HasSuffix(line, "\r") {
		return line[:len(line)-1], "\r"
	}
	return line, ""
}

// redactYAMLBlockScalars masks multi-line YAML block scalar values whose key
// names secret material, or whose body is unmistakably a PEM private key
// regardless of key name.
//
// This is the shape private keys actually take in a repository: Kubernetes
// Secret stringData, GitHub Actions env, docker-compose, Ansible vars, and
// Helm values all embed key material as an indented block. The KEY: VALUE
// rules are line-oriented, so before this rule the indicator was masked
// while every continuation line was emitted verbatim.
//
// The whole scalar is replaced by a single "<redacted>" on the header line.
// Retaining the indicator, or emitting a richer placeholder that named the
// line count or format, would both break the engine's idempotence contract:
// the colon rule rewrites any surviving value on the next pass, so only the
// exact "<redacted>" marker is a fixed point.
func redactYAMLBlockScalars(input string) string {
	// Fast path: no indicator character means no block scalar.
	if !strings.ContainsAny(input, "|>") {
		return input
	}

	lines := strings.Split(input, "\n")
	out := make([]string, 0, len(lines))

	for i := 0; i < len(lines); i++ {
		body, ending := trimCR(lines[i])
		header := blockScalarHeaderPattern.FindStringSubmatch(body)
		if header == nil {
			out = append(out, lines[i])
			continue
		}

		// The threshold is the key's column, which is where YAML puts the
		// parent mapping: block content must be more indented than that, and
		// siblings sit at exactly that column. Using the containing line's
		// indentation instead consumed siblings of a compact sequence entry
		// ("- private_key: |" followed by "  image: nginx"), destroying
		// diagnostics. Content at or left of the key column is not block
		// content to a YAML parser either; unstructured key material is
		// covered independently by redactPEMPrivateKeys.
		indent := displayWidth(header[2])

		// Walk forward while lines are blank or more deeply indented. Only
		// non-blank deeper lines extend the block, so blank lines that merely
		// trail the block stay outside it and survive as document structure.
		lineIndent := indentWidth(body)
		headerHasTab := strings.ContainsRune(header[2], '\t')
		end := i
		for j := i + 1; j < len(lines); j++ {
			candidate, _ := trimCR(lines[j])
			if strings.TrimSpace(candidate) == "" {
				continue
			}
			width := indentWidth(candidate)
			if width > indent {
				end = j
				continue
			}
			// A line at exactly the key column is ambiguous in two cases,
			// and in both it is treated as block content so malformed input
			// fails toward redaction:
			//
			//   - a compact sequence entry ("- private_key: |") shifts the key
			//     column right of the line's own indentation, so content and
			//     siblings can share a column;
			//   - mixed tab and space indentation cannot be compared by width
			//     without collisions, since a tab-indented header and a body
			//     indented with eight spaces both measure 8.
			//
			// Both are gated on the line not looking like a mapping entry, so
			// a genuine sibling field is never consumed. Outside these cases
			// the strict test applies, so an unindented log line following an
			// indicator is never swallowed.
			if width == indent && !mappingEntryPattern.MatchString(candidate) {
				sequenceShift := indent > lineIndent
				mixedIndent := width > 0 && (headerHasTab || strings.ContainsRune(leadingWhitespace(candidate), '\t'))
				if sequenceShift || mixedIndent {
					end = j
					continue
				}
			}
			break
		}

		if end == i {
			// Indicator with no body. The colon rule masks the indicator
			// itself, which is already a fixed point.
			out = append(out, lines[i])
			continue
		}

		// The PEM check is redundant defense in depth at engine level, where
		// redactPEMPrivateKeys already collapsed any key material before this
		// rule runs. It is kept, and asserted directly by
		// TestBlockScalarPEMGateDirectly, so that reordering the pipeline
		// cannot silently reopen the benign-key ("data: |") bypass.
		blockBody := strings.Join(lines[i+1:end+1], "\n")
		if !IsSecretKeyName(header[3]) && !pemPrivateKeyMarker.MatchString(blockBody) {
			out = append(out, lines[i])
			continue
		}

		out = append(out, header[1]+"<redacted>"+ending)
		i = end
	}

	return strings.Join(out, "\n")
}

func redactWithAssignmentPattern(input string, pattern *regexp.Regexp) string {
	return pattern.ReplaceAllStringFunc(input, func(match string) string {
		parts := pattern.FindStringSubmatch(match)
		if len(parts) < 5 || parts[4] == "" {
			return match
		}
		if !IsSecretKeyName(parts[2]) {
			return match
		}
		return maskedAssignment(match, parts[1], parts[2]+parts[3], parts[4])
	})
}

// isSecretSource reports whether an evidence Source identifier names secret
// material. Whole-value masking is scoped to CI environment-variable evidence
// (ci_env__ / ci_setup__ namespaces), whose values are bare secrets when the
// key name says so; other namespaces (ci_runs_on__auth, file paths) carry
// diagnostic values that content rules handle. The trailing key segment is
// decoded from the %5F%5F escaping applied by sanitizeSource before matching.
func isSecretSource(source string) bool {
	if !strings.HasPrefix(source, "ci_env__") && !strings.HasPrefix(source, "ci_setup__") {
		return false
	}
	rest := source[strings.Index(source, "__")+2:]
	if idx := strings.LastIndex(rest, "__"); idx != -1 {
		rest = rest[idx+2:]
	}
	key := strings.ReplaceAll(rest, "%5F%5F", "__")
	return IsSecretKeyName(key)
}
