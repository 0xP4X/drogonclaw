package agent

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// grounding guards against the agent fabricating environment facts (network
// interfaces, hardware presence, IP addresses) that contradict the raw tool
// output it actually recorded this session. It is deterministic — it never
// calls the LLM — so it fires on every final answer, including ones served by
// the fast model tier.
//
// The detector produces advisory corrections that are appended to the final
// answer and surfaced to the operator; it deliberately does not rewrite the
// agent's prose or block execution.

var (
	// ifaceTokenRe matches kernel network-interface identifiers in tool output
	// and in the agent's final answer (eth0, wlan0, enp3s0, docker0, ...).
	ifaceTokenRe = regexp.MustCompile(`(?i)\b(?:eth\d+|wlan\d+|wlp\w+|wifi\d+|enp\d+s\d+|ens\d+|eno\d+|en\w+\d+|wwan\d+|docker\d+|virbr\d+|tap\d+|tun\d+|veth\w+|bond\d+|br-\w+)\b`)

	// loTokenRe matches the loopback interface name as a standalone token so it
	// does not collide with words like "hello" or "protocol".
	loTokenRe = regexp.MustCompile(`(?:^|[^\w])lo(?:[^\w]|$)`)

	// ipv4Re matches dotted-quad IPv4 addresses in evidence and claims.
	ipv4Re = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

	// macRe matches colon-separated MAC/BSSID addresses in evidence and claims.
	macRe = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b`)

	// wirelessEvidenceRe flags tool output that proves wireless hardware exists
	// (ESSID, WPA2, 802.11, signal level, a wlan/wl interface).
	wirelessEvidenceRe = regexp.MustCompile(`(?i)(?:essid|wpa\s?2?|wpa2?|wi-?fi|wireless|802\.11|signal level|wlan\d+|ieee 802\.11)`)

	// wirelessNegationRe flags statements that deny the presence of WiFi. It
	// requires a hardware noun so phrases like "no wireless issue" do not trip
	// it, while "no physical WiFi hardware" / "no WiFi devices" still do.
	wirelessNegationRe = regexp.MustCompile(`(?i)\bno\s+(?:physical\s+)?(?:wifi|wi-fi|wlan|wireless)\s+(?:hardware|adapter\w*|device\w*|interface\w*|nics?|card\w*|radios?|present|available)\b|\b(?:iw|iwconfig)\s+dev\s+(?:returns?|shows?)\s+nothing\b|\bdoes\s?n'?t\s+have\s+(?:any\s+)?(?:wifi|wi-fi|wireless|wlan)\s+(?:hardware|adapter\w*|device\w*|card\w*|radios?)\b|\bno\s+(?:wifi|wi-fi|wireless|wlan)\s+(?:present|available)\b`)

	// envClaimRe gates the invented-IP check: we only cross-check IPs when the
	// final answer is making claims about the environment/hardware stack.
	envClaimRe = regexp.MustCompile(`(?i)container|sandbox(?:ed)?\s+environment|virtual\s+(?:ethernet|network)|physical\s+hardware|network\s+(?:stack|interface)|wireless\s+(?:nics?|adapters?|hardware)|no\s+physical`)

	// denyContextRe guards against flagging interface names used in a denial
	// ("no eth0 present", "without wlan0") rather than as a factual claim.
	denyContextRe = regexp.MustCompile(`(?i)(?:^|[^\w])(?:no|not|without|never)\s+`)
)

type groundingFacts struct {
	interfaces  map[string]bool
	ips         map[string]bool
	macs        map[string]bool
	hadWireless bool
	hasEvidence bool
}

func collectGroundingFacts(recs []toolOutputEvidence) groundingFacts {
	f := groundingFacts{
		interfaces: map[string]bool{},
		ips:        map[string]bool{},
		macs:       map[string]bool{},
	}
	for _, rec := range recs {
		for _, m := range ifaceTokenRe.FindAllString(rec.output, -1) {
			f.interfaces[strings.ToLower(m)] = true
		}
		for range loTokenRe.FindAllString(rec.output, -1) {
			f.interfaces["lo"] = true
		}
		for _, m := range ipv4Re.FindAllString(rec.output, -1) {
			f.ips[m] = true
		}
		for _, m := range macRe.FindAllString(rec.output, -1) {
			f.macs[strings.ToUpper(m)] = true
		}
		if wirelessEvidenceRe.MatchString(rec.output) {
			f.hadWireless = true
		}
	}
	f.hasEvidence = len(f.interfaces) > 0 || len(f.ips) > 0
	return f
}

// interfaceNames returns the sorted interface identifiers recorded in evidence,
// optionally restricted to wireless-looking names.
func (f groundingFacts) interfaceNames(wirelessOnly bool) []string {
	var names []string
	for name := range f.interfaces {
		if wirelessOnly && !(strings.Contains(name, "wlan") || strings.Contains(name, "wifi") || strings.Contains(name, "wl")) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func deniedInterface(final, match string) bool {
	idx := strings.Index(final, match)
	if idx < 0 {
		return false
	}
	start := idx - 24
	if start < 0 {
		start = 0
	}
	return denyContextRe.MatchString(final[start:idx])
}

// inventedInterfaceWarnings flags interface identifiers the answer presents as
// present that never appeared in any recorded tool result.
func inventedInterfaceWarnings(final string, facts groundingFacts) []string {
	for _, m := range ifaceTokenRe.FindAllString(final, -1) {
		name := strings.ToLower(m)
		if facts.interfaces[name] || deniedInterface(final, m) {
			continue
		}
		return []string{fmt.Sprintf(`said "%s" is present, but no recorded tool output in this session mentions an interface named "%s"`, m, m)}
	}
	return nil
}

// inventedIPWarnings flags IPs the answer cites as observed that no tool ever
// returned. Only meaningful when the answer is making environment claims.
func inventedIPWarnings(final string, facts groundingFacts) []string {
	if !envClaimRe.MatchString(final) || len(facts.ips) == 0 {
		return nil
	}
	var warns []string
	for _, ip := range ipv4Re.FindAllString(final, -1) {
		if facts.ips[ip] {
			continue
		}
		warns = append(warns, fmt.Sprintf("cited %s as an observed address, but no recorded tool output returned that IP — quote only values that appear verbatim in tool results", ip))
		if len(warns) >= 3 {
			break
		}
	}
	return warns
}

// wirelessDenialWarning flags denials of WiFi hardware that contradict recorded
// wireless evidence in the same session.
func wirelessDenialWarning(final string, facts groundingFacts) []string {
	if !facts.hadWireless || !wirelessNegationRe.MatchString(final) {
		return nil
	}
	names := facts.interfaceNames(true)
	ref := "wireless signal data (ESSID/WPA/802.11)"
	if len(names) > 0 {
		ref = "wireless interface " + strings.Join(names, ", ")
	}
	return []string{"claimed there is no WiFi/wireless hardware, but recorded tool output shows " + ref}
}

// inventedMACWarnings flags MAC/BSSID addresses the answer cites that no tool
// ever returned (e.g. an invented access-point address).
func inventedMACWarnings(final string, facts groundingFacts) []string {
	if len(facts.macs) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var warns []string
	for _, m := range macRe.FindAllString(final, -1) {
		up := strings.ToUpper(m)
		if facts.macs[up] || seen[up] {
			continue
		}
		seen[up] = true
		warns = append(warns, fmt.Sprintf("cited %s as an observed MAC/BSSID, but no recorded tool output returned that address — quote only values that appear verbatim in tool results", m))
		if len(warns) >= 3 {
			break
		}
	}
	return warns
}

// groundingCorrections inspects the agent's final answer against the raw tool
// evidence this run and returns human-readable corrections, or "" when the
// answer is consistent with (or unverifiable against) the evidence.
func groundingCorrections(final string, recs []toolOutputEvidence) string {
	facts := collectGroundingFacts(recs)
	if !facts.hasEvidence || strings.TrimSpace(final) == "" {
		return ""
	}

	var warns []string
	warns = append(warns, inventedInterfaceWarnings(final, facts)...)
	warns = append(warns, inventedIPWarnings(final, facts)...)
	warns = append(warns, inventedMACWarnings(final, facts)...)
	warns = append(warns, wirelessDenialWarning(final, facts)...)

	if len(warns) == 0 {
		return ""
	}
	if len(warns) > 5 {
		warns = warns[:5]
	}
	return "the summary makes claims that contradict the recorded tool evidence:\n- " + strings.Join(warns, "\n- ")
}
