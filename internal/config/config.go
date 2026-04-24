// Package config provides YAML configuration loading and management for ReconForge.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

// Version and BuildTime are set at compile time via ldflags.
var (
	Version   = "dev"
	BuildTime = "unknown"
)

// Config is the root configuration struct for ReconForge.
type Config struct {
	General     GeneralConfig     `mapstructure:"general"`
	VM          VMConfig          `mapstructure:"vm"`
	Target      TargetConfig      `mapstructure:"target"`
	OSINT       OSINTConfig       `mapstructure:"osint"`
	Subdomain   SubdomainConfig   `mapstructure:"subdomain"`
	Web         WebConfig         `mapstructure:"web"`
	Vuln        VulnConfig        `mapstructure:"vuln"`
	DNS         DNSConfig         `mapstructure:"dns"`
	RateLimit   RateLimitConfig   `mapstructure:"ratelimit"`
	Cache       CacheConfig       `mapstructure:"cache"`
	Monitoring  MonitoringConfig  `mapstructure:"monitoring"`
	Incremental IncrementalConfig `mapstructure:"incremental"`
	Export      ExportConfig      `mapstructure:"export"`
	AI          AIConfig          `mapstructure:"ai"`
}

// GeneralConfig holds general settings.
type GeneralConfig struct {
	ToolsDir   string `mapstructure:"tools_dir"`
	OutputDir  string `mapstructure:"output_dir"`
	Parallel   bool   `mapstructure:"parallel"`
	MaxWorkers int    `mapstructure:"max_workers"`
	Deep       bool   `mapstructure:"deep"`
	Verbose    bool   `mapstructure:"verbose"`
}

// VMConfig holds VM management settings.
type VMConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Provider  string `mapstructure:"provider"`
	Name      string `mapstructure:"name"`
	Memory    int    `mapstructure:"memory"`
	CPUs      int    `mapstructure:"cpus"`
	DiskGB    int    `mapstructure:"disk_gb"`
	Image     string `mapstructure:"image"`
	SSHPort   int    `mapstructure:"ssh_port"`
	SharedDir string `mapstructure:"shared_dir"`
}

// TargetConfig holds target scoping settings.
type TargetConfig struct {
	ScopeFile        string `mapstructure:"scope_file"`
	OutOfScopeFile   string `mapstructure:"out_of_scope_file"`
	ExcludeSensitive bool   `mapstructure:"exclude_sensitive"`
}

// OSINTConfig holds OSINT module settings.
type OSINTConfig struct {
	Enabled          bool   `mapstructure:"enabled"`
	GoogleDorks      bool   `mapstructure:"google_dorks"`
	GithubDorks      bool   `mapstructure:"github_dorks"`
	GithubRepos      bool   `mapstructure:"github_repos"`
	GithubLeaks      bool   `mapstructure:"github_leaks"`
	EmailHarvest     bool   `mapstructure:"email_harvest"`
	CloudEnum        bool   `mapstructure:"cloud_enum"`
	Metadata         bool   `mapstructure:"metadata"`
	MailHygiene      bool   `mapstructure:"mail_hygiene"`
	SPFDMARC         bool   `mapstructure:"spf_dmarc"`
	APILeaks         bool   `mapstructure:"api_leaks"`
	DomainInfo       bool   `mapstructure:"domain_info"`
	Spoof            bool   `mapstructure:"spoof"`
	IPInfo           bool   `mapstructure:"ip_info"`
	ThirdParties     bool   `mapstructure:"third_parties"`
	GithubActions    bool   `mapstructure:"github_actions_audit"`
	GithubTokensFile string `mapstructure:"github_tokens_file"`
	WhoisXMLAPIKey   string `mapstructure:"whoisxml_api_key"`
}

// SubdomainConfig holds subdomain enumeration settings.
type SubdomainConfig struct {
	Enabled          bool `mapstructure:"enabled"`
	Passive          bool `mapstructure:"passive"`
	CRT              bool `mapstructure:"crt"`
	Brute            bool `mapstructure:"brute"`
	Permutations     bool `mapstructure:"permutations"`
	AIPermutations   bool `mapstructure:"ai_permutations"`
	RecursivePassive bool `mapstructure:"recursive_passive"`
	RecursiveBrute   bool `mapstructure:"recursive_brute"`
	Takeover         bool `mapstructure:"takeover"`
	ZoneTransfer     bool `mapstructure:"zone_transfer"`
	S3Buckets        bool `mapstructure:"s3_buckets"`
	WildcardFilter   bool `mapstructure:"wildcard_filter"`
	ASNEnum          bool `mapstructure:"asn_enum"`
	NoError          bool `mapstructure:"noerror"`
	SRVEnum          bool `mapstructure:"srv_enum"`
	Scraping         bool `mapstructure:"scraping"`
	Analytics        bool `mapstructure:"analytics"`
	NSDelegation     bool `mapstructure:"ns_delegation"`
	RegexPermut      bool `mapstructure:"regex_permut"`
	PtrCidrs         bool `mapstructure:"ptr_cidrs"`
	GeoInfo          bool `mapstructure:"geo_info"`
	SubIAPermut      bool `mapstructure:"sub_ia_permut"`
}

// WebConfig holds web analysis settings.
type WebConfig struct {
	Enabled            bool      `mapstructure:"enabled"`
	Probe              bool      `mapstructure:"probe"`
	Screenshots        bool      `mapstructure:"screenshots"`
	Ports              PortsConf `mapstructure:"ports"`
	Nuclei             bool      `mapstructure:"nuclei"`
	CDNProvider        bool      `mapstructure:"cdnprovider"`
	Fuzzing            bool      `mapstructure:"fuzzing"`
	JSAnalysis         bool      `mapstructure:"js_analysis"`
	Crawl              bool      `mapstructure:"crawl"`
	CMSScan            bool      `mapstructure:"cms_scan"`
	WAFDetect          bool      `mapstructure:"waf_detect"`
	GraphQL            bool      `mapstructure:"graphql"`
	URLExt             bool      `mapstructure:"urlext"`
	ServiceFingerprint bool      `mapstructure:"service_fingerprint"`
	ParamDiscovery     bool      `mapstructure:"param_discovery"`
	PortScan           bool      `mapstructure:"port_scan"`
	VirtualHosts       bool      `mapstructure:"virtual_hosts"`
	URLChecks          bool      `mapstructure:"url_checks"`
	URLGF              bool      `mapstructure:"url_gf"`
	IISShortname       bool      `mapstructure:"iis_shortname"`
	TLSIPPivots        bool      `mapstructure:"tls_ip_pivots"`
	FavireconTech      bool      `mapstructure:"favirecon_tech"`
	BrokenLinks        bool      `mapstructure:"broken_links"`
	WordlistGen        bool      `mapstructure:"wordlist_gen"`
	SubJSExtract       bool      `mapstructure:"sub_js_extract"`
	WellKnownPivots    bool      `mapstructure:"wellknown_pivots"`
	GrpcReflection     bool      `mapstructure:"grpc_reflection"`
	WebsocketChecks    bool      `mapstructure:"websocket_checks"`
	RobotsWordlist     bool      `mapstructure:"wordlist_gen_roboxtractor"`
	PasswordDict       bool      `mapstructure:"password_dict"`
	LLMProbe           bool      `mapstructure:"llm_probe"`
}

// PortsConf holds port configuration.
type PortsConf struct {
	Standard string `mapstructure:"standard"`
	Uncommon string `mapstructure:"uncommon"`
}

// VulnConfig holds vulnerability scanning settings.
type VulnConfig struct {
	Enabled          bool `mapstructure:"enabled"`
	XSS              bool `mapstructure:"xss"`
	SSRF             bool `mapstructure:"ssrf"`
	SQLi             bool `mapstructure:"sqli"`
	SSTI             bool `mapstructure:"ssti"`
	LFI              bool `mapstructure:"lfi"`
	SSL              bool `mapstructure:"ssl"`
	Smuggling        bool `mapstructure:"smuggling"`
	Spray            bool `mapstructure:"spray"`
	CommandInjection bool `mapstructure:"command_injection"`
	NucleiDAST       bool `mapstructure:"nuclei_dast"`
	CRLF             bool `mapstructure:"crlf"`
	Bypass4xx        bool `mapstructure:"bypass4xx"`
	WebCache         bool `mapstructure:"webcache"`
}

// DNSConfig holds DNS resolution settings.
type DNSConfig struct {
	Resolver            string `mapstructure:"resolver"`
	GenerateResolvers   bool   `mapstructure:"generate_resolvers"`
	ResolversURL        string `mapstructure:"resolvers_url"`
	TrustedResolversURL string `mapstructure:"trusted_resolvers_url"`
}

// RateLimitConfig holds rate limiting settings.
type RateLimitConfig struct {
	Adaptive bool `mapstructure:"adaptive"`
	MinRate  int  `mapstructure:"min_rate"`
	MaxRate  int  `mapstructure:"max_rate"`
	HTTPX    int  `mapstructure:"httpx"`
	Nuclei   int  `mapstructure:"nuclei"`
	FFUF     int  `mapstructure:"ffuf"`
}

// CacheConfig holds caching settings.
type CacheConfig struct {
	MaxAgeDays       int `mapstructure:"max_age_days"`
	ResolversTTLDays int `mapstructure:"resolvers_ttl_days"`
	WordlistsTTLDays int `mapstructure:"wordlists_ttl_days"`
}

// MonitoringConfig holds continuous monitoring settings.
type MonitoringConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	IntervalMinutes int    `mapstructure:"interval_minutes"`
	MaxCycles       int    `mapstructure:"max_cycles"`
	MinSeverity     string `mapstructure:"min_severity"`
}

// IncrementalConfig holds incremental scan settings.
type IncrementalConfig struct {
	Enabled  bool `mapstructure:"enabled"`
	DiffOnly bool `mapstructure:"diff_only"`
}

// ExportConfig holds export settings.
type ExportConfig struct {
	Format string       `mapstructure:"format"`
	Notify NotifyConfig `mapstructure:"notify"`
}

// NotifyConfig holds notification settings.
type NotifyConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	SlackWebhook   string `mapstructure:"slack_webhook"`
	DiscordWebhook string `mapstructure:"discord_webhook"`
	TelegramToken  string `mapstructure:"telegram_token"`
	TelegramChatID string `mapstructure:"telegram_chat_id"`
}

// AIConfig holds AI analysis settings.
type AIConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	Model         string `mapstructure:"model"`
	ReportProfile string `mapstructure:"report_profile"`
}

// Load reads configuration from a YAML file and environment variables.
func Load(cfgFile string, logger zerolog.Logger) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		// Search config in standard locations
		v.SetConfigName("default")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./configs")
		v.AddConfigPath(filepath.Join(os.Getenv("HOME"), ".reconforge"))
	}

	// Environment variables override (RECONFORGE_GENERAL_MAXWORKERS, etc.)
	v.SetEnvPrefix("RECONFORGE")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logger.Warn().Msg("No config file found, using defaults")
		} else {
			return nil, fmt.Errorf("error reading config: %w", err)
		}
	} else {
		logger.Info().Str("config", v.ConfigFileUsed()).Msg("Config loaded")
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error parsing config: %w", err)
	}

	// Expand ~ in paths
	cfg.General.ToolsDir = expandHome(cfg.General.ToolsDir)
	cfg.General.OutputDir = expandHome(cfg.General.OutputDir)

	if err := Validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// setDefaults applies sane default values.
func setDefaults(v *viper.Viper) {
	// General
	v.SetDefault("general.tools_dir", "~/Tools")
	v.SetDefault("general.output_dir", "./Recon")
	v.SetDefault("general.parallel", true)
	v.SetDefault("general.max_workers", 4)
	v.SetDefault("general.deep", false)
	v.SetDefault("general.verbose", false)

	// VM
	v.SetDefault("vm.enabled", true)
	v.SetDefault("vm.provider", "virtualbox")
	v.SetDefault("vm.name", "kali-reconforge")
	v.SetDefault("vm.memory", 4096)
	v.SetDefault("vm.cpus", 2)
	v.SetDefault("vm.disk_gb", 50)
	v.SetDefault("vm.image", "kali-rolling")
	v.SetDefault("vm.ssh_port", 2222)
	v.SetDefault("vm.shared_dir", "/shared")

	// OSINT
	v.SetDefault("osint.enabled", true)
	v.SetDefault("osint.google_dorks", true)
	v.SetDefault("osint.github_dorks", true)
	v.SetDefault("osint.github_repos", true)
	v.SetDefault("osint.github_leaks", true)
	v.SetDefault("osint.email_harvest", true)
	v.SetDefault("osint.cloud_enum", true)
	v.SetDefault("osint.metadata", true)
	v.SetDefault("osint.mail_hygiene", true)
	v.SetDefault("osint.spf_dmarc", true)
	v.SetDefault("osint.ip_info", true)
	v.SetDefault("osint.third_parties", true)
	v.SetDefault("osint.github_actions_audit", true)

	// Subdomain
	v.SetDefault("subdomain.enabled", true)
	v.SetDefault("subdomain.passive", true)
	v.SetDefault("subdomain.crt", true)
	v.SetDefault("subdomain.brute", true)
	v.SetDefault("subdomain.permutations", true)
	v.SetDefault("subdomain.ai_permutations", true)
	v.SetDefault("subdomain.recursive_passive", false)
	v.SetDefault("subdomain.recursive_brute", false)
	v.SetDefault("subdomain.takeover", true)
	v.SetDefault("subdomain.zone_transfer", true)
	v.SetDefault("subdomain.s3_buckets", true)
	v.SetDefault("subdomain.wildcard_filter", true)
	v.SetDefault("subdomain.regex_permut", true)
	v.SetDefault("subdomain.ptr_cidrs", true)
	v.SetDefault("subdomain.geo_info", true)
	v.SetDefault("subdomain.sub_ia_permut", true)

	// Web
	v.SetDefault("web.enabled", true)
	v.SetDefault("web.probe", true)
	v.SetDefault("web.screenshots", true)
	v.SetDefault("web.ports.standard", "80,443")
	v.SetDefault("web.ports.uncommon", "8080,8443,8000,9090")
	v.SetDefault("web.nuclei", true)
	v.SetDefault("web.cdnprovider", true)
	v.SetDefault("web.fuzzing", true)
	v.SetDefault("web.js_analysis", true)
	v.SetDefault("web.crawl", true)
	v.SetDefault("web.cms_scan", true)
	v.SetDefault("web.waf_detect", true)
	v.SetDefault("web.graphql", true)
	v.SetDefault("web.urlext", true)
	v.SetDefault("web.service_fingerprint", true)
	v.SetDefault("web.param_discovery", true)
	v.SetDefault("web.port_scan", true)
	v.SetDefault("web.virtual_hosts", true)
	v.SetDefault("web.url_checks", true)
	v.SetDefault("web.url_gf", true)
	v.SetDefault("web.iis_shortname", true)
	v.SetDefault("web.tls_ip_pivots", true)
	v.SetDefault("web.favirecon_tech", true)
	v.SetDefault("web.broken_links", true)
	v.SetDefault("web.wordlist_gen", true)
	v.SetDefault("web.sub_js_extract", true)
	v.SetDefault("web.wellknown_pivots", true)
	v.SetDefault("web.grpc_reflection", true)
	v.SetDefault("web.websocket_checks", true)
	v.SetDefault("web.wordlist_gen_roboxtractor", true)
	v.SetDefault("web.password_dict", true)
	v.SetDefault("web.llm_probe", true)

	// Vuln
	v.SetDefault("vuln.enabled", false)
	v.SetDefault("vuln.xss", true)
	v.SetDefault("vuln.ssrf", true)
	v.SetDefault("vuln.sqli", true)
	v.SetDefault("vuln.ssti", true)
	v.SetDefault("vuln.lfi", true)
	v.SetDefault("vuln.ssl", true)
	v.SetDefault("vuln.smuggling", true)
	v.SetDefault("vuln.spray", true)
	v.SetDefault("vuln.command_injection", true)
	v.SetDefault("vuln.nuclei_dast", true)

	// DNS
	v.SetDefault("dns.resolver", "auto")
	v.SetDefault("dns.generate_resolvers", false)

	// Rate limit
	v.SetDefault("ratelimit.adaptive", false)
	v.SetDefault("ratelimit.min_rate", 10)
	v.SetDefault("ratelimit.max_rate", 500)
	v.SetDefault("ratelimit.httpx", 150)
	v.SetDefault("ratelimit.nuclei", 150)
	v.SetDefault("ratelimit.ffuf", 0)

	// Cache
	v.SetDefault("cache.max_age_days", 30)
	v.SetDefault("cache.resolvers_ttl_days", 7)
	v.SetDefault("cache.wordlists_ttl_days", 30)

	// Monitoring
	v.SetDefault("monitoring.enabled", false)
	v.SetDefault("monitoring.interval_minutes", 60)
	v.SetDefault("monitoring.max_cycles", 0)
	v.SetDefault("monitoring.min_severity", "high")

	// Incremental
	v.SetDefault("incremental.enabled", false)
	v.SetDefault("incremental.diff_only", true)

	// Export
	v.SetDefault("export.format", "all")
	v.SetDefault("export.notify.enabled", false)

	// AI
	v.SetDefault("ai.enabled", false)
	v.SetDefault("ai.model", "llama3:8b")
	v.SetDefault("ai.report_profile", "bughunter")
}

// expandHome replaces ~ with the user's home directory.
func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
