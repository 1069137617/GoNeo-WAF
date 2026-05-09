package core

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/waf-go/waf/ip2region"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	maxCheckLength = 8 * 1024
)

type Config struct {
	Enabled                bool
	CCEnabled              bool
	CCRequestLimit         int
	CCBlockDuration        time.Duration
	AttackBlockThreshold   int
	AttackBlockDuration    time.Duration
	AttackBlockDurationStr string
	AttackWindowDuration   time.Duration
	SQLInjectionEnabled    bool
	UAEnabled              bool
	XSSEnabled             bool
	SSRFEnabled            bool
	CRLFEnabled            bool
	ZeroDayEnabled         bool
	PathTraversalEnabled   bool
	SensitiveParamEnabled  bool
	StrictMode             bool
	AllowedUAs             []string
	AllowLocalNetwork      bool
	AllowedNetworks        []string
	MaxRequestSize         int64
	NodeReportPaths        []string
	IP2RegionDBPath        string
}

type WAF struct {
	config     Config
	ipCounter  map[string]*ipRecord
	mu         sync.RWMutex
	uaPatterns []*regexp.Regexp

	sqlPatterns           []*regexp.Regexp
	zeroDayPatterns       []*zeroDayRule
	vulnPatterns          []*vulnRule
	ssrfPatterns          []*regexp.Regexp
	crlfPatterns          []*regexp.Regexp
	sensitiveParams       []sensitiveParamRule
	sensitivePathPatterns []*regexp.Regexp
	allowedNetworks       []*net.IPNet
	ipSearcher            *ip2region.Searcher

	attackCounter map[string]*attackRecord
	attackMu      sync.RWMutex

	stats *WAFStats
}

type ipRecord struct {
	count        int
	firstSeen    time.Time
	blockedUntil time.Time
}

type attackRecord struct {
	count        int
	firstSeen    time.Time
	blockedUntil time.Time
}

type WAFStats struct {
	mu                     sync.RWMutex
	TotalRequests          int64
	BlockedCC              int64
	BlockedUA              int64
	BlockedSQL             int64
	BlockedZeroDay         int64
	BlockedVulnerability   int64
	BlockedSensitiveParams int64
	BlockedTotal           int64
	TopBlockedIPs          map[string]*IPStats
	TopBlockedUAs          map[string]int64
	TopBlockedCountries    map[string]int64
	HourlyStats            [24]*HourlyStat
}

type IPStats struct {
	Count        int64
	Country      string
	City         string
	BlockCC      int64
	BlockUA      int64
	BlockSQL     int64
	BlockZeroDay int64
	BlockVuln    int64
}

type HourlyStat struct {
	Timestamp              time.Time
	TotalRequests          int64
	BlockedCC              int64
	BlockedUA              int64
	BlockedSQL             int64
	BlockedZeroDay         int64
	BlockedVuln            int64
	BlockedSensitiveParams int64
}

type zeroDayRule struct {
	pattern  *regexp.Regexp
	keywords []string
	isRegex  bool
}

type vulnRule struct {
	pattern  *regexp.Regexp
	keywords []string
	isRegex  bool
}

type sensitiveParamRule struct {
	param   string
	values  []string
	pattern *regexp.Regexp
	isRegex bool
}

type TopIPInfo struct {
	IP           string `json:"ip"`
	Count        int64  `json:"count"`
	Country      string `json:"country"`
	BlockCC      int64  `json:"blockCC"`
	BlockUA      int64  `json:"blockUA"`
	BlockSQL     int64  `json:"blockSQL"`
	BlockZeroDay int64  `json:"blockZeroDay"`
	BlockVuln    int64  `json:"blockVuln"`
}

type UAStat struct {
	UA    string `json:"ua"`
	Count int64  `json:"count"`
}

type CountryStat struct {
	Country string `json:"country"`
	Count   int64  `json:"count"`
}

type HourlyStatInfo struct {
	Hour                   int       `json:"hour"`
	Timestamp              time.Time `json:"timestamp"`
	TotalRequests          int64     `json:"totalRequests"`
	BlockedCC              int64     `json:"blockedCC"`
	BlockedUA              int64     `json:"blockedUA"`
	BlockedSQL             int64     `json:"blockedSQL"`
	BlockedZeroDay         int64     `json:"blockedZeroDay"`
	BlockedVuln            int64     `json:"blockedVuln"`
	BlockedSensitiveParams int64     `json:"blockedSensitiveParams"`
}

type WAFStatsResponse struct {
	TotalRequests          int64            `json:"totalRequests"`
	BlockedCC              int64            `json:"blockedCC"`
	BlockedUA              int64            `json:"blockedUA"`
	BlockedSQL             int64            `json:"blockedSQL"`
	BlockedZeroDay         int64            `json:"blockedZeroDay"`
	BlockedVulnerability   int64            `json:"blockedVulnerability"`
	BlockedSensitiveParams int64            `json:"blockedSensitiveParams"`
	BlockedTotal           int64            `json:"blockedTotal"`
	TopIPs                 []TopIPInfo      `json:"topIPs"`
	TopUAs                 []UAStat         `json:"topUAs"`
	TopCountries           []CountryStat    `json:"topCountries"`
	HourlyStats            []HourlyStatInfo `json:"hourlyStats"`
}

var defaultWAF *WAF

func New(cfg Config) *WAF {
	waf := &WAF{
		config:        cfg,
		ipCounter:     make(map[string]*ipRecord),
		attackCounter: make(map[string]*attackRecord),
		stats: &WAFStats{
			TopBlockedIPs:       make(map[string]*IPStats),
			TopBlockedUAs:       make(map[string]int64),
			TopBlockedCountries: make(map[string]int64),
		},
	}

	for i := range waf.stats.HourlyStats {
		waf.stats.HourlyStats[i] = &HourlyStat{}
	}

	for _, ua := range cfg.AllowedUAs {
		pattern, err := regexp.Compile(ua)
		if err == nil {
			waf.uaPatterns = append(waf.uaPatterns, pattern)
		}
	}

	waf.compileSQLPatterns()
	waf.compileZeroDayPatterns()
	waf.compileVulnPatterns()
	waf.compileSSRFPatterns()
	waf.compileCRLFPatterns()
	waf.compileSensitiveParams()
	waf.compileSensitivePaths()
	waf.parseAllowedNetworks()
	waf.initIPSearcher()

	go waf.cleanupLoop()

	return waf
}

func (w *WAF) compileSQLPatterns() {
	w.sqlPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)\s`),
		regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)\s+(all|distinct|top)`),
		regexp.MustCompile(`(?i)concat\s*\(`),
		regexp.MustCompile(`(?i)char\s*\(\s*\d+\s*\)`),
		regexp.MustCompile(`(?i)information_schema`),
		regexp.MustCompile(`(?i)benchmark\s*\(`),
		regexp.MustCompile(`(?i)sleep\s*\(`),
		regexp.MustCompile(`(?i)load_file\s*\(`),
		regexp.MustCompile(`(?i)into\s+(out|dump)file`),
		regexp.MustCompile(`--\s*$`),
		regexp.MustCompile(`;\s*drop\s`),
		regexp.MustCompile(`;\s*delete\s`),
		regexp.MustCompile(`;\s*insert\s`),
		regexp.MustCompile(`;\s*update\s`),
		regexp.MustCompile(`(?i)\bunion\s+(all\s+)?select\b`),
		regexp.MustCompile(`(?i)(\bor\b|\band\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?`),
		regexp.MustCompile(`(?i)['"]\s*(or|and)\s+['"]?\w+['"]?\s*=\s*['"]?\w+`),
		regexp.MustCompile(`(?i)['"]\s*(or|and)\s+['"]`),
		regexp.MustCompile(`(?i)'\s+(or|and)\s+'`),
		regexp.MustCompile(`(?i)extractvalue\s*\(`),
		regexp.MustCompile(`(?i)updatexml\s*\(`),
		regexp.MustCompile(`(?i)information_schema\.(tables|columns|schemata)`),
		regexp.MustCompile(`';\s*--`),
		regexp.MustCompile(`"\s*;\s*--`),
		regexp.MustCompile(`(?i)union(/\*.*?\*/)?\s*(all\s+)?select`),
		regexp.MustCompile(`(?i)union\s*/\*.*?\*/\s*select`),
		regexp.MustCompile(`(?i)union\s*\(select`),
		regexp.MustCompile(`(?i)union\s*\(.*?select`),
		regexp.MustCompile(`(?i)'\s*or\s*['"]?\d+['"]?\s*=\s*['"]?\d+`),
		regexp.MustCompile(`(?i)'\s*or\s*'\w+'\s*=\s*'\w+`),
		regexp.MustCompile(`(?i)'\s*or\s*'\w+'\s*like\s*'\w+`),
		regexp.MustCompile(`(?i)'\s*or\s*1\s*=\s*1`),
		regexp.MustCompile(`(?i)'\s*and\s*1\s*=\s*1`),
		regexp.MustCompile(`(?i)'\s*or\s*'[^']*'\s*=\s*'[^']*'`),
		regexp.MustCompile(`(?i)(u%6eion|uniunionon|selecselectt|ununionion)`),
		regexp.MustCompile(`(?i)%27\s*(or|and)\s*%27`),
		regexp.MustCompile(`(?i)%27\s*or\s*1\s*=\s*1`),
		regexp.MustCompile(`(?i)'\s*or\s*'[^']*'\s*=\s*'[^']*'`),
		regexp.MustCompile(`(?i)'\s*or\s*'\d+'\s*=\s*'\d+'`),
		regexp.MustCompile(`(?i)'\s*or\s*'[a-z]+'\s*=\s*'[a-z]+'`),
		regexp.MustCompile(`(?i)\bor\b\s+\d+=\d+`),
		regexp.MustCompile(`(?i)\bor\b\s+'[^']*'\s*=\s*'[^']*'`),
	}
}

func (w *WAF) compileZeroDayPatterns() {
	w.zeroDayPatterns = []*zeroDayRule{
		{keywords: []string{"<%", "{{", "%00", "\\x00", "\\u0000"}},
		{keywords: []string{"｛｛", "＜%", "＜！DOCTYPE"}},
		{pattern: regexp.MustCompile(`(?i)\$\{\s*jndi\s*:`), keywords: []string{"${jndi:"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\$\{\s*(lower|upper|env|sys)\s*:`), keywords: []string{"${lower:", "${upper:", "${env:", "${sys:"}, isRegex: true},
		{keywords: []string{"proc/self/environ", "/etc/passwd", "/etc/shadow", "/etc/hosts", "c:\\windows", "/bin/sh", "/bin/bash", "cmd.exe", "powershell"}},
		{keywords: []string{"/root/.ssh/id_rsa", "/.ssh/id_rsa", ".git/config", ".git/HEAD", "/.env", "%2f.env", ".env.local", ".env.production", ".env"}},
		{keywords: []string{"wp-config.php", "database.yml", "boot.ini", "win.ini", "system32/config/sam", "windows/system32/drivers/etc/hosts"}},
		{keywords: []string{"bin/sh", "daemon", "outroot", "passwd", "shadow", "sudo", "su "}},
		{keywords: []string{"touch ", "chmod ", "chown ", "wget ", "curl ", "nc ", "netcat ", "bash ", "python ", "perl ", "ruby ", "php "}},
		{keywords: []string{"exec(", "passthru(", "shell_exec(", "system(", "popen(", "proc_open(", "curl_init(", "assert("}},
		{keywords: []string{";tac ", "|tac ", ";nl ", "|nl ", ";more ", "|more ", ";less ", "|less ", ";head ", "|head ", ";tail ", "|tail ", ";cat ", "|cat "}},
		{keywords: []string{"/?/??t", "/bin/c??", "/bin/??t", "/usr/bin/c??"}},
		{pattern: regexp.MustCompile(`(?i)base64\s*\(`), keywords: []string{"base64"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)compress\.zlib`), keywords: []string{"compress.zlib"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\.\./\.\./`), keywords: []string{"../.."}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\.\./\.\.`), keywords: []string{"../.."}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)%2e%2e%2e`), keywords: []string{"%2e%2e%2e"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\.\.%`), keywords: []string{"..%"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\.\.%2f`), keywords: []string{"..%2f"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\.%2e/`), keywords: []string{".%2e/"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\.\.%5c`), keywords: []string{"..%5c"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\.\.\\`), keywords: []string{"..\\"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)%u[0-9a-f]{4}`), keywords: []string{"%u"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}`), keywords: []string{"%"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\\x[0-9a-f]{2}`), keywords: []string{"\\x"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)&#x[0-9a-f]+;`), keywords: []string{"&#x"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)&#\d+;`), keywords: []string{"&#"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)<!\[cdata\[`), keywords: []string{"<![CDATA["}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)<!DOCTYPE`), keywords: []string{"<!DOCTYPE"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)xmlns`), keywords: []string{"xmlns"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)xlink`), keywords: []string{"xlink"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)ENTITY\s+`), keywords: []string{"ENTITY"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)SYSTEM\s+`), keywords: []string{"SYSTEM"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)PUBLIC\s+`), keywords: []string{"PUBLIC"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\{[\s\S]*"\\u`), keywords: []string{"\\u"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)"\s*:\s*"\s*\+\s*"`), keywords: []string{}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)__proto__`), keywords: []string{"__proto__"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*cat`), keywords: []string{"|cat"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*ls`), keywords: []string{"|ls"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i);\s*cat`), keywords: []string{";cat"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*tac`), keywords: []string{"|tac"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*nl`), keywords: []string{"|nl"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*more`), keywords: []string{"|more"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\$\(`), keywords: []string{"$("}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\{\{`), keywords: []string{"{{"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\{\{[\s\S]*?\}\}`), keywords: []string{"{{}}"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\{\{template`), keywords: []string{"{{template"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\{\{range`), keywords: []string{"{{range"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\{\{if`), keywords: []string{"{{if"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\{\{printf`), keywords: []string{"{{printf"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\{\{\.`), keywords: []string{"{{."}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\{\{block`), keywords: []string{"{{block"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\{\{with`), keywords: []string{"{{with"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\(\^[a-zA-Z]+\$\)\*`), keywords: []string{"(^...$)*"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\(\.[a-zA-Z]+\)\+`), keywords: []string{"(.*)+"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\([a-zA-Z]+\+\)\+`), keywords: []string{"(a+)+"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)exec\.Command`), keywords: []string{"exec.Command"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)os/exec`), keywords: []string{"os/exec"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)exec\.LookPath`), keywords: []string{"exec.LookPath"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)%2e%2e%2f`), keywords: []string{"%2e%2e%2f"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)%252e%252e%252f`), keywords: []string{"%252e%252e%252f"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)%2e%2e%5c`), keywords: []string{"%2e%2e%5c"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)%252e%252e%5c`), keywords: []string{"%252e%252e%5c"}, isRegex: true},
	}
}

func (w *WAF) compileVulnPatterns() {
	w.vulnPatterns = []*vulnRule{
		{pattern: regexp.MustCompile(`(?i)/\.\./`), keywords: []string{"../"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)%2e%2e`), keywords: []string{"%2e%2e"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)%252e%252e`), keywords: []string{"%252e%252e"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\.\./`), keywords: []string{"../"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\.\.%`), keywords: []string{"..%"}, isRegex: true},
		{keywords: []string{"javascript:", "<script", "onerror=", "onload=", "onclick=", "onmouseover=", "<iframe", "<embed", "<object"}},
		{keywords: []string{"alert(", "eval(", "document.cookie", "document.write"}},
		{keywords: []string{"file:///", "dict://", "sftp://", "ldap://", "gopher://", "mysql://", "postgres://", "mongodb://", "php://", "expect://", "phar://", "glob://"}},
		{keywords: []string{"/.git/config", "/.svn/entries", "/.hg/hgrc", "/.DS_Store", "/server-status", "/phpinfo.php", "/vendor/phpunit"}},
		{pattern: regexp.MustCompile(`(?i)(eval|assert|system|passthru|shell_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)`), keywords: []string{"$_"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)(base64_decode|gzinflate|str_rot13)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)`), keywords: []string{"$_"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)preg_replace\s*\([^)]*/e[^)]*\$_(GET|POST|REQUEST|COOKIE|SERVER)`), keywords: []string{"preg_replace", "$_"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)create_function\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE|SERVER)`), keywords: []string{"create_function", "$_"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onfocus\s*=`), keywords: []string{"onfocus="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onblur\s*=`), keywords: []string{"onblur="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onchange\s*=`), keywords: []string{"onchange="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onsubmit\s*=`), keywords: []string{"onsubmit="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onreset\s*=`), keywords: []string{"onreset="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onselect\s*=`), keywords: []string{"onselect="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onkeydown\s*=`), keywords: []string{"onkeydown="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onkeypress\s*=`), keywords: []string{"onkeypress="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onkeyup\s*=`), keywords: []string{"onkeyup="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onmousedown\s*=`), keywords: []string{"onmousedown="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onmousemove\s*=`), keywords: []string{"onmousemove="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onmouseout\s*=`), keywords: []string{"onmouseout="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onmouseup\s*=`), keywords: []string{"onmouseup="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onabort\s*=`), keywords: []string{"onabort="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onload\s*=`), keywords: []string{"onload="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)onerror\s*=`), keywords: []string{"onerror="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)autofocus\s*=`), keywords: []string{"autofocus="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)accesskey\s*=`), keywords: []string{"accesskey="}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)data:text/html`), keywords: []string{"data:text/html"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)vbscript:`), keywords: []string{"vbscript:"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)jar:`), keywords: []string{"jar:"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*whoami`), keywords: []string{"|whoami"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*id\b`), keywords: []string{"|id"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*pwd`), keywords: []string{"|pwd"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*ls\b`), keywords: []string{"|ls"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*dir\b`), keywords: []string{"|dir"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*cat\b`), keywords: []string{"|cat"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*tac\b`), keywords: []string{"|tac"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*nl\b`), keywords: []string{"|nl"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*more\b`), keywords: []string{"|more"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*less\b`), keywords: []string{"|less"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*head\b`), keywords: []string{"|head"}, isRegex: true},
		{pattern: regexp.MustCompile(`(?i)\|\s*tail\b`), keywords: []string{"|tail"}, isRegex: true},
	}
}

func (w *WAF) compileSSRFPatterns() {
	w.ssrfPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(url|src|dest|redirect|uri|continue|return)\s*=\s*[` + "`" + `"']?https?://`),
		regexp.MustCompile(`(?i)url\s*=\s*[` + "`" + `"']?//`),
		regexp.MustCompile(`(?i)url\s*=\s*[` + "`" + `"']?ftp://`),
		regexp.MustCompile(`(?i)url\s*=\s*[` + "`" + `"']?file://`),
		regexp.MustCompile(`(?i)url\s*=\s*[` + "`" + `"']?dict://`),
		regexp.MustCompile(`(?i)url\s*=\s*[` + "`" + `"']?sftp://`),
		regexp.MustCompile(`(?i)url\s*=\s*[` + "`" + `"']?ldap://`),
		regexp.MustCompile(`(?i)url\s*=\s*[` + "`" + `"']?gopher://`),
		regexp.MustCompile(`(?i)url\s*=\s*[` + "`" + `"']?data://`),
		regexp.MustCompile(`(?i)url\s*=\s*[` + "`" + `"']?glob://`),
		regexp.MustCompile(`(?i)url\s*=\s*[` + "`" + `"']?phar://`),
		regexp.MustCompile(`(?i)url\s*=\s*[` + "`" + `"']?tar://`),
		regexp.MustCompile(`(?i)169\.254\.169\.254`),
		regexp.MustCompile(`(?i)metadata\.google\.internal`),
		regexp.MustCompile(`(?i)latest/meta-data`),
		regexp.MustCompile(`(?i)metadata/identity/oauth2/token`),
	}
}

func (w *WAF) compileCRLFPatterns() {
	w.crlfPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)%0[dD]%0[aA]\s*(location|set-cookie|content-type|content-length)\s*:`),
		regexp.MustCompile(`(?i)%0[aA]\s*(location|set-cookie|content-type|content-length)\s*:`),
		regexp.MustCompile(`(?i)%0[dD]\s*(location|set-cookie|content-type|content-length)\s*:`),
		regexp.MustCompile(`(?i)\r\n\s*(location|set-cookie|content-type|content-length)\s*:`),
		regexp.MustCompile(`(?i)\n\s*(location|set-cookie|content-type|content-length)\s*:`),
		regexp.MustCompile(`(?i)%0[dD]%0[aA]\s*http/`),
		regexp.MustCompile(`(?i)%0[aA]\s*http/`),
		regexp.MustCompile(`(?i)%0[dD]\s*http/`),
		regexp.MustCompile(`(?i)\r\n\s*http/`),
		regexp.MustCompile(`(?i)\n\s*http/`),
	}
}

func (w *WAF) compileSensitiveParams() {
	w.sensitiveParams = []sensitiveParamRule{
		{param: "debug", values: []string{"pprof", "true", "1", "on", "yes"}},
		{param: "trace", values: []string{"pprof", "true", "1", "on", "yes"}},
		{param: "profile", values: []string{"pprof", "true", "1", "on", "yes"}},
		{param: "pprof", values: []string{"true", "1", "on", "yes", "enable", "enabled"}},
		{param: "debug_mode", values: []string{"true", "1", "on", "yes"}},
		{param: "debugmode", values: []string{"true", "1", "on", "yes"}},
		{param: "enable_debug", values: []string{"true", "1", "on", "yes"}},
		{param: "admin", values: []string{"true", "1", "on", "yes"}},
		{param: "test", values: []string{"pprof", "debug"}},
		{param: "cmd", values: []string{"exec", "run", "shell"}},
		{param: "command", values: []string{"exec", "run", "shell"}},
		{param: "exec", values: []string{"true", "1", "on", "yes"}},
		{param: "shell", values: []string{"true", "1", "on", "yes"}},
		{param: "console", values: []string{"true", "1", "on", "yes"}},
		{param: "terminal", values: []string{"true", "1", "on", "yes"}},
		{pattern: regexp.MustCompile(`(?i)^(debug|trace|profile|pprof)$`), isRegex: true},
	}
}

func (w *WAF) compileSensitivePaths() {
	w.sensitivePathPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)/debug/pprof`),
		regexp.MustCompile(`(?i)/debug/vars`),
		regexp.MustCompile(`(?i)/debug/requests`),
		regexp.MustCompile(`(?i)/debug/events`),
		regexp.MustCompile(`(?i)/debug/expvars`),
		regexp.MustCompile(`(?i)/debug/goroutine`),
		regexp.MustCompile(`(?i)/debug/heap`),
		regexp.MustCompile(`(?i)/debug/threadcreate`),
		regexp.MustCompile(`(?i)/debug/block`),
		regexp.MustCompile(`(?i)/debug/mutex`),
		regexp.MustCompile(`(?i)/debug/allocs`),
		regexp.MustCompile(`(?i)/debug/trace`),
		regexp.MustCompile(`(?i)/debug/profile`),
		regexp.MustCompile(`(?i)/debug/cmdline`),
		regexp.MustCompile(`(?i)/debug/symbol`),

		regexp.MustCompile(`(?i)/actuator`),
		regexp.MustCompile(`(?i)/actuator/health`),
		regexp.MustCompile(`(?i)/actuator/env`),
		regexp.MustCompile(`(?i)/actuator/beans`),
		regexp.MustCompile(`(?i)/actuator/mappings`),
		regexp.MustCompile(`(?i)/actuator/loggers`),
		regexp.MustCompile(`(?i)/actuator/httptrace`),
		regexp.MustCompile(`(?i)/actuator/threaddump`),
		regexp.MustCompile(`(?i)/actuator/heapdump`),
		regexp.MustCompile(`(?i)/actuator/dump`),
		regexp.MustCompile(`(?i)/actuator/auditevents`),
		regexp.MustCompile(`(?i)/actuator/scheduledtasks`),
		regexp.MustCompile(`(?i)/actuator/sessions`),
		regexp.MustCompile(`(?i)/actuator/shutdown`),
		regexp.MustCompile(`(?i)/actuator/jolokia`),
		regexp.MustCompile(`(?i)/actuator/hystrix`),
	}
}

func (w *WAF) parseAllowedNetworks() {
	for _, network := range w.config.AllowedNetworks {
		_, ipNet, err := net.ParseCIDR(network)
		if err == nil {
			w.allowedNetworks = append(w.allowedNetworks, ipNet)
		}
	}
}

func (w *WAF) initIPSearcher() {
	dbPath := w.config.IP2RegionDBPath
	if dbPath == "" {
		dbPath = filepath.Join("data", "ip2region_v4.xdb")
	}

	searcher, err := ip2region.LoadFromFile(dbPath)
	if err != nil {
		zap.L().Warn("[WAF] ip2region数据库加载失败，IP地理位置检测将不可用", zap.Error(err))
		return
	}
	w.ipSearcher = searcher
	zap.L().Info("[WAF] ip2region数据库加载成功")
}

func (w *WAF) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		w.cleanup()
	}
}

func (w *WAF) cleanup() {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	for ip, record := range w.ipCounter {
		if now.Sub(record.firstSeen) > 10*time.Minute && now.After(record.blockedUntil) {
			delete(w.ipCounter, ip)
		}
	}

	w.attackMu.Lock()
	defer w.attackMu.Unlock()
	for ip, record := range w.attackCounter {
		if now.Sub(record.firstSeen) > 10*time.Minute && now.After(record.blockedUntil) {
			delete(w.attackCounter, ip)
		}
	}
}

func (w *WAF) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !w.config.Enabled {
			c.Next()
			return
		}

		clientIP := c.ClientIP()
		w.stats.mu.Lock()
		w.stats.TotalRequests++
		w.stats.mu.Unlock()

		lowIntensity := false
		for _, path := range w.config.NodeReportPaths {
			if c.Request.URL.Path == path {
				lowIntensity = true
				break
			}
		}

		w.mu.RLock()
		record, exists := w.ipCounter[clientIP]
		w.mu.RUnlock()

		if exists && time.Now().Before(record.blockedUntil) {
			w.stats.mu.Lock()
			w.stats.BlockedCC++
			w.stats.BlockedTotal++
			w.stats.mu.Unlock()
			w.recordBlockedIP(clientIP, "cc")
			w.recordHourlyStat("cc")
			zap.L().Warn("[WAF] IP已被拉黑",
				zap.String("ip", clientIP),
				zap.String("path", c.Request.URL.Path),
			)
			ForbiddenWithHelp(c, "请求过于频繁，请稍后再试", "如误拦截请联系管理员")
			c.Abort()
			return
		}

		bodyBytes, bodyErr := w.readAndRestoreBody(c)
		if bodyErr != nil {
			zap.L().Warn("[WAF] 请求体过大或读取失败",
				zap.String("ip", clientIP),
				zap.String("path", c.Request.URL.Path),
				zap.Error(bodyErr),
			)
			c.JSON(413, gin.H{
				"success": false,
				"message": "请求体过大",
			})
			c.Abort()
			return
		}

		if w.config.CCEnabled {
			if w.isCCAttack(clientIP) {
				w.stats.BlockedCC++
				w.stats.BlockedTotal++
				w.recordBlockedIP(clientIP, "cc")
				w.recordHourlyStat("cc")
				zap.L().Warn("[WAF] CC攻击拦截",
					zap.String("ip", clientIP),
					zap.String("path", c.Request.URL.Path),
					zap.String("ua", maskUA(c.Request.UserAgent())),
				)
				ForbiddenWithHelp(c, "请求过于频繁，请稍后再试", "如误拦截请联系管理员")
				c.Abort()
				return
			}
		}

		if w.config.UAEnabled && !lowIntensity && len(w.uaPatterns) > 0 {
			if !w.isAllowedUA(c.Request.UserAgent()) {
				w.stats.BlockedUA++
				w.stats.BlockedTotal++
				w.recordBlockedIP(clientIP, "ua")
				w.stats.recordUA(c.Request.UserAgent())
				w.recordHourlyStat("ua")
				zap.L().Warn("[WAF] UA拦截",
					zap.String("ip", clientIP),
					zap.String("ua", maskUA(c.Request.UserAgent())),
				)
				Forbidden(c, "不支持的客户端环境")
				c.Abort()
				return
			}
		}

		if w.config.SQLInjectionEnabled && !lowIntensity {
			if w.isSQLInjection(c, bodyBytes) {
				w.stats.BlockedSQL++
				w.stats.BlockedTotal++
				w.recordBlockedIP(clientIP, "sql")
				w.recordHourlyStat("sql")

				if w.recordAttackAndCheckBlock(clientIP) {
					w.stats.BlockedCC++
					w.recordBlockedIP(clientIP, "cc")
					w.recordHourlyStat("cc")
					zap.L().Warn("[WAF] 多次攻击IP已被拉黑",
						zap.String("ip", clientIP),
						zap.String("type", "sql"),
						zap.String("path", c.Request.URL.Path),
					)
				}

				zap.L().Warn("[WAF] SQL注入拦截",
					zap.String("ip", clientIP),
					zap.String("path", c.Request.URL.Path),
					zap.String("query", maskSensitive(c.Request.URL.RawQuery)),
				)
				ForbiddenWithHelp(c, "请求参数包含非法内容", "如误拦截请联系管理员")
				c.Abort()
				return
			}
		}

		if w.config.ZeroDayEnabled && !lowIntensity && w.hasZeroDayThreat(c, bodyBytes) {
			w.stats.BlockedZeroDay++
			w.stats.BlockedTotal++
			w.recordBlockedIP(clientIP, "zeroday")
			w.recordHourlyStat("zeroday")

			if w.recordAttackAndCheckBlock(clientIP) {
				w.stats.BlockedCC++
				w.recordBlockedIP(clientIP, "cc")
				w.recordHourlyStat("cc")
				zap.L().Warn("[WAF] 多次攻击IP已被拉黑",
					zap.String("ip", clientIP),
					zap.String("type", "zeroday"),
					zap.String("path", c.Request.URL.Path),
				)
			}

			zap.L().Warn("[WAF] 0day攻击拦截",
				zap.String("ip", clientIP),
				zap.String("path", c.Request.URL.Path),
				zap.String("method", c.Request.Method),
			)
			ForbiddenWithHelp(c, "请求包含潜在攻击特征", "如误拦截请联系管理员")
			c.Abort()
			return
		}

		if !lowIntensity && w.hasGoVulnerability(c, bodyBytes) {
			w.stats.BlockedVulnerability++
			w.stats.BlockedTotal++
			w.recordBlockedIP(clientIP, "vuln")
			w.recordHourlyStat("vuln")

			if w.recordAttackAndCheckBlock(clientIP) {
				w.stats.BlockedCC++
				w.recordBlockedIP(clientIP, "cc")
				w.recordHourlyStat("cc")
				zap.L().Warn("[WAF] 多次攻击IP已被拉黑",
					zap.String("ip", clientIP),
					zap.String("type", "vuln"),
					zap.String("path", c.Request.URL.Path),
				)
			}

			zap.L().Warn("[WAF] 漏洞攻击拦截",
				zap.String("ip", clientIP),
				zap.String("path", c.Request.URL.Path),
			)
			ForbiddenWithHelp(c, "请求包含潜在攻击特征", "如误拦截请联系管理员")
			c.Abort()
			return
		}

		if w.config.SensitiveParamEnabled && !lowIntensity && w.hasSensitiveParams(c) {
			w.stats.BlockedSensitiveParams++
			w.stats.BlockedTotal++
			w.recordBlockedIP(clientIP, "sensitive_param")
			w.recordHourlyStat("sensitive_param")

			if w.recordAttackAndCheckBlock(clientIP) {
				w.stats.BlockedCC++
				w.recordBlockedIP(clientIP, "cc")
				w.recordHourlyStat("cc")
				zap.L().Warn("[WAF] 多次攻击IP已被拉黑",
					zap.String("ip", clientIP),
					zap.String("type", "sensitive_param"),
					zap.String("path", c.Request.URL.Path),
				)
			}

			zap.L().Warn("[WAF] 敏感参数拦截",
				zap.String("ip", clientIP),
				zap.String("path", c.Request.URL.Path),
				zap.String("query", maskSensitive(c.Request.URL.RawQuery)),
			)
			ForbiddenWithHelp(c, "请求参数包含非法内容", "如误拦截请联系管理员")
			c.Abort()
			return
		}

		if w.config.SensitiveParamEnabled && !lowIntensity && w.hasSensitivePath(c) {
			w.stats.BlockedSensitiveParams++
			w.stats.BlockedTotal++
			w.recordBlockedIP(clientIP, "sensitive_path")
			w.recordHourlyStat("sensitive_path")

			if w.recordAttackAndCheckBlock(clientIP) {
				w.stats.BlockedCC++
				w.recordBlockedIP(clientIP, "cc")
				w.recordHourlyStat("cc")
				zap.L().Warn("[WAF] 多次攻击IP已被拉黑",
					zap.String("ip", clientIP),
					zap.String("type", "sensitive_path"),
					zap.String("path", c.Request.URL.Path),
				)
			}

			zap.L().Warn("[WAF] 敏感路径拦截",
				zap.String("ip", clientIP),
				zap.String("path", c.Request.URL.Path),
			)
			ForbiddenWithHelp(c, "请求路径包含非法内容", "如误拦截请联系管理员")
			c.Abort()
			return
		}

		c.Next()
	}
}

func (w *WAF) isCCAttack(ip string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	record, exists := w.ipCounter[ip]

	if !exists {
		w.ipCounter[ip] = &ipRecord{
			count:        1,
			firstSeen:    now,
			blockedUntil: time.Time{},
		}
		return false
	}

	if now.Before(record.blockedUntil) {
		return true
	}

	if now.Sub(record.firstSeen) > time.Minute {
		record.count = 1
		record.firstSeen = now
		record.blockedUntil = time.Time{}
		return false
	}

	record.count++
	if record.count > w.config.CCRequestLimit {
		record.blockedUntil = now.Add(w.config.CCBlockDuration)
		return true
	}

	return false
}

func (w *WAF) recordAttackAndCheckBlock(ip string) bool {
	w.attackMu.Lock()
	defer w.attackMu.Unlock()

	now := time.Now()
	record, exists := w.attackCounter[ip]

	if !exists {
		w.attackCounter[ip] = &attackRecord{
			count:        1,
			firstSeen:    now,
			blockedUntil: time.Time{},
		}
		return false
	}

	if now.Before(record.blockedUntil) {
		return true
	}

	windowDuration := w.config.AttackWindowDuration
	if windowDuration == 0 {
		windowDuration = 10 * time.Minute
	}

	if now.Sub(record.firstSeen) > windowDuration {
		record.count = 1
		record.firstSeen = now
		record.blockedUntil = time.Time{}
		return false
	}

	record.count++
	threshold := w.config.AttackBlockThreshold
	if threshold == 0 {
		threshold = 5
	}

	if record.count >= threshold {
		blockDuration := w.config.AttackBlockDuration
		if blockDuration == 0 {
			blockDuration = 1 * time.Hour
		}
		record.blockedUntil = now.Add(blockDuration)
		return true
	}

	return false
}

func (w *WAF) isAllowedUA(ua string) bool {
	if ua == "" {
		return false
	}

	for _, pattern := range w.uaPatterns {
		if pattern.MatchString(ua) {
			return true
		}
	}
	return false
}

func (w *WAF) isSQLInjection(c *gin.Context, bodyBytes []byte) bool {
	rawQuery := c.Request.URL.RawQuery
	decodedQuery := w.decodeQuery(rawQuery)
	checkString := rawQuery + " " + decodedQuery + " " + string(bodyBytes)

	for _, pattern := range w.sqlPatterns {
		if pattern.MatchString(checkString) {
			return true
		}
	}

	return false
}

func (w *WAF) decodeQuery(rawQuery string) string {
	decoded, err := url.QueryUnescape(rawQuery)
	if err != nil {
		return rawQuery
	}
	decoded2, err := url.QueryUnescape(decoded)
	if err != nil {
		return decoded
	}
	return decoded + " " + decoded2
}

func (w *WAF) hasZeroDayThreat(c *gin.Context, bodyBytes []byte) bool {
	checkString := w.buildCheckString(c, bodyBytes)

	for _, rule := range w.zeroDayPatterns {
		if w.matchRule(checkString, rule) {
			return true
		}
	}

	if w.isHTTPSmuggling(c) {
		return true
	}

	if w.config.CRLFEnabled && w.isCRLFInjection(c, bodyBytes) {
		return true
	}

	if w.isUnicodeBypass(c, bodyBytes) {
		return true
	}

	return false
}

func (w *WAF) matchRule(checkString string, rule *zeroDayRule) bool {
	if len(rule.keywords) > 0 {
		for _, keyword := range rule.keywords {
			if strings.Contains(checkString, keyword) {
				if !rule.isRegex || rule.pattern == nil {
					return true
				}
				if rule.pattern.MatchString(checkString) {
					return true
				}
			}
		}
		return false
	}

	if rule.isRegex && rule.pattern != nil {
		return rule.pattern.MatchString(checkString)
	}

	return false
}

func (w *WAF) matchVulnRule(checkString string, rule *vulnRule) bool {
	if !w.vulnRuleEnabled(rule) {
		return false
	}

	if len(rule.keywords) > 0 {
		for _, keyword := range rule.keywords {
			if strings.Contains(checkString, keyword) {
				if !rule.isRegex || rule.pattern == nil {
					return true
				}
				if rule.pattern.MatchString(checkString) {
					return true
				}
			}
		}
		return false
	}

	if rule.isRegex && rule.pattern != nil {
		return rule.pattern.MatchString(checkString)
	}

	return false
}

func (w *WAF) vulnRuleEnabled(rule *vulnRule) bool {
	if w.ruleHasKeyword(rule, "../", "%2e%2e", "%252e%252e", "..%", "/.git/config", "/.svn/entries", "/.hg/hgrc") {
		return w.config.PathTraversalEnabled
	}
	if w.ruleHasKeyword(rule, "javascript:", "<script", "onerror=", "onload=", "onclick=", "<iframe", "alert(", "document.cookie", "data:text/html", "vbscript:", "jar:") {
		return w.config.XSSEnabled
	}
	if w.ruleHasKeyword(rule, "file:///", "dict://", "sftp://", "ldap://", "gopher://", "mysql://", "postgres://", "mongodb://", "php://", "expect://", "phar://", "glob://") {
		return w.config.SSRFEnabled
	}
	return w.config.ZeroDayEnabled || w.config.StrictMode
}

func (w *WAF) ruleHasKeyword(rule *vulnRule, keywords ...string) bool {
	if rule == nil {
		return false
	}
	for _, ruleKeyword := range rule.keywords {
		for _, keyword := range keywords {
			if ruleKeyword == keyword || strings.Contains(ruleKeyword, keyword) {
				return true
			}
		}
	}
	return false
}

func (w *WAF) buildCheckString(c *gin.Context, bodyBytes []byte) string {
	var sb strings.Builder
	sb.WriteString(c.Request.URL.Path)
	sb.WriteString(" ")
	rawQuery := c.Request.URL.RawQuery
	sb.WriteString(rawQuery)
	sb.WriteString(" ")
	sb.WriteString(w.decodeQuery(rawQuery))
	sb.WriteString(" ")
	sb.WriteString(c.Request.Method)
	sb.WriteString(" ")

	if len(bodyBytes) > maxCheckLength {
		sb.Write(bodyBytes[:maxCheckLength])
	} else {
		sb.Write(bodyBytes)
	}
	sb.WriteString(" ")

	for name, values := range c.Request.Header {
		for _, value := range values {
			sb.WriteString(name)
			sb.WriteString(": ")
			sb.WriteString(value)
			sb.WriteString(" ")
		}
	}

	result := sb.String()
	if len(result) > maxCheckLength {
		return result[:maxCheckLength]
	}
	return result
}

func (w *WAF) isHTTPSmuggling(c *gin.Context) bool {
	te := c.GetHeader("Transfer-Encoding")
	cl := c.GetHeader("Content-Length")

	if strings.Contains(strings.ToLower(te), "chunked") && cl != "" {
		return true
	}

	if c.Request.ProtoMajor == 1 && c.Request.ProtoMinor == 0 && te != "" {
		return true
	}

	return false
}

func (w *WAF) isCRLFInjection(c *gin.Context, bodyBytes []byte) bool {
	for name, values := range c.Request.Header {
		headerValue := strings.Join(values, " ")
		for _, pattern := range w.crlfPatterns {
			if pattern.MatchString(headerValue) {
				return true
			}
		}
		_ = name
	}

	rawQuery := c.Request.URL.RawQuery
	for _, pattern := range w.crlfPatterns {
		if pattern.MatchString(rawQuery) {
			return true
		}
	}

	if len(bodyBytes) > 0 {
		bodyStr := string(bodyBytes)
		for _, pattern := range w.crlfPatterns {
			if pattern.MatchString(bodyStr) {
				return true
			}
		}
	}

	return false
}

func (w *WAF) isUnicodeBypass(c *gin.Context, bodyBytes []byte) bool {
	checkString := c.Request.URL.RawQuery
	if len(checkString) > maxCheckLength {
		checkString = checkString[:maxCheckLength]
	}

	unicodeMarkers := []string{"%uff1c", "%uf0fl", "%uf0", "%c0%", "%dc%", "%25"}
	for _, marker := range unicodeMarkers {
		if strings.Contains(checkString, marker) {
			return true
		}
	}

	if len(bodyBytes) > maxCheckLength {
		bodyBytes = bodyBytes[:maxCheckLength]
	}

	for _, marker := range unicodeMarkers {
		if strings.Contains(string(bodyBytes), marker) {
			return true
		}
	}

	return false
}

func (w *WAF) hasGoVulnerability(c *gin.Context, bodyBytes []byte) bool {
	checkString := w.buildCheckString(c, bodyBytes)

	for _, rule := range w.vulnPatterns {
		if w.matchVulnRule(checkString, rule) {
			return true
		}
	}

	if w.config.SSRFEnabled && w.isSSRFAttempt(c, bodyBytes) {
		return true
	}

	return false
}

func (w *WAF) hasSensitiveParams(c *gin.Context) bool {
	if !w.config.SensitiveParamEnabled {
		return false
	}

	query := c.Request.URL.Query()

	for _, rule := range w.sensitiveParams {
		if rule.isRegex && rule.pattern != nil {
			for paramName := range query {
				if rule.pattern.MatchString(paramName) {
					paramValues := query[paramName]
					for _, value := range paramValues {
						if value != "" {
							return true
						}
					}
				}
			}
		} else if rule.param != "" {
			if values, exists := query[rule.param]; exists {
				for _, value := range values {
					valueLower := strings.ToLower(value)
					for _, blockedValue := range rule.values {
						if valueLower == strings.ToLower(blockedValue) {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

func (w *WAF) hasSensitivePath(c *gin.Context) bool {
	if !w.config.SensitiveParamEnabled {
		return false
	}

	path := c.Request.URL.Path

	for _, pattern := range w.sensitivePathPatterns {
		if pattern.MatchString(path) {
			return true
		}
	}

	return false
}

func (w *WAF) isSSRFAttempt(c *gin.Context, bodyBytes []byte) bool {
	checkString := c.Request.URL.RawQuery + " " + string(bodyBytes)

	for _, pattern := range w.ssrfPatterns {
		if pattern.MatchString(checkString) {
			return true
		}
	}

	return false
}

func (w *WAF) readAndRestoreBody(c *gin.Context) ([]byte, error) {
	if c.Request.Body == nil {
		return []byte{}, nil
	}

	if !w.shouldInspectBody(c) {
		return []byte{}, nil
	}

	limit := w.config.MaxRequestSize
	if limit <= 0 {
		limit = 2 * 1024 * 1024
	}

	reader := io.LimitReader(c.Request.Body, limit+1)
	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return []byte{}, err
	}

	if int64(len(bodyBytes)) > limit {
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes[:limit]))
		return bodyBytes[:limit], fmt.Errorf("request body size exceeds limit %d", limit)
	}

	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	return bodyBytes, nil
}

func (w *WAF) shouldInspectBody(c *gin.Context) bool {
	contentType := c.GetHeader("Content-Type")
	if contentType == "" {
		return true
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	}

	switch strings.ToLower(mediaType) {
	case "application/json", "application/x-www-form-urlencoded", "text/plain", "application/xml", "text/xml":
		return true
	default:
		return false
	}
}

func maskUA(ua string) string {
	if ua == "" {
		return ""
	}

	if len(ua) > 30 {
		return ua[:30] + "..."
	}
	return ua
}

func maskSensitive(data string) string {
	if data == "" {
		return ""
	}

	sensitive := []string{"password", "passwd", "pwd", "token", "key", "secret", "auth", "credential"}

	result := data
	for _, s := range sensitive {
		pattern := regexp.MustCompile(fmt.Sprintf(`(?i)(%s=)[^&]*`, s))
		result = pattern.ReplaceAllString(result, "$1***")
	}

	return result
}

func InitDefault(cfg Config) {
	defaultWAF = New(cfg)
}

func GetDefault() *WAF {
	return defaultWAF
}

func GetConfig() Config {
	if defaultWAF == nil {
		return Config{}
	}
	return defaultWAF.config
}

func FormatAllowedUAs(uas string) []string {
	if uas == "" {
		return []string{
			`(?i)mozilla/.*`,
			`(?i)chrome/.*`,
			`(?i)safari/.*`,
			`(?i)firefox/.*`,
			`(?i)edg/.*`,
			`(?i)go-http-client/.*`,
			`(?i)golang/.*`,
		}
	}

	parts := strings.Split(uas, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func (w *WAF) recordBlockedIP(ip string, blockType string) {
	w.stats.mu.Lock()
	defer w.stats.mu.Unlock()

	if w.stats.TopBlockedIPs[ip] == nil {
		w.stats.TopBlockedIPs[ip] = &IPStats{}
	}
	w.stats.TopBlockedIPs[ip].Count++
	w.stats.TopBlockedIPs[ip].Country = w.detectCountry(ip)

	switch blockType {
	case "cc":
		w.stats.TopBlockedIPs[ip].BlockCC++
	case "ua":
		w.stats.TopBlockedIPs[ip].BlockUA++
	case "sql":
		w.stats.TopBlockedIPs[ip].BlockSQL++
	case "zeroday":
		w.stats.TopBlockedIPs[ip].BlockZeroDay++
	case "vuln":
		w.stats.TopBlockedIPs[ip].BlockVuln++
	}

	w.stats.TopBlockedCountries[w.stats.TopBlockedIPs[ip].Country]++
}

func (w *WAF) detectCountry(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "Unknown"
	}

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
		return "Local"
	}

	if w.ipSearcher != nil {
		region, err := w.ipSearcher.Search(ipStr)
		if err == nil && region != nil {
			if region.IsoCode != "" {
				return ip2region.GetCountryGroup(region.IsoCode)
			}
			if region.Country != "" && region.Country != "0" {
				return region.Country
			}
		}
	}

	ipBytes := ip.To4()
	if ipBytes != nil {
		firstOctet := int(ipBytes[0])
		secondOctet := int(ipBytes[1])

		switch {
		case firstOctet >= 1 && firstOctet <= 126:
			return "North America"
		case firstOctet >= 128 && firstOctet <= 191:
			if secondOctet >= 0 && secondOctet <= 15 {
				return "Europe"
			}
			return "Asia"
		case firstOctet >= 192 && firstOctet <= 223:
			if secondOctet >= 16 && secondOctet <= 31 {
				return "Europe"
			}
			return "Asia"
		case firstOctet >= 224 && firstOctet <= 239:
			return "Multicast"
		case firstOctet >= 240 && firstOctet <= 255:
			return "Reserved"
		}
	}

	return "Unknown"
}

func (w *WAF) recordHourlyStat(blockType string) {
	hour := time.Now().Hour()
	if w.stats.HourlyStats[hour] == nil {
		w.stats.HourlyStats[hour] = &HourlyStat{}
	}
	w.stats.HourlyStats[hour].TotalRequests++

	switch blockType {
	case "cc":
		w.stats.HourlyStats[hour].BlockedCC++
	case "ua":
		w.stats.HourlyStats[hour].BlockedUA++
	case "sql":
		w.stats.HourlyStats[hour].BlockedSQL++
	case "zeroday":
		w.stats.HourlyStats[hour].BlockedZeroDay++
	case "vuln":
		w.stats.HourlyStats[hour].BlockedVuln++
	case "sensitive_param":
		w.stats.HourlyStats[hour].BlockedSensitiveParams++
	}
}

func (s *WAFStats) recordUA(ua string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ua == "" {
		return
	}
	shortUA := maskUA(ua)
	s.TopBlockedUAs[shortUA]++
}

func (w *WAF) GetStats() WAFStatsResponse {
	w.stats.mu.RLock()
	defer w.stats.mu.RUnlock()

	var topIPs []TopIPInfo
	for ip, stats := range w.stats.TopBlockedIPs {
		topIPs = append(topIPs, TopIPInfo{
			IP:           ip,
			Count:        stats.Count,
			Country:      stats.Country,
			BlockCC:      stats.BlockCC,
			BlockUA:      stats.BlockUA,
			BlockSQL:     stats.BlockSQL,
			BlockZeroDay: stats.BlockZeroDay,
			BlockVuln:    stats.BlockVuln,
		})
	}
	sort.Slice(topIPs, func(i, j int) bool {
		return topIPs[i].Count > topIPs[j].Count
	})
	if len(topIPs) > 20 {
		topIPs = topIPs[:20]
	}

	var topUAs []UAStat
	for ua, count := range w.stats.TopBlockedUAs {
		topUAs = append(topUAs, UAStat{UA: ua, Count: count})
	}
	sort.Slice(topUAs, func(i, j int) bool {
		return topUAs[i].Count > topUAs[j].Count
	})
	if len(topUAs) > 10 {
		topUAs = topUAs[:10]
	}

	var topCountries []CountryStat
	for country, count := range w.stats.TopBlockedCountries {
		topCountries = append(topCountries, CountryStat{Country: country, Count: count})
	}
	sort.Slice(topCountries, func(i, j int) bool {
		return topCountries[i].Count > topCountries[j].Count
	})

	var hourlyStats []HourlyStatInfo
	now := time.Now()
	for i, stat := range w.stats.HourlyStats {
		if stat != nil && stat.TotalRequests > 0 {
			hourlyStats = append(hourlyStats, HourlyStatInfo{
				Hour:                   i,
				Timestamp:              now.Truncate(time.Hour).Add(time.Duration(i) * time.Hour),
				TotalRequests:          stat.TotalRequests,
				BlockedCC:              stat.BlockedCC,
				BlockedUA:              stat.BlockedUA,
				BlockedSQL:             stat.BlockedSQL,
				BlockedZeroDay:         stat.BlockedZeroDay,
				BlockedVuln:            stat.BlockedVuln,
				BlockedSensitiveParams: stat.BlockedSensitiveParams,
			})
		}
	}

	return WAFStatsResponse{
		TotalRequests:          w.stats.TotalRequests,
		BlockedCC:              w.stats.BlockedCC,
		BlockedUA:              w.stats.BlockedUA,
		BlockedSQL:             w.stats.BlockedSQL,
		BlockedZeroDay:         w.stats.BlockedZeroDay,
		BlockedVulnerability:   w.stats.BlockedVulnerability,
		BlockedSensitiveParams: w.stats.BlockedSensitiveParams,
		BlockedTotal:           w.stats.BlockedTotal,
		TopIPs:                 topIPs,
		TopUAs:                 topUAs,
		TopCountries:           topCountries,
		HourlyStats:            hourlyStats,
	}
}

func Forbidden(c *gin.Context, message string) {
	c.Header("Content-Type", "application/json; charset=utf-8")
	c.Status(403)
	c.JSON(403, gin.H{
		"code":    403,
		"message": message,
	})
}

func ForbiddenWithHelp(c *gin.Context, message string, help string) {
	c.Header("Content-Type", "application/json; charset=utf-8")
	c.Status(403)
	c.JSON(403, gin.H{
		"code":    403,
		"message": message,
		"help":    help,
	})
}
