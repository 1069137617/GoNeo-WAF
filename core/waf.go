package core

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/waf-go/waf/ip2region"
	"github.com/waf-go/waf/rules"

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

type ruleHit struct {
	Time   time.Time
	Result rules.MatchResult
	IP     string
	Path   string
}

type WAF struct {
	config      Config
	ipCounter   map[string]*ipRecord
	mu          sync.RWMutex
	ruleMatcher *rules.RuleMatcher

	ruleHits []ruleHit
	ruleMu   sync.RWMutex

	allowedNetworks []*net.IPNet
	ipSearcher      *ip2region.Searcher

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
	RuleHits               []RuleHitLog     `json:"ruleHits,omitempty"`
}

type RuleHitLog struct {
	Time     string `json:"time"`
	RuleID   string `json:"ruleId"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Score    int    `json:"score"`
	IP       string `json:"ip"`
	Path     string `json:"path"`
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

	ruleMatcher, err := rules.LoadDefault()
	if err != nil {
		zap.L().Warn("[WAF] 规则文件加载失败，使用内置规则", zap.Error(err))
	}
	waf.ruleMatcher = ruleMatcher

	waf.parseAllowedNetworks()
	waf.initIPSearcher()

	go waf.cleanupLoop()

	return waf
}

func (w *WAF) logRuleHit(ip, path string, result rules.MatchResult) {
	zap.L().Info("[WAF] 规则命中",
		zap.String("ruleId", result.RuleID),
		zap.String("name", result.Name),
		zap.String("category", result.Category),
		zap.Int("score", result.Score),
		zap.String("ip", ip),
		zap.String("path", path),
	)

	w.ruleMu.Lock()
	w.ruleHits = append(w.ruleHits, ruleHit{
		Time:   time.Now(),
		Result: result,
		IP:     ip,
		Path:   path,
	})
	if len(w.ruleHits) > 1000 {
		w.ruleHits = w.ruleHits[len(w.ruleHits)-500:]
	}
	w.ruleMu.Unlock()
}

func (w *WAF) GetRecentRuleHits(limit int) []RuleHitLog {
	w.ruleMu.RLock()
	defer w.ruleMu.RUnlock()

	n := len(w.ruleHits)
	if n == 0 {
		return nil
	}
	if limit > 0 && limit < n {
		n = limit
	}
	hits := w.ruleHits[len(w.ruleHits)-n:]
	result := make([]RuleHitLog, len(hits))
	for i, h := range hits {
		result[i] = RuleHitLog{
			Time:     h.Time.Format("2006-01-02 15:04:05"),
			RuleID:   h.Result.RuleID,
			Name:     h.Result.Name,
			Category: h.Result.Category,
			Score:    h.Result.Score,
			IP:       h.IP,
			Path:     h.Path,
		}
	}
	return result
}

func (w *WAF) isSQLInjection(c *gin.Context, bodyBytes []byte) bool {
	if w.ruleMatcher == nil {
		return false
	}
	rawQuery := c.Request.URL.RawQuery
	decodedQuery := w.decodeQuery(rawQuery)
	checkString := rawQuery + " " + decodedQuery + " " + string(bodyBytes)

	for _, rule := range w.ruleMatcher.SQLPatterns {
		if rule.MatchRegex(checkString) {
			w.logRuleHit(c.ClientIP(), c.Request.URL.Path, rule.ToResult())
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
	if w.ruleMatcher == nil {
		return false
	}
	checkString := w.buildCheckString(c, bodyBytes)

	for _, rule := range w.ruleMatcher.ZeroDayRules {
		if rule.MatchKeyword(checkString) {
			w.logRuleHit(c.ClientIP(), c.Request.URL.Path, rule.ToResult())
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
	if w.ruleMatcher == nil {
		return false
	}

	for name, values := range c.Request.Header {
		headerValue := strings.Join(values, " ")
		for _, rule := range w.ruleMatcher.CRLFPatterns {
			if rule.MatchRegex(headerValue) {
				w.logRuleHit(c.ClientIP(), c.Request.URL.Path, rule.ToResult())
				return true
			}
		}
		_ = name
	}

	rawQuery := c.Request.URL.RawQuery
	for _, rule := range w.ruleMatcher.CRLFPatterns {
		if rule.MatchRegex(rawQuery) {
			w.logRuleHit(c.ClientIP(), c.Request.URL.Path, rule.ToResult())
			return true
		}
	}

	if len(bodyBytes) > 0 {
		bodyStr := string(bodyBytes)
		for _, rule := range w.ruleMatcher.CRLFPatterns {
			if rule.MatchRegex(bodyStr) {
				w.logRuleHit(c.ClientIP(), c.Request.URL.Path, rule.ToResult())
				return true
			}
		}
	}

	return false
}

func (w *WAF) isUnicodeBypass(c *gin.Context, bodyBytes []byte) bool {
	if w.ruleMatcher == nil {
		return false
	}
	checkString := c.Request.URL.RawQuery
	if len(checkString) > maxCheckLength {
		checkString = checkString[:maxCheckLength]
	}

	bodyStr := ""
	if len(bodyBytes) > maxCheckLength {
		bodyStr = string(bodyBytes[:maxCheckLength])
	} else {
		bodyStr = string(bodyBytes)
	}

	for _, rule := range w.ruleMatcher.UnicodeMarkers {
		if strings.Contains(checkString, rule.Keywords[0]) {
			return true
		}
		if strings.Contains(bodyStr, rule.Keywords[0]) {
			return true
		}
	}
	return false
}

func (w *WAF) hasGoVulnerability(c *gin.Context, bodyBytes []byte) bool {
	if w.ruleMatcher == nil {
		return false
	}
	checkString := w.buildCheckString(c, bodyBytes)

	for _, rule := range w.ruleMatcher.VulnRules {
		cat := rule.Category
		if cat == "path_traversal" && !w.config.PathTraversalEnabled {
			continue
		}
		if cat == "xss" && !w.config.XSSEnabled {
			continue
		}
		if cat == "ssrf" && !w.config.SSRFEnabled {
			continue
		}
		if (cat == "command_injection" || cat == "file_inclusion") && !(w.config.ZeroDayEnabled || w.config.StrictMode) {
			continue
		}
		if rule.Type == "keyword" {
			for _, kw := range rule.Keywords {
				if strings.Contains(checkString, kw) {
					w.logRuleHit(c.ClientIP(), c.Request.URL.Path, rule.ToResult())
					return true
				}
			}
		} else if rule.MatchKeyword(checkString) {
			w.logRuleHit(c.ClientIP(), c.Request.URL.Path, rule.ToResult())
			return true
		}
	}

	if w.config.SSRFEnabled && w.isSSRFAttempt(c, bodyBytes) {
		return true
	}

	return false
}

func (w *WAF) isSSRFAttempt(c *gin.Context, bodyBytes []byte) bool {
	if w.ruleMatcher == nil {
		return false
	}
	checkString := w.buildCheckString(c, bodyBytes)

	for _, rule := range w.ruleMatcher.SSRFPatterns {
		if rule.MatchRegex(checkString) {
			w.logRuleHit(c.ClientIP(), c.Request.URL.Path, rule.ToResult())
			return true
		}
	}
	return false
}

func (w *WAF) hasSensitiveParams(c *gin.Context) bool {
	if !w.config.SensitiveParamEnabled || w.ruleMatcher == nil {
		return false
	}

	query := c.Request.URL.Query()

	for _, rule := range w.ruleMatcher.SensitiveParams {
		if rule.Type == "param_regex" && rule.PatternRegex() != nil {
			for paramName := range query {
				if rule.PatternRegex().MatchString(paramName) {
					paramValues := query[paramName]
					for _, value := range paramValues {
						if value != "" {
							w.logRuleHit(c.ClientIP(), c.Request.URL.Path, rule.ToResult())
							return true
						}
					}
				}
			}
		} else if rule.Param != "" {
			if values, exists := query[rule.Param]; exists {
				for _, value := range values {
					for _, blockedValue := range rule.Values {
						if strings.EqualFold(value, blockedValue) {
							w.logRuleHit(c.ClientIP(), c.Request.URL.Path, rule.ToResult())
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
	if !w.config.SensitiveParamEnabled || w.ruleMatcher == nil {
		return false
	}

	path := c.Request.URL.Path

	for _, rule := range w.ruleMatcher.SensitivePaths {
		if rule.MatchRegex(path) {
			w.logRuleHit(c.ClientIP(), c.Request.URL.Path, rule.ToResult())
			return true
		}
	}
	return false
}

func (w *WAF) isAllowedUA(ua string) bool {
	if w.ruleMatcher == nil {
		return true
	}
	if ua == "" {
		return false
	}

	for _, rule := range w.ruleMatcher.UAPatterns {
		if rule.Type == "regex" && rule.MatchRegex(ua) {
			return false
		}
	}
	return true
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
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		w.mu.Lock()
		for ip, record := range w.ipCounter {
			if now.Sub(record.firstSeen) > 10*time.Minute && now.After(record.blockedUntil) {
				delete(w.ipCounter, ip)
			}
		}
		w.mu.Unlock()

		w.attackMu.Lock()
		for ip, record := range w.attackCounter {
			if now.Sub(record.firstSeen) > 10*time.Minute && now.After(record.blockedUntil) {
				delete(w.attackCounter, ip)
			}
		}
		w.attackMu.Unlock()
	}
}

func (w *WAF) isCCAttack(ip string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	record, exists := w.ipCounter[ip]

	if !exists {
		w.ipCounter[ip] = &ipRecord{
			count:     1,
			firstSeen: now,
		}
		return false
	}

	if now.Sub(record.firstSeen) > time.Minute {
		record.count = 1
		record.firstSeen = now
		return false
	}

	record.count++
	return record.count > w.config.CCRequestLimit
}

func (w *WAF) recordBlockedIP(ip, blockType string) {
	stats := w.stats
	stats.mu.Lock()
	defer stats.mu.Unlock()

	entry, exists := stats.TopBlockedIPs[ip]
	if !exists {
		entry = &IPStats{}
		stats.TopBlockedIPs[ip] = entry

		if w.ipSearcher != nil {
			if info, err := w.ipSearcher.Search(ip); err == nil {
				entry.Country = ip2region.GetCountryGroup(info.IsoCode)
				entry.City = info.City
			}
		}
	}
	entry.Count++

	switch blockType {
	case "cc":
		entry.BlockCC++
	case "ua":
		entry.BlockUA++
	case "sql":
		entry.BlockSQL++
	case "zeroday":
		entry.BlockZeroDay++
	case "vuln", "ssrf", "crlf", "xss", "path_traversal":
		entry.BlockVuln++
	}
}

func (w *WAF) recordUA(ua string) {
	w.stats.mu.Lock()
	defer w.stats.mu.Unlock()

	w.stats.TopBlockedUAs[ua]++
}

func (w *WAF) recordCountry(country string) {
	w.stats.mu.Lock()
	defer w.stats.mu.Unlock()

	w.stats.TopBlockedCountries[country]++
}

func (w *WAF) recordHourlyStat(blockType string) {
	now := time.Now()
	hour := now.Hour()

	w.stats.mu.Lock()
	defer w.stats.mu.Unlock()

	stat := w.stats.HourlyStats[hour]
	if stat.Timestamp.Hour() != now.Hour() {
		*stat = HourlyStat{Timestamp: now}
	}

	stat.TotalRequests++

	switch blockType {
	case "cc":
		stat.BlockedCC++
	case "ua":
		stat.BlockedUA++
	case "sql":
		stat.BlockedSQL++
	case "zeroday":
		stat.BlockedZeroDay++
	case "vuln":
		stat.BlockedVuln++
	case "sensitive_param":
		stat.BlockedSensitiveParams++
	}
}

func (w *WAF) recordAttackAndCheckBlock(ip string) bool {
	w.attackMu.Lock()
	defer w.attackMu.Unlock()

	now := time.Now()
	record, exists := w.attackCounter[ip]

	if !exists {
		w.attackCounter[ip] = &attackRecord{
			count:     1,
			firstSeen: now,
		}
		return false
	}

	if now.After(record.blockedUntil) && now.Sub(record.firstSeen) > w.config.AttackWindowDuration {
		record.count = 1
		record.firstSeen = now
		return false
	}

	record.count++
	if record.count >= w.config.AttackBlockThreshold {
		record.blockedUntil = now.Add(w.config.AttackBlockDuration)
		return true
	}

	return false
}

func (w *WAF) isLocalIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	if parsed.IsLoopback() {
		return true
	}

	for _, network := range w.allowedNetworks {
		if network.Contains(parsed) {
			return true
		}
	}

	return false
}

func maskUA(ua string) string {
	if len(ua) == 0 {
		return ""
	}
	if len(ua) <= 10 {
		return ua[:1] + "***" + ua[len(ua)-1:]
	}
	return ua[:5] + "***" + ua[len(ua)-5:]
}

func maskSensitive(s string) string {
	if len(s) > 100 {
		return s[:50] + "..." + s[len(s)-50:]
	}
	return s
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

		if w.config.UAEnabled && !lowIntensity {
			if !w.isAllowedUA(c.Request.UserAgent()) {
				w.stats.BlockedUA++
				w.stats.BlockedTotal++
				w.recordBlockedIP(clientIP, "ua")
				w.recordUA(c.Request.UserAgent())
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
			w.recordHourlyStat("sensitive_param")

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
			ForbiddenWithHelp(c, "请求路径包含敏感端点", "如误拦截请联系管理员")
			c.Abort()
			return
		}

		c.Next()
	}
}

func (w *WAF) readAndRestoreBody(c *gin.Context) ([]byte, error) {
	if c.Request.Body == nil {
		return nil, nil
	}

	limitedReader := io.LimitReader(c.Request.Body, w.config.MaxRequestSize+1)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}

	if int64(len(bodyBytes)) > w.config.MaxRequestSize {
		return nil, fmt.Errorf("请求体超过最大限制 %d bytes", w.config.MaxRequestSize)
	}

	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	return bodyBytes, nil
}

func (w *WAF) GetStats() *WAFStatsResponse {
	w.stats.mu.RLock()
	defer w.stats.mu.RUnlock()

	resp := &WAFStatsResponse{
		TotalRequests:          w.stats.TotalRequests,
		BlockedCC:              w.stats.BlockedCC,
		BlockedUA:              w.stats.BlockedUA,
		BlockedSQL:             w.stats.BlockedSQL,
		BlockedZeroDay:         w.stats.BlockedZeroDay,
		BlockedVulnerability:   w.stats.BlockedVulnerability,
		BlockedSensitiveParams: w.stats.BlockedSensitiveParams,
		BlockedTotal:           w.stats.BlockedTotal,
	}

	type ipEntry struct {
		ip    string
		stats *IPStats
	}
	var ipList []ipEntry
	for k, v := range w.stats.TopBlockedIPs {
		ipList = append(ipList, ipEntry{k, v})
	}
	sort.Slice(ipList, func(i, j int) bool {
		return ipList[i].stats.Count > ipList[j].stats.Count
	})
	for i := 0; i < len(ipList) && i < 20; i++ {
		e := ipList[i]
		resp.TopIPs = append(resp.TopIPs, TopIPInfo{
			IP:      e.ip,
			Count:   e.stats.Count,
			Country: e.stats.Country,
			BlockCC: e.stats.BlockCC,
			BlockUA: e.stats.BlockUA,
		})
	}

	for ua, count := range w.stats.TopBlockedUAs {
		resp.TopUAs = append(resp.TopUAs, UAStat{UA: ua, Count: count})
	}
	sort.Slice(resp.TopUAs, func(i, j int) bool {
		return resp.TopUAs[i].Count > resp.TopUAs[j].Count
	})
	if len(resp.TopUAs) > 10 {
		resp.TopUAs = resp.TopUAs[:10]
	}

	for country, count := range w.stats.TopBlockedCountries {
		resp.TopCountries = append(resp.TopCountries, CountryStat{Country: country, Count: count})
	}
	sort.Slice(resp.TopCountries, func(i, j int) bool {
		return resp.TopCountries[i].Count > resp.TopCountries[j].Count
	})
	if len(resp.TopCountries) > 10 {
		resp.TopCountries = resp.TopCountries[:10]
	}

	for hour, stat := range w.stats.HourlyStats {
		if stat.TotalRequests > 0 {
			resp.HourlyStats = append(resp.HourlyStats, HourlyStatInfo{
				Hour:                   hour,
				Timestamp:              stat.Timestamp,
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

	resp.RuleHits = w.GetRecentRuleHits(50)

	return resp
}

func InitDefault(cfg Config) {
	defaultWAF = New(cfg)
}

func GetDefault() *WAF {
	return defaultWAF
}

func Forbidden(c *gin.Context, message string) {
	c.JSON(403, gin.H{
		"code":    403,
		"message": message,
	})
	c.Abort()
}

func ForbiddenWithHelp(c *gin.Context, message, help string) {
	c.JSON(403, gin.H{
		"code":    403,
		"message": message,
		"help":    help,
	})
	c.Abort()
}

func FormatAllowedUAs(ua string) []string {
	if ua == "" {
		return []string{
			`(?i)mozilla/.*`,
			`(?i)chrome/.*`,
			`(?i)safari/.*`,
			`(?i)firefox/.*`,
			`(?i)edge/.*`,
			`(?i)opera/.*`,
		}
	}
	return []string{ua}
}
