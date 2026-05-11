package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type RuleType string

const (
	TypeRegex       RuleType = "regex"
	TypeKeyword     RuleType = "keyword"
	TypeKeywordRegex RuleType = "keyword_regex"
	TypeParamValue  RuleType = "param_value"
	TypeParamRegex  RuleType = "param_regex"
)

type Rule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Type     RuleType `json:"type"`
	Pattern  string   `json:"pattern,omitempty"`
	Keywords []string `json:"keywords,omitempty"`
	Param    string   `json:"param,omitempty"`
	Values   []string `json:"values,omitempty"`
	Score    int      `json:"score"`
	Enabled  bool     `json:"enabled"`

	compiled *regexp.Regexp
}

type RuleFile struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

type RuleMatcher struct {
	SQLPatterns       []MatchedRule
	ZeroDayRules      []MatchedRule
	VulnRules         []MatchedRule
	SSRFPatterns      []MatchedRule
	CRLFPatterns      []MatchedRule
	SensitiveParams   []MatchedRule
	SensitivePaths    []MatchedRule
	UAPatterns        []MatchedRule
	UnicodeMarkers    []MatchedRule
}

type MatchedRule struct {
	Rule
	compiledRegex *regexp.Regexp
}

type MatchResult struct {
	RuleID   string `json:"ruleId"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Score    int    `json:"score"`
}

func (r *Rule) CompilePattern() error {
	if r.Pattern != "" {
		compiled, err := regexp.Compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("编译规则 %s 正则失败: %w", r.ID, err)
		}
		r.compiled = compiled
	}
	return nil
}

func (r *Rule) PatternRegex() *regexp.Regexp {
	return r.compiled
}

func LoadFromFile(path string) (*RuleMatcher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取规则文件失败: %w", err)
	}

	var ruleFile RuleFile
	if err := json.Unmarshal(data, &ruleFile); err != nil {
		return nil, fmt.Errorf("解析规则文件失败: %w", err)
	}

	matcher := &RuleMatcher{}

	for _, rule := range ruleFile.Rules {
		if !rule.Enabled {
			continue
		}

		if err := rule.CompilePattern(); err != nil {
			continue
		}

		mr := MatchedRule{Rule: rule, compiledRegex: rule.compiled}

		switch rule.Category {
		case "sql_injection":
			matcher.SQLPatterns = append(matcher.SQLPatterns, mr)
		case "zeroday":
			matcher.ZeroDayRules = append(matcher.ZeroDayRules, mr)
		case "path_traversal", "xss", "ssrf", "command_injection", "file_inclusion":
			matcher.VulnRules = append(matcher.VulnRules, mr)
		case "ssrf_url":
			matcher.SSRFPatterns = append(matcher.SSRFPatterns, mr)
		case "crlf":
			matcher.CRLFPatterns = append(matcher.CRLFPatterns, mr)
		case "sensitive_param":
			matcher.SensitiveParams = append(matcher.SensitiveParams, mr)
		case "sensitive_path":
			matcher.SensitivePaths = append(matcher.SensitivePaths, mr)
		case "ua":
			matcher.UAPatterns = append(matcher.UAPatterns, mr)
		case "unicode_bypass":
			matcher.UnicodeMarkers = append(matcher.UnicodeMarkers, mr)
		}
	}

	return matcher, nil
}

func LoadDefault() (*RuleMatcher, error) {
	path := filepath.Join("rules", "rules.json")
	return LoadFromFile(path)
}

func (mr *MatchedRule) MatchRegex(checkString string) bool {
	if mr.compiledRegex == nil {
		return false
	}
	return mr.compiledRegex.MatchString(checkString)
}

func (mr *MatchedRule) MatchKeyword(checkString string) bool {
	for _, kw := range mr.Keywords {
		if strings.Contains(checkString, kw) {
			if mr.compiledRegex == nil {
				return true
			}
			return mr.compiledRegex.MatchString(checkString)
		}
	}
	return false
}

func (mr *MatchedRule) MatchParamValue(paramName, paramValue string) bool {
	if mr.Param != "" && !strings.EqualFold(paramName, mr.Param) {
		return false
	}
	if mr.Type == TypeParamRegex && mr.compiledRegex != nil {
		return mr.compiledRegex.MatchString(paramName)
	}
	for _, v := range mr.Values {
		if strings.EqualFold(paramValue, v) {
			return true
		}
	}
	return false
}

func (mr *MatchedRule) ToResult() MatchResult {
	return MatchResult{
		RuleID:   mr.ID,
		Name:     mr.Name,
		Category: mr.Category,
		Score:    mr.Score,
	}
}
