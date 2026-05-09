package core

import "time"

type ConfigBuilder struct {
	config Config
}

func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{
		config: Config{
			Enabled:                true,
			CCEnabled:              true,
			CCRequestLimit:         60,
			CCBlockDuration:        10 * time.Minute,
			AttackBlockThreshold:   5,
			AttackBlockDuration:    1 * time.Hour,
			AttackWindowDuration:   10 * time.Minute,
			SQLInjectionEnabled:    true,
			UAEnabled:              true,
			XSSEnabled:             true,
			SSRFEnabled:            true,
			CRLFEnabled:            true,
			ZeroDayEnabled:         true,
			PathTraversalEnabled:   true,
			SensitiveParamEnabled:  true,
			StrictMode:             false,
			AllowedUAs:             FormatAllowedUAs(""),
			AllowLocalNetwork:      true,
			MaxRequestSize:         2 * 1024 * 1024,
			IP2RegionDBPath:        "",
		},
	}
}

func (b *ConfigBuilder) Enabled(enabled bool) *ConfigBuilder {
	b.config.Enabled = enabled
	return b
}

func (b *ConfigBuilder) WithCCProtection(enabled bool, requestLimit int, blockDuration time.Duration) *ConfigBuilder {
	b.config.CCEnabled = enabled
	b.config.CCRequestLimit = requestLimit
	b.config.CCBlockDuration = blockDuration
	return b
}

func (b *ConfigBuilder) WithAttackProtection(threshold int, blockDuration, windowDuration time.Duration) *ConfigBuilder {
	b.config.AttackBlockThreshold = threshold
	b.config.AttackBlockDuration = blockDuration
	b.config.AttackWindowDuration = windowDuration
	return b
}

func (b *ConfigBuilder) WithSQLInjection(enabled bool) *ConfigBuilder {
	b.config.SQLInjectionEnabled = enabled
	return b
}

func (b *ConfigBuilder) WithUAFilter(enabled bool, allowedUAs []string) *ConfigBuilder {
	b.config.UAEnabled = enabled
	if len(allowedUAs) > 0 {
		b.config.AllowedUAs = allowedUAs
	}
	return b
}

func (b *ConfigBuilder) WithXSSProtection(enabled bool) *ConfigBuilder {
	b.config.XSSEnabled = enabled
	return b
}

func (b *ConfigBuilder) WithSSRFProtection(enabled bool) *ConfigBuilder {
	b.config.SSRFEnabled = enabled
	return b
}

func (b *ConfigBuilder) WithCRLFProtection(enabled bool) *ConfigBuilder {
	b.config.CRLFEnabled = enabled
	return b
}

func (b *ConfigBuilder) WithZeroDayProtection(enabled bool) *ConfigBuilder {
	b.config.ZeroDayEnabled = enabled
	return b
}

func (b *ConfigBuilder) WithPathTraversalProtection(enabled bool) *ConfigBuilder {
	b.config.PathTraversalEnabled = enabled
	return b
}

func (b *ConfigBuilder) WithSensitiveParamProtection(enabled bool) *ConfigBuilder {
	b.config.SensitiveParamEnabled = enabled
	return b
}

func (b *ConfigBuilder) WithStrictMode(enabled bool) *ConfigBuilder {
	b.config.StrictMode = enabled
	return b
}

func (b *ConfigBuilder) WithAllowedNetworks(networks []string) *ConfigBuilder {
	b.config.AllowedNetworks = networks
	return b
}

func (b *ConfigBuilder) WithMaxRequestSize(size int64) *ConfigBuilder {
	b.config.MaxRequestSize = size
	return b
}

func (b *ConfigBuilder) WithIP2RegionDBPath(path string) *ConfigBuilder {
	b.config.IP2RegionDBPath = path
	return b
}

func (b *ConfigBuilder) WithNodeReportPaths(paths []string) *ConfigBuilder {
	b.config.NodeReportPaths = paths
	return b
}

func (b *ConfigBuilder) Build() Config {
	return b.config
}
