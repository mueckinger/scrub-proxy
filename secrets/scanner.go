package secrets

import (
	"fmt"

	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// Scanner detects secrets in a text and returns findings with byte offsets.
// It is satisfied by *GitleaksScanner and can be mocked in tests.
type Scanner interface {
	Scan(text string) []Finding
}

// GitleaksScanner wraps a gitleaks Detector to scan text for secrets.
type GitleaksScanner struct {
	detector *detect.Detector
}

// NewGitleaksScanner builds a scanner from a gitleaks config file. If configPath
// is empty, the gitleaks default config is used. It returns an error if the
// config cannot be loaded.
func NewGitleaksScanner(configPath string) (*GitleaksScanner, error) {
	var (
		detector *detect.Detector
		err      error
	)

	if configPath == "" {
		detector, err = detect.NewDetectorDefaultConfig()
		if err != nil {
			return nil, fmt.Errorf("load gitleaks default config: %w", err)
		}
	} else {
		cfg, err := loadConfigFile(configPath)
		if err != nil {
			return nil, err
		}
		detector = detect.NewDetector(cfg)
	}

	return &GitleaksScanner{detector: detector}, nil
}

// Scan runs gitleaks over the text and converts each finding's line/column
// positions into byte offsets.
func (s *GitleaksScanner) Scan(text string) []Finding {
	raw := s.detector.DetectString(text)
	var out []Finding
	for _, f := range raw {
		start, end := ConvertLineColumnToOffsets(text, f.StartLine, f.StartColumn, f.EndLine, f.EndColumn)
		if start >= end {
			continue
		}
		out = append(out, Finding{
			RuleID:  f.RuleID,
			Start:   start,
			End:     end,
			Secret:  f.Secret,
			Entropy: f.Entropy,
		})
	}
	return out
}

// loadConfigFile loads a gitleaks config from a TOML file path using a local
// viper instance, mirroring how the gitleaks CLI loads a --config file. A
// dedicated instance avoids mutating global viper state.
func loadConfigFile(path string) (config.Config, error) {
	v := viper.New()
	v.SetConfigType("toml")
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return config.Config{}, fmt.Errorf("read gitleaks config %q: %w", path, err)
	}
	var vc config.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		return config.Config{}, fmt.Errorf("parse gitleaks config %q: %w", path, err)
	}
	cfg, err := vc.Translate()
	if err != nil {
		return config.Config{}, fmt.Errorf("translate gitleaks config %q: %w", path, err)
	}
	cfg.Path = path
	return cfg, nil
}
