package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"html"
	"html/template"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

//go:embed admin.html
var uiHTML string

var (
	uiTmpl = template.Must(template.New("ui").Parse(uiHTML))

	configFile = "proxy_config.json"
	cacheDir   = "certs"

	mu   sync.Mutex
	mcfg = ConfigFile{
		Hosts:   map[string]HostConfig{},
		Certs:   map[string]CertConfig{},
		Users:   map[string]UserConfig{},
		Plugins: map[string]PluginConfig{},
		Settings: GlobalSettings{
			HTTP3Enabled:   false,
			HTTP3Advertise: false,
			HTTP3MaxAge:    86400,
			HTTPPorts:      []int{80},
			HTTPSPorts:     []int{443},
			UpdateChannel:  "stable",
		},
	}

	snapV atomic.Value // *ConfigSnapshot

	rrIdx              uint32
	csrfK                     = newCSRFKey()
	logLevel           uint32 = logLevelInfo
	logs                      = newLogBuffer(500)
	logger                    = log.New(newLogWriter(os.Stdout, logs, &logLevel), "", 0)
	defaultRenewBefore        = 7 * 24 * time.Hour

	certManager = &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Cache:       autocert.DirCache(cacheDir),
		RenewBefore: defaultRenewBefore,
	}

	sharedTransport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	healthMu       sync.RWMutex
	healthByHost   = map[string]map[string]BackendHealth{}
	healthInterval = 10 * time.Second
	healthTimeout  = 3 * time.Second
	healthPath     = "/health"

	wafProfiles = map[string][]wafRule{
		"baseline": {
			{
				Name:  "sql-injection",
				Regex: regexp.MustCompile(`(?i)(union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|or\s+1=1|--\s|;--|/\*.*\*/)`),
			},
			{
				Name:  "xss",
				Regex: regexp.MustCompile(`(?i)(<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img|<\s*svg)`),
			},
			{
				Name:  "path-traversal",
				Regex: regexp.MustCompile(`(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c)`),
			},
		},
		"balanced": {
			{
				Name:  "sql-injection",
				Regex: regexp.MustCompile(`(?i)(union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|or\s+1=1|--\s|;--|/\*.*\*/)`),
			},
			{
				Name:  "xss",
				Regex: regexp.MustCompile(`(?i)(<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img|<\s*svg)`),
			},
			{
				Name:  "path-traversal",
				Regex: regexp.MustCompile(`(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c)`),
			},
			{
				Name:  "command-injection",
				Regex: regexp.MustCompile(`(?i)(\|\||&&|;|` + "`" + `|\$\(|\$\{)`),
			},
		},
		"strict": {
			{
				Name:  "sql-injection",
				Regex: regexp.MustCompile(`(?i)(union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|or\s+1=1|--\s|;--|/\*.*\*/|benchmark\s*\(|sleep\s*\()`),
			},
			{
				Name:  "xss",
				Regex: regexp.MustCompile(`(?i)(<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img|<\s*svg|data:text/html|document\.cookie)`),
			},
			{
				Name:  "path-traversal",
				Regex: regexp.MustCompile(`(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|%2fetc%2fpasswd|/etc/passwd)`),
			},
			{
				Name:  "command-injection",
				Regex: regexp.MustCompile(`(?i)(\|\||&&|;|` + "`" + `|\$\(|\$\{)`),
			},
		},
		"custom": {
			{
				Name:  "sql-injection",
				Regex: regexp.MustCompile(`(?i)(union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|or\s+1=1|--\s|;--|/\*.*\*/|benchmark\s*\(|sleep\s*\()`),
			},
			{
				Name:  "xss",
				Regex: regexp.MustCompile(`(?i)(<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img|<\s*svg|data:text/html|document\.cookie)`),
			},
			{
				Name:  "path-traversal",
				Regex: regexp.MustCompile(`(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|%2fetc%2fpasswd|/etc/passwd)`),
			},
			{
				Name:  "command-injection",
				Regex: regexp.MustCompile(`(?i)(\|\||&&|;|` + "`" + `|\$\(|\$\{)`),
			},
		},
	}

	requestLimiter = newRateLimiter()

	audits = newAuditBuffer(500)

	streamManager = newStreamProxyManager()

	rngMu sync.Mutex
	rng   = rand.New(rand.NewSource(time.Now().UnixNano()))

	trafficMu    sync.Mutex
	trafficByDay = map[string]*trafficPoint{}
)

type trafficPoint struct {
	Day   string `json:"day"`
	Count int64  `json:"count"`
	Bytes int64  `json:"bytes"`
}

const (
	adminCredsFile = ".admin_credentials"
	workingDir     = "/opt/puffproxy"
)

var (
	securityTemplates = map[string]ExploitBlockConfig{
		"minimal": {
			FrameOptions:       true,
			XSSProtection:      true,
			ContentTypeOptions: true,
		},
		"balanced": {
			FrameOptions:       true,
			XSSProtection:      true,
			ContentTypeOptions: true,
			ReferrerPolicy:     true,
		},
		"strict": {
			FrameOptions:          true,
			XSSProtection:         true,
			ContentTypeOptions:    true,
			ContentSecurityPolicy: true,
			StrictTransport:       true,
			ReferrerPolicy:        true,
		},
	}

	availablePlugins = map[string]PluginConfig{
		"geo-routing": {
			Name:        "geo-routing",
			Enabled:     true,
			Version:     "1.0.0",
			Description: "Route traffic based on country headers such as CF-IPCountry or X-Geo-Country.",
		},
		"traffic-mirror": {
			Name:        "traffic-mirror",
			Enabled:     true,
			Version:     "1.0.0",
			Description: "Mirror requests asynchronously for testing and debugging.",
		},
		"stream-proxy": {
			Name:        "stream-proxy",
			Enabled:     true,
			Version:     "1.0.0",
			Description: "TCP/UDP stream proxying for non-HTTP workloads.",
		},
		"auth-bridge": {
			Name:        "auth-bridge",
			Enabled:     false,
			Version:     "0.9.0",
			Description: "Extensible authentication bridge for custom middleware.",
		},
	}

	loadBalancingStrategies = map[string]string{
		"none":          "None (single backend)",
		"round_robin":   "Round robin",
		"least_latency": "Least latency",
		"random":        "Random",
		"ip_hash":       "IP hash",
	}

	hostTemplates = []HostTemplate{
		{
			ID:          "jellyfin",
			Name:        "Jellyfin Media",
			Description: "Optimized for streaming with WebSockets and strict security headers.",
			Defaults: HostTemplateDefaults{
				WebSocket:            true,
				WAFEnabled:           true,
				WAFProfile:           "baseline",
				SecurityTemplate:     "strict",
				SecurityIntegrations: SecurityIntegrations{Fail2Ban: true},
				RateLimitPerMinute:   240,
				OriginShield:         true,
			},
		},
		{
			ID:          "nextcloud",
			Name:        "Nextcloud",
			Description: "Balanced headers with WebDAV-friendly settings.",
			Defaults: HostTemplateDefaults{
				WebSocket:            true,
				WAFEnabled:           true,
				WAFProfile:           "baseline",
				SecurityTemplate:     "balanced",
				SecurityIntegrations: SecurityIntegrations{CrowdSec: true},
				RateLimitPerMinute:   180,
				OriginShield:         true,
			},
		},
		{
			ID:          "proxmox",
			Name:        "Proxmox",
			Description: "Low-latency admin UI with hardened headers.",
			Defaults: HostTemplateDefaults{
				WebSocket:            true,
				WAFEnabled:           true,
				WAFProfile:           "strict",
				SecurityTemplate:     "strict",
				SecurityIntegrations: SecurityIntegrations{Fail2Ban: true, CrowdSec: true},
				RateLimitPerMinute:   120,
				OriginShield:         true,
			},
		},
		{
			ID:          "grafana",
			Name:        "Grafana",
			Description: "Dashboard-first configuration with WebSockets and balanced security.",
			Defaults: HostTemplateDefaults{
				WebSocket:            true,
				WAFEnabled:           true,
				WAFProfile:           "baseline",
				SecurityTemplate:     "balanced",
				SecurityIntegrations: SecurityIntegrations{CrowdSec: true},
				RateLimitPerMinute:   300,
				OriginShield:         true,
			},
		},
		{
			ID:          "home-assistant",
			Name:        "Home Assistant",
			Description: "Reliable smart-home control with WebSockets and access safeguards.",
			Defaults: HostTemplateDefaults{
				WebSocket:            true,
				WAFEnabled:           true,
				WAFProfile:           "baseline",
				SecurityTemplate:     "balanced",
				SecurityIntegrations: SecurityIntegrations{Fail2Ban: true},
				RateLimitPerMinute:   150,
				OriginShield:         true,
			},
		},
		{
			ID:          "gitea",
			Name:        "Gitea",
			Description: "Code hosting with strict headers and conservative rate limits.",
			Defaults: HostTemplateDefaults{
				WebSocket:            false,
				WAFEnabled:           true,
				WAFProfile:           "strict",
				SecurityTemplate:     "strict",
				SecurityIntegrations: SecurityIntegrations{Fail2Ban: true},
				RateLimitPerMinute:   180,
				OriginShield:         true,
			},
		},
	}
	wafRuleNames = map[string]struct{}{
		"sql-injection":         {},
		"xss":                   {},
		"path-traversal":        {},
		"command-injection":     {},
		"protocol-anomalies":    {},
		"local-file-inclusion":  {},
		"remote-file-inclusion": {},
		"scanner-probes":        {},
		"bad-bots":              {},
		"request-smuggling":     {},
	}
)

type CertConfig struct {
	Type         string `json:"type"` // letsencrypt|custom
	AutoGenerate bool   `json:"auto_generate"`
	AutoRenew    bool   `json:"auto_renew"`
	RenewDays    int    `json:"renew_days"`
	Domain       string `json:"domain,omitempty"`
	CertPath     string `json:"cert_path"`
	KeyPath      string `json:"key_path"`
}

type HostConfig struct {
	Backends             []string             `json:"backends"`
	GeoRouting           map[string]string    `json:"geo_routing,omitempty"`
	MirrorBackends       []string             `json:"mirror_backends,omitempty"`
	CertName             string               `json:"cert_name,omitempty"`
	AutoCert             bool                 `json:"auto_cert,omitempty"`
	SSL                  bool                 `json:"ssl"`
	Webhook              string               `json:"webhook,omitempty"`
	WebSocket            bool                 `json:"websocket"`
	ExploitBlocks        ExploitBlockConfig   `json:"exploit_blocks"`
	LoadBalancing        string               `json:"load_balancing,omitempty"`
	HealthCheckPath      string               `json:"health_check_path,omitempty"`
	SecurityTemplate     string               `json:"security_template,omitempty"`
	SecurityIntegrations SecurityIntegrations `json:"security_integrations,omitempty"`
	RequireAuth          bool                 `json:"require_auth"`
	WAFEnabled           bool                 `json:"waf_enabled"`
	WAFProfile           string               `json:"waf_profile,omitempty"`
	WAFRules             map[string]bool      `json:"waf_rules,omitempty"`
	Allowlist            []string             `json:"allowlist,omitempty"`
	Denylist             []string             `json:"denylist,omitempty"`
	RateLimitPerMinute   int                  `json:"rate_limit_per_minute,omitempty"`
	OriginShield         bool                 `json:"origin_shield"`
}

type ExploitBlockConfig struct {
	FrameOptions          bool `json:"frame_options"`
	XSSProtection         bool `json:"xss_protection"`
	ContentTypeOptions    bool `json:"content_type_options"`
	ContentSecurityPolicy bool `json:"content_security_policy"`
	StrictTransport       bool `json:"strict_transport_security"`
	ReferrerPolicy        bool `json:"referrer_policy"`
}

type SecurityIntegrations struct {
	Fail2Ban bool `json:"fail2ban"`
	CrowdSec bool `json:"crowdsec"`
}

type ConfigFile struct {
	Hosts         map[string]HostConfig   `json:"hosts"`
	Certs         map[string]CertConfig   `json:"certs"`
	Users         map[string]UserConfig   `json:"users"`
	StreamProxies []StreamProxyConfig     `json:"stream_proxies,omitempty"`
	Plugins       map[string]PluginConfig `json:"plugins,omitempty"`
	Settings      GlobalSettings          `json:"settings"`
}

type UserConfig struct {
	Password string `json:"password"`
	Role     string `json:"role"`
}

type GlobalSettings struct {
	HTTP3Enabled   bool   `json:"http3_enabled"`
	HTTP3Advertise bool   `json:"http3_advertise"`
	HTTP3MaxAge    int    `json:"http3_max_age"`
	HTTPPorts      []int  `json:"http_ports,omitempty"`
	HTTPSPorts     []int  `json:"https_ports,omitempty"`
	UpdateChannel  string `json:"update_channel"`
}

type PluginConfig struct {
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

type StreamProxyConfig struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Listen   string `json:"listen"`
	Backend  string `json:"backend"`
	Enabled  bool   `json:"enabled"`
}

type HostTemplate struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Defaults    HostTemplateDefaults `json:"defaults"`
}

type HostTemplateDefaults struct {
	WebSocket            bool                 `json:"websocket"`
	RequireAuth          bool                 `json:"require_auth"`
	WAFEnabled           bool                 `json:"waf_enabled"`
	WAFProfile           string               `json:"waf_profile"`
	WAFRules             map[string]bool      `json:"waf_rules,omitempty"`
	SecurityTemplate     string               `json:"security_template"`
	SecurityIntegrations SecurityIntegrations `json:"security_integrations"`
	RateLimitPerMinute   int                  `json:"rate_limit_per_minute"`
	OriginShield         bool                 `json:"origin_shield"`
	MirrorBackends       []string             `json:"mirror_backends"`
	GeoRouting           map[string]string    `json:"geo_routing"`
}

func (e ExploitBlockConfig) isAll() bool {
	return e.FrameOptions &&
		e.XSSProtection &&
		e.ContentTypeOptions &&
		e.ContentSecurityPolicy &&
		e.StrictTransport &&
		e.ReferrerPolicy
}

func exploitBlockConfigAll(enabled bool) ExploitBlockConfig {
	return ExploitBlockConfig{
		FrameOptions:          enabled,
		XSSProtection:         enabled,
		ContentTypeOptions:    enabled,
		ContentSecurityPolicy: enabled,
		StrictTransport:       enabled,
		ReferrerPolicy:        enabled,
	}
}

func (h *HostConfig) UnmarshalJSON(data []byte) error {
	type rawHost struct {
		Backends             json.RawMessage      `json:"backends"`
		GeoRouting           map[string]string    `json:"geo_routing"`
		MirrorBackends       []string             `json:"mirror_backends"`
		CertName             string               `json:"cert_name"`
		AutoCert             bool                 `json:"auto_cert"`
		SSL                  bool                 `json:"ssl"`
		Webhook              string               `json:"webhook"`
		WebSocket            bool                 `json:"websocket"`
		BlockExploits        *bool                `json:"block_exploits"`
		ExploitBlocks        *ExploitBlockConfig  `json:"exploit_blocks"`
		LoadBalancing        string               `json:"load_balancing"`
		HealthCheckPath      string               `json:"health_check_path"`
		SecurityTemplate     string               `json:"security_template"`
		SecurityIntegrations SecurityIntegrations `json:"security_integrations"`
		RequireAuth          bool                 `json:"require_auth"`
		WAFEnabled           bool                 `json:"waf_enabled"`
		WAFProfile           string               `json:"waf_profile"`
		WAFRules             map[string]bool      `json:"waf_rules"`
		Allowlist            []string             `json:"allowlist"`
		Denylist             []string             `json:"denylist"`
		RateLimitPerMinute   int                  `json:"rate_limit_per_minute"`
		OriginShield         bool                 `json:"origin_shield"`
	}
	var raw rawHost
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	backends, err := parseBackends(raw.Backends)
	if err != nil {
		return err
	}
	blocks := ExploitBlockConfig{}
	switch {
	case raw.ExploitBlocks != nil:
		blocks = *raw.ExploitBlocks
	case raw.BlockExploits != nil:
		blocks = exploitBlockConfigAll(*raw.BlockExploits)
	}
	loadBalancing := normalizeLoadBalancing(raw.LoadBalancing)
	if loadBalancing == "" {
		loadBalancing = "round_robin"
	}
	*h = HostConfig{
		Backends:             backends,
		GeoRouting:           normalizeGeoRouting(raw.GeoRouting),
		MirrorBackends:       normalizeBackends(raw.MirrorBackends),
		CertName:             raw.CertName,
		AutoCert:             raw.AutoCert,
		SSL:                  raw.SSL,
		Webhook:              raw.Webhook,
		WebSocket:            raw.WebSocket,
		ExploitBlocks:        blocks,
		LoadBalancing:        loadBalancing,
		HealthCheckPath:      normalizeHealthCheckPath(raw.HealthCheckPath),
		SecurityTemplate:     normalizeSecurityTemplate(raw.SecurityTemplate),
		SecurityIntegrations: raw.SecurityIntegrations,
		RequireAuth:          raw.RequireAuth,
		WAFEnabled:           raw.WAFEnabled,
		WAFProfile:           normalizeWAFProfile(raw.WAFProfile),
		WAFRules:             normalizeWAFRules(raw.WAFRules),
		Allowlist:            normalizeIPList(raw.Allowlist),
		Denylist:             normalizeIPList(raw.Denylist),
		RateLimitPerMinute:   raw.RateLimitPerMinute,
		OriginShield:         raw.OriginShield,
	}
	return nil
}

type ConfigSnapshot struct {
	Hosts         map[string]HostConfig
	Certs         map[string]CertConfig
	CustomCerts   map[string]*tls.Certificate
	LEHosts       []string
	Users         map[string]UserConfig
	StreamProxies []StreamProxyConfig
	Plugins       map[string]PluginConfig
	Settings      GlobalSettings
}

type BackendHealth struct {
	Healthy    bool      `json:"healthy"`
	LastCheck  time.Time `json:"last_check"`
	LatencyMS  int64     `json:"latency_ms"`
	LastError  string    `json:"last_error,omitempty"`
	StatusCode int       `json:"status_code,omitempty"`
}

type wafRule struct {
	Name  string
	Regex *regexp.Regexp
}

type rateBucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: map[string]*rateBucket{}}
}

func (r *rateLimiter) Allow(key string, limit int) bool {
	if limit <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	bucket, ok := r.buckets[key]
	if !ok {
		r.buckets[key] = &rateBucket{tokens: float64(limit - 1), last: now}
		return true
	}
	elapsed := now.Sub(bucket.last).Seconds()
	refillRate := float64(limit) / 60.0
	bucket.tokens = math.Min(float64(limit), bucket.tokens+elapsed*refillRate)
	bucket.last = now
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens -= 1
	return true
}

type streamProxy struct {
	cfg        StreamProxyConfig
	listener   net.Listener
	packetConn net.PacketConn
	stop       chan struct{}
}

type streamProxyManager struct {
	mu      sync.Mutex
	proxies map[string]*streamProxy
}

func newStreamProxyManager() *streamProxyManager {
	return &streamProxyManager{proxies: map[string]*streamProxy{}}
}

func (m *streamProxyManager) sync(proxies []StreamProxyConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	desired := map[string]StreamProxyConfig{}
	for _, cfg := range proxies {
		if !cfg.Enabled {
			continue
		}
		key := streamProxyKey(cfg)
		desired[key] = cfg
	}
	for key, proxy := range m.proxies {
		if desiredCfg, ok := desired[key]; !ok || !streamProxyEqual(proxy.cfg, desiredCfg) {
			proxy.stopProxy()
			delete(m.proxies, key)
		}
	}
	for key, cfg := range desired {
		if _, ok := m.proxies[key]; ok {
			continue
		}
		proxy := &streamProxy{cfg: cfg, stop: make(chan struct{})}
		if err := proxy.start(); err != nil {
			logger.Printf(`{"level":"error","msg":"failed to start stream proxy","name":%q,"err":%q}`, cfg.Name, err.Error())
			continue
		}
		m.proxies[key] = proxy
	}
}

func (p *streamProxy) start() error {
	switch strings.ToLower(p.cfg.Protocol) {
	case "tcp":
		return p.startTCP()
	case "udp":
		return p.startUDP()
	default:
		return fmt.Errorf("unsupported protocol %q", p.cfg.Protocol)
	}
}

func (p *streamProxy) stopProxy() {
	close(p.stop)
	if p.listener != nil {
		_ = p.listener.Close()
	}
	if p.packetConn != nil {
		_ = p.packetConn.Close()
	}
}

func (p *streamProxy) startTCP() error {
	ln, err := net.Listen("tcp", p.cfg.Listen)
	if err != nil {
		return err
	}
	p.listener = ln
	logger.Printf(`{"level":"info","msg":"tcp stream proxy listening","listen":%q,"backend":%q}`, p.cfg.Listen, p.cfg.Backend)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-p.stop:
					return
				default:
					logger.Printf(`{"level":"warn","msg":"tcp proxy accept failed","listen":%q,"err":%q}`, p.cfg.Listen, err.Error())
					continue
				}
			}
			go p.handleTCP(conn)
		}
	}()
	return nil
}

func (p *streamProxy) handleTCP(client net.Conn) {
	defer client.Close()
	backend, err := net.Dial("tcp", p.cfg.Backend)
	if err != nil {
		logger.Printf(`{"level":"warn","msg":"tcp proxy backend dial failed","backend":%q,"err":%q}`, p.cfg.Backend, err.Error())
		return
	}
	defer backend.Close()
	go io.Copy(backend, client)
	_, _ = io.Copy(client, backend)
}

func (p *streamProxy) startUDP() error {
	pc, err := net.ListenPacket("udp", p.cfg.Listen)
	if err != nil {
		return err
	}
	p.packetConn = pc
	logger.Printf(`{"level":"info","msg":"udp stream proxy listening","listen":%q,"backend":%q}`, p.cfg.Listen, p.cfg.Backend)
	go p.handleUDP(pc)
	return nil
}

func (p *streamProxy) handleUDP(pc net.PacketConn) {
	backendAddr, err := net.ResolveUDPAddr("udp", p.cfg.Backend)
	if err != nil {
		logger.Printf(`{"level":"error","msg":"udp proxy backend resolve failed","backend":%q,"err":%q}`, p.cfg.Backend, err.Error())
		return
	}
	type udpClient struct {
		conn net.Conn
		addr net.Addr
	}
	clients := map[string]*udpClient{}
	buf := make([]byte, 65535)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-p.stop:
					return
				default:
					continue
				}
			}
			logger.Printf(`{"level":"warn","msg":"udp proxy read failed","listen":%q,"err":%q}`, p.cfg.Listen, err.Error())
			continue
		}
		key := addr.String()
		client := clients[key]
		if client == nil {
			conn, err := net.DialUDP("udp", nil, backendAddr)
			if err != nil {
				logger.Printf(`{"level":"warn","msg":"udp proxy backend dial failed","backend":%q,"err":%q}`, p.cfg.Backend, err.Error())
				continue
			}
			client = &udpClient{conn: conn, addr: addr}
			clients[key] = client
			go func(c *udpClient) {
				reply := make([]byte, 65535)
				for {
					nr, err := c.conn.Read(reply)
					if err != nil {
						return
					}
					_, _ = pc.WriteTo(reply[:nr], c.addr)
				}
			}(client)
		}
		_, _ = client.conn.Write(buf[:n])
	}
}

func streamProxyKey(cfg StreamProxyConfig) string {
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		name = strings.TrimSpace(cfg.Listen + ":" + cfg.Protocol)
	}
	return strings.ToLower(name)
}

func streamProxyEqual(a, b StreamProxyConfig) bool {
	return strings.EqualFold(a.Protocol, b.Protocol) &&
		a.Listen == b.Listen &&
		a.Backend == b.Backend &&
		a.Enabled == b.Enabled &&
		a.Name == b.Name
}

const (
	logLevelDebug uint32 = iota
	logLevelInfo
	logLevelWarn
	logLevelError
)

type logEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Raw     string `json:"raw"`
}

type logBuffer struct {
	mu      sync.Mutex
	entries []logEntry
	max     int
}

func newLogBuffer(max int) *logBuffer {
	return &logBuffer{max: max}
}

func (b *logBuffer) add(entry logEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, entry)
	if len(b.entries) > b.max {
		b.entries = append([]logEntry{}, b.entries[len(b.entries)-b.max:]...)
	}
}

func (b *logBuffer) list(minLevel uint32) []logEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]logEntry, 0, len(b.entries))
	for i := len(b.entries) - 1; i >= 0; i-- {
		e := b.entries[i]
		if levelFromString(e.Level) < minLevel {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (b *logBuffer) clearAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = nil
}

func (b *logBuffer) clearSince(cutoff time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	kept := b.entries[:0]
	for _, e := range b.entries {
		t, err := time.Parse(time.RFC3339, e.Time)
		if err != nil || t.Before(cutoff) {
			kept = append(kept, e)
		}
	}
	b.entries = kept
}

type auditEntry struct {
	Time   string `json:"time"`
	User   string `json:"user"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail,omitempty"`
}

type auditBuffer struct {
	mu      sync.Mutex
	entries []auditEntry
	max     int
}

func newAuditBuffer(max int) *auditBuffer {
	return &auditBuffer{max: max}
}

func (b *auditBuffer) add(entry auditEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, entry)
	if len(b.entries) > b.max {
		b.entries = append([]auditEntry{}, b.entries[len(b.entries)-b.max:]...)
	}
}

func (b *auditBuffer) list() []auditEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]auditEntry, len(b.entries))
	copy(out, b.entries)
	return out
}

func (b *auditBuffer) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = nil
}

type logWriter struct {
	out   io.Writer
	buf   *logBuffer
	level *uint32
}

func newLogWriter(out io.Writer, buf *logBuffer, level *uint32) *logWriter {
	return &logWriter{out: out, buf: buf, level: level}
}

func (w *logWriter) Write(p []byte) (int, error) {
	lines := strings.Split(string(p), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		entry := parseLogEntry(line)
		w.buf.add(entry)
		if levelFromString(entry.Level) < atomic.LoadUint32(w.level) {
			continue
		}
		if _, err := io.WriteString(w.out, line+"\n"); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

func parseLogEntry(line string) logEntry {
	entry := logEntry{
		Time:    time.Now().Format(time.RFC3339),
		Level:   "info",
		Message: line,
		Raw:     line,
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return entry
	}
	if lvl, ok := payload["level"].(string); ok && lvl != "" {
		entry.Level = strings.ToLower(lvl)
	}
	if msg, ok := payload["msg"].(string); ok && msg != "" {
		entry.Message = formatLogMessage(msg, payload)
	}
	return entry
}

func formatLogMessage(msg string, payload map[string]any) string {
	keys := make([]string, 0, len(payload))
	for k := range payload {
		if k == "level" || k == "msg" {
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return msg
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		val := payload[k]
		if s, ok := val.(string); ok {
			parts = append(parts, fmt.Sprintf("%s=%s", k, s))
			continue
		}
		encoded, err := json.Marshal(val)
		if err != nil {
			parts = append(parts, fmt.Sprintf("%s=%v", k, val))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, string(encoded)))
	}
	return fmt.Sprintf("%s %s", msg, strings.Join(parts, " "))
}

func parseBackends(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" {
			return nil, nil
		}
		return []string{single}, nil
	}
	var anyList []any
	if err := json.Unmarshal(raw, &anyList); err == nil {
		for _, item := range anyList {
			s, ok := item.(string)
			if !ok {
				continue
			}
			list = append(list, s)
		}
		return list, nil
	}
	return nil, errors.New("invalid backends format")
}

func validateBackendURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid backend url: %s", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("backend must be http/https: %s", raw)
	}
	return nil
}

func normalizeBackends(backends []string) []string {
	out := make([]string, 0, len(backends))
	for _, b := range backends {
		b = strings.TrimSpace(b)
		if b == "" {
			continue
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeLoadBalancing(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "round_robin"
	}
	if _, ok := loadBalancingStrategies[value]; ok {
		return value
	}
	return ""
}

func normalizeHealthCheckPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "/") {
		return ""
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return ""
	}
	return value
}

func normalizeGeoRouting(rules map[string]string) map[string]string {
	if len(rules) == 0 {
		return nil
	}
	out := map[string]string{}
	for key, backend := range rules {
		code := strings.ToUpper(strings.TrimSpace(key))
		backend = strings.TrimSpace(backend)
		if code == "" || backend == "" {
			continue
		}
		out[code] = backend
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeSecurityTemplate(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "balanced"
	}
	if _, ok := securityTemplates[name]; ok {
		return name
	}
	return "custom"
}

func normalizeWAFProfile(profile string) string {
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile == "" {
		return "baseline"
	}
	if _, ok := wafProfiles[profile]; ok {
		return profile
	}
	return "baseline"
}

func normalizeWAFRules(rules map[string]bool) map[string]bool {
	if len(rules) == 0 {
		return nil
	}
	out := make(map[string]bool, len(rules))
	for name, enabled := range rules {
		if _, ok := wafRuleNames[name]; ok {
			out[name] = enabled
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func wafRuleEnabled(rules map[string]bool, name string) bool {
	if len(rules) == 0 {
		return true
	}
	if enabled, ok := rules[name]; ok {
		return enabled
	}
	return true
}

func normalizeStreamProxies(items []StreamProxyConfig) []StreamProxyConfig {
	if len(items) == 0 {
		return nil
	}
	out := make([]StreamProxyConfig, 0, len(items))
	for _, proxy := range items {
		proxy.Name = strings.TrimSpace(proxy.Name)
		proxy.Protocol = strings.ToLower(strings.TrimSpace(proxy.Protocol))
		proxy.Listen = strings.TrimSpace(proxy.Listen)
		proxy.Backend = strings.TrimSpace(proxy.Backend)
		if proxy.Protocol == "" {
			proxy.Protocol = "tcp"
		}
		if proxy.Listen == "" || proxy.Backend == "" {
			continue
		}
		out = append(out, proxy)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeIPList(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, entry := range items {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		if !isValidIPEntry(trimmed) {
			continue
		}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isValidIPEntry(entry string) bool {
	if entry == "" {
		return false
	}
	if strings.Contains(entry, "/") {
		_, _, err := net.ParseCIDR(entry)
		return err == nil
	}
	return net.ParseIP(entry) != nil
}

func ipInList(ipStr string, list []string) (bool, string) {
	if ipStr == "" {
		return false, ""
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, ""
	}
	for _, entry := range list {
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, cidr, err := net.ParseCIDR(entry)
			if err != nil || cidr == nil {
				continue
			}
			if cidr.Contains(ip) {
				return true, entry
			}
			continue
		}
		if ip.Equal(net.ParseIP(entry)) {
			return true, entry
		}
	}
	return false, ""
}

func wafMatch(profile string, selectedRules map[string]bool, payload string) string {
	if payload == "" {
		return ""
	}
	profileRules, ok := wafProfiles[profile]
	if !ok {
		profileRules = wafProfiles["baseline"]
	}
	for _, rule := range profileRules {
		if !wafRuleEnabled(selectedRules, rule.Name) {
			continue
		}
		if rule.Regex.MatchString(payload) {
			return rule.Name
		}
	}
	return ""
}

func wafDetect(r *http.Request, profile string, rules map[string]bool, body []byte) (string, bool) {
	target := r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	if match := wafMatch(profile, rules, target); match != "" {
		return match, true
	}
	if len(body) == 0 && (r.Body == nil || r.ContentLength == 0) {
		return "", false
	}
	if len(body) == 0 {
		var err error
		body, err = readRequestBody(r, 1<<20)
		if err != nil {
			return "", false
		}
	}
	if match := wafMatch(profile, rules, string(body)); match != "" {
		return match, true
	}
	return "", false
}

func readRequestBody(r *http.Request, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, limit))
	if err != nil {
		return nil, err
	}
	if r.Body != nil {
		_ = r.Body.Close()
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

func levelFromString(level string) uint32 {
	switch strings.ToLower(level) {
	case "debug":
		return logLevelDebug
	case "warn", "warning":
		return logLevelWarn
	case "error":
		return logLevelError
	default:
		return logLevelInfo
	}
}

func levelToString(level uint32) string {
	switch level {
	case logLevelDebug:
		return "debug"
	case logLevelWarn:
		return "warn"
	case logLevelError:
		return "error"
	default:
		return "info"
	}
}

func setLogLevel(level string) error {
	switch strings.ToLower(level) {
	case "debug":
		atomic.StoreUint32(&logLevel, logLevelDebug)
	case "info":
		atomic.StoreUint32(&logLevel, logLevelInfo)
	case "warn", "warning":
		atomic.StoreUint32(&logLevel, logLevelWarn)
	case "error":
		atomic.StoreUint32(&logLevel, logLevelError)
	default:
		return fmt.Errorf("unknown log level: %s", level)
	}
	return nil
}

func normalizeHost(hostport string) string {
	h := strings.TrimSpace(hostport)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

func intSlicesEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func normalizePorts(ports []int, defaults []int) ([]int, bool) {
	changed := false
	normalized := make([]int, 0, len(ports))
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			changed = true
			continue
		}
		if _, ok := seen[port]; ok {
			changed = true
			continue
		}
		seen[port] = struct{}{}
		normalized = append(normalized, port)
	}
	if len(normalized) == 0 {
		normalized = append([]int(nil), defaults...)
		if !intSlicesEqual(ports, normalized) {
			changed = true
		}
	} else if !intSlicesEqual(ports, normalized) {
		changed = true
	}
	return normalized, changed
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

var hostnameRE = regexp.MustCompile(`^[a-z0-9.-]+$`)

func validateHostnameStrict(domain string) error {
	d := normalizeHost(domain)
	if d == "" {
		return errors.New("empty hostname")
	}
	if len(d) > 253 {
		return fmt.Errorf("hostname too long (%d)", len(d))
	}
	if net.ParseIP(d) != nil {
		return errors.New("IP addresses are not allowed as hostnames here")
	}
	if !hostnameRE.MatchString(d) {
		return errors.New("hostname contains invalid characters (allowed: a-z 0-9 . -)")
	}
	if strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return errors.New("hostname cannot start or end with dot")
	}
	if strings.Contains(d, "..") {
		return errors.New("hostname cannot contain consecutive dots")
	}
	labels := strings.Split(d, ".")
	for _, lab := range labels {
		if lab == "" {
			return errors.New("hostname has empty label")
		}
		if len(lab) > 63 {
			return fmt.Errorf("hostname label too long: %q", lab)
		}
		if strings.HasPrefix(lab, "-") || strings.HasSuffix(lab, "-") {
			return fmt.Errorf("hostname label cannot start or end with hyphen: %q", lab)
		}
	}
	return nil
}

func newReqID() string {
	var b [12]byte
	_, _ = crand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func newCSRFKey() []byte {
	var b [32]byte
	_, _ = crand.Read(b[:])
	return b[:]
}

func randomPassword(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("invalid password length")
	}
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}

func csrfTokenForIP(ip string) string {
	day := time.Now().UTC().Format("2006-01-02")
	raw := []byte(ip + "|" + day)
	out := make([]byte, 16)
	for i := 0; i < len(out); i++ {
		out[i] = csrfK[i] ^ raw[i%len(raw)]
	}
	return hex.EncodeToString(out)
}

func getClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func loadConfigFromDisk() (bool, error) {
	mu.Lock()
	defer mu.Unlock()
	b, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	cf, changed, err := decodeConfigBytes(b)
	if err != nil {
		return false, err
	}
	mcfg = cf
	if changed {
		if err := saveConfigToDiskLocked(); err != nil {
			return false, err
		}
	}
	return changed, nil
}

func ensureAdminUser() error {
	mu.Lock()
	defer mu.Unlock()

	for _, user := range mcfg.Users {
		if normalizeUserRole(user.Role) == "admin" {
			return nil
		}
	}

	password, err := randomPassword(16)
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	mcfg.Users["admin"] = UserConfig{Password: string(hash), Role: "admin"}
	if err := saveConfigToDiskLocked(); err != nil {
		return err
	}

	creds := fmt.Sprintf("user=admin\npassword=%s\n", password)
	if err := os.WriteFile(adminCredsFile, []byte(creds), 0600); err != nil {
		return err
	}
	logger.Printf(`{"level":"info","msg":"admin user created","user":"admin","creds_file":%q}`, adminCredsFile)
	return nil
}

func saveConfigToDiskLocked() error {
	tmp := configFile + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&mcfg); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, configFile)
}

func decodeConfigBytes(b []byte) (ConfigFile, bool, error) {
	var cf ConfigFile
	if err := json.Unmarshal(b, &cf); err == nil {
		ncf, changed := normalizeConfig(cf)
		return ncf, changed, nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return ConfigFile{}, false, err
	}
	cfg := ConfigFile{
		Hosts:   map[string]HostConfig{},
		Certs:   map[string]CertConfig{},
		Users:   map[string]UserConfig{},
		Plugins: map[string]PluginConfig{},
		Settings: GlobalSettings{
			HTTP3Enabled:   false,
			HTTP3Advertise: false,
			HTTP3MaxAge:    86400,
			HTTPPorts:      []int{80},
			HTTPSPorts:     []int{443},
			UpdateChannel:  "stable",
		},
	}
	changed := true

	if rawHosts, ok := raw["hosts"]; ok {
		var hostMap map[string]json.RawMessage
		if err := json.Unmarshal(rawHosts, &hostMap); err == nil {
			for domain, payload := range hostMap {
				var hc HostConfig
				if err := json.Unmarshal(payload, &hc); err != nil {
					logger.Printf(`{"level":"warn","msg":"invalid host config skipped","host":%q,"err":%q}`, domain, err.Error())
					continue
				}
				cfg.Hosts[domain] = hc
			}
		} else {
			var hostList []map[string]json.RawMessage
			if err := json.Unmarshal(rawHosts, &hostList); err == nil {
				for _, item := range hostList {
					var domain string
					if rawDomain, ok := item["domain"]; ok {
						_ = json.Unmarshal(rawDomain, &domain)
					}
					if domain == "" {
						continue
					}
					payload, err := json.Marshal(item)
					if err != nil {
						continue
					}
					var hc HostConfig
					if err := json.Unmarshal(payload, &hc); err != nil {
						logger.Printf(`{"level":"warn","msg":"invalid host config skipped","host":%q,"err":%q}`, domain, err.Error())
						continue
					}
					cfg.Hosts[domain] = hc
				}
			}
		}
	}

	if rawCerts, ok := raw["certs"]; ok {
		var certMap map[string]json.RawMessage
		if err := json.Unmarshal(rawCerts, &certMap); err == nil {
			for name, payload := range certMap {
				var cc CertConfig
				if err := json.Unmarshal(payload, &cc); err != nil {
					logger.Printf(`{"level":"warn","msg":"invalid cert config skipped","cert":%q,"err":%q}`, name, err.Error())
					continue
				}
				cfg.Certs[name] = cc
			}
		} else {
			var certList []map[string]json.RawMessage
			if err := json.Unmarshal(rawCerts, &certList); err == nil {
				for _, item := range certList {
					var name string
					if rawName, ok := item["name"]; ok {
						_ = json.Unmarshal(rawName, &name)
					}
					if name == "" {
						continue
					}
					payload, err := json.Marshal(item)
					if err != nil {
						continue
					}
					var cc CertConfig
					if err := json.Unmarshal(payload, &cc); err != nil {
						logger.Printf(`{"level":"warn","msg":"invalid cert config skipped","cert":%q,"err":%q}`, name, err.Error())
						continue
					}
					cfg.Certs[name] = cc
				}
			}
		}
	}

	if rawUsers, ok := raw["users"]; ok {
		var userMap map[string]json.RawMessage
		if err := json.Unmarshal(rawUsers, &userMap); err == nil {
			for username, payload := range userMap {
				var entry UserConfig
				if err := json.Unmarshal(payload, &entry); err == nil && (entry.Password != "" || entry.Role != "") {
					if entry.Role == "" {
						entry.Role = "admin"
					}
					cfg.Users[username] = entry
					continue
				}
				var hash string
				if err := json.Unmarshal(payload, &hash); err == nil {
					cfg.Users[username] = UserConfig{Password: hash, Role: "admin"}
				}
			}
		} else {
			var userList []string
			if err := json.Unmarshal(rawUsers, &userList); err == nil {
				for _, user := range userList {
					if strings.TrimSpace(user) == "" {
						continue
					}
					cfg.Users[user] = UserConfig{Role: "admin"}
				}
			}
		}
	}

	if rawSettings, ok := raw["settings"]; ok {
		var settings GlobalSettings
		if err := json.Unmarshal(rawSettings, &settings); err == nil {
			cfg.Settings = settings
		}
	}

	if rawPlugins, ok := raw["plugins"]; ok {
		var pluginMap map[string]PluginConfig
		if err := json.Unmarshal(rawPlugins, &pluginMap); err == nil {
			cfg.Plugins = pluginMap
		} else {
			var pluginList []string
			if err := json.Unmarshal(rawPlugins, &pluginList); err == nil {
				for _, name := range pluginList {
					if strings.TrimSpace(name) == "" {
						continue
					}
					cfg.Plugins[name] = PluginConfig{Name: name, Enabled: true}
				}
			}
		}
	}

	if rawStreams, ok := raw["stream_proxies"]; ok {
		var proxies []StreamProxyConfig
		if err := json.Unmarshal(rawStreams, &proxies); err == nil {
			cfg.StreamProxies = proxies
		}
	}

	ncf, changedNorm := normalizeConfig(cfg)
	return ncf, changed || changedNorm, nil
}

func normalizeConfig(cf ConfigFile) (ConfigFile, bool) {
	changed := false
	if cf.Hosts == nil {
		cf.Hosts = map[string]HostConfig{}
		changed = true
	}
	if cf.Certs == nil {
		cf.Certs = map[string]CertConfig{}
		changed = true
	}
	if cf.Users == nil {
		cf.Users = map[string]UserConfig{}
		changed = true
	}
	if cf.Plugins == nil {
		cf.Plugins = map[string]PluginConfig{}
		changed = true
	}
	normalizedStreams := normalizeStreamProxies(cf.StreamProxies)
	if len(normalizedStreams) != len(cf.StreamProxies) {
		changed = true
	}
	cf.StreamProxies = normalizedStreams
	if isZeroGlobalSettings(cf.Settings) {
		cf.Settings = GlobalSettings{
			HTTP3Enabled:   false,
			HTTP3Advertise: false,
			HTTP3MaxAge:    86400,
			HTTPPorts:      []int{80},
			HTTPSPorts:     []int{443},
			UpdateChannel:  "stable",
		}
		changed = true
	} else {
		if cf.Settings.HTTP3MaxAge == 0 {
			cf.Settings.HTTP3MaxAge = 86400
			changed = true
		}
		if cf.Settings.UpdateChannel == "" {
			cf.Settings.UpdateChannel = "stable"
			changed = true
		}
	}
	httpPorts, httpChanged := normalizePorts(cf.Settings.HTTPPorts, []int{80})
	if httpChanged {
		cf.Settings.HTTPPorts = httpPorts
		changed = true
	}
	httpsPorts, httpsChanged := normalizePorts(cf.Settings.HTTPSPorts, []int{443})
	if httpsChanged {
		cf.Settings.HTTPSPorts = httpsPorts
		changed = true
	}
	for name, plugin := range availablePlugins {
		cfg := cf.Plugins[name]
		updated := false
		if cfg.Name == "" {
			cfg.Name = name
			updated = true
		}
		if cfg.Description == "" {
			cfg.Description = plugin.Description
			updated = true
		}
		if cfg.Version == "" {
			cfg.Version = plugin.Version
			updated = true
		}
		if _, ok := cf.Plugins[name]; !ok {
			cfg.Enabled = plugin.Enabled
			updated = true
		}
		cf.Plugins[name] = cfg
		if updated {
			changed = true
		}
	}
	nHosts := make(map[string]HostConfig, len(cf.Hosts))
	for k, v := range cf.Hosts {
		nk := normalizeHost(k)
		if nk == "" || validateHostnameStrict(nk) != nil {
			logger.Printf(`{"level":"warn","msg":"invalid hostname skipped on load","host":%q}`, nk)
			changed = true
			continue
		}
		backends := make([]string, 0, len(v.Backends))
		for _, b := range v.Backends {
			b = strings.TrimSpace(b)
			if b == "" {
				continue
			}
			backends = append(backends, b)
		}
		if len(backends) != len(v.Backends) {
			changed = true
		}
		v.Backends = backends
		geoRouting := normalizeGeoRouting(v.GeoRouting)
		if len(geoRouting) != len(v.GeoRouting) {
			changed = true
		}
		v.GeoRouting = geoRouting
		mirrorBackends := normalizeBackends(v.MirrorBackends)
		if len(mirrorBackends) != len(v.MirrorBackends) {
			changed = true
		}
		v.MirrorBackends = mirrorBackends
		v.WAFProfile = normalizeWAFProfile(v.WAFProfile)
		wafRules := normalizeWAFRules(v.WAFRules)
		if len(wafRules) != len(v.WAFRules) {
			changed = true
		}
		v.WAFRules = wafRules
		loadBalancing := normalizeLoadBalancing(v.LoadBalancing)
		if loadBalancing == "" {
			loadBalancing = "round_robin"
			changed = true
		}
		if loadBalancing != v.LoadBalancing {
			changed = true
		}
		v.LoadBalancing = loadBalancing
		healthPath := normalizeHealthCheckPath(v.HealthCheckPath)
		if healthPath != v.HealthCheckPath {
			changed = true
		}
		v.HealthCheckPath = healthPath
		if v.SecurityTemplate == "" {
			v.SecurityTemplate = "balanced"
			changed = true
		} else {
			normalizedTemplate := normalizeSecurityTemplate(v.SecurityTemplate)
			if normalizedTemplate != v.SecurityTemplate {
				v.SecurityTemplate = normalizedTemplate
				changed = true
			}
		}
		if v.SecurityTemplate != "custom" {
			if tmpl, ok := securityTemplates[v.SecurityTemplate]; ok {
				v.ExploitBlocks = tmpl
			}
		}
		if v.RateLimitPerMinute < 0 {
			v.RateLimitPerMinute = 0
			changed = true
		}
		allowlist := normalizeIPList(v.Allowlist)
		if len(allowlist) != len(v.Allowlist) {
			changed = true
		}
		denylist := normalizeIPList(v.Denylist)
		if len(denylist) != len(v.Denylist) {
			changed = true
		}
		v.Allowlist = allowlist
		v.Denylist = denylist
		nHosts[nk] = v
		if nk != k {
			changed = true
		}
	}
	cf.Hosts = nHosts
	for name, user := range cf.Users {
		if user.Role == "" {
			user.Role = "admin"
			cf.Users[name] = user
			changed = true
		}
	}
	return cf, changed
}

func isZeroGlobalSettings(settings GlobalSettings) bool {
	return !settings.HTTP3Enabled &&
		!settings.HTTP3Advertise &&
		settings.HTTP3MaxAge == 0 &&
		len(settings.HTTPPorts) == 0 &&
		len(settings.HTTPSPorts) == 0 &&
		settings.UpdateChannel == ""
}

func cleanupUnusedCertFilesLocked() {
	used := map[string]bool{}
	for _, h := range mcfg.Hosts {
		if h.SSL && !h.AutoCert && h.CertName != "" {
			used[h.CertName] = true
		}
	}
	for name, c := range mcfg.Certs {
		if used[name] {
			continue
		}
		if c.CertPath != "" {
			_ = os.Remove(c.CertPath)
		}
		if c.KeyPath != "" {
			_ = os.Remove(c.KeyPath)
		}
		delete(mcfg.Certs, name)
		logger.Printf(`{"level":"info","msg":"cleaned unused cert","cert":%q}`, name)
	}
}

func publishSnapshotLocked() {
	hosts := make(map[string]HostConfig, len(mcfg.Hosts))
	for k, v := range mcfg.Hosts {
		nk := normalizeHost(k)
		if nk != "" {
			hosts[nk] = v
		}
	}
	certs := make(map[string]CertConfig, len(mcfg.Certs))
	for k, v := range mcfg.Certs {
		certs[k] = v
	}

	custom := make(map[string]*tls.Certificate)
	for domain, hc := range hosts {
		if !hc.SSL || hc.AutoCert || hc.CertName == "" {
			continue
		}
		cc, ok := certs[hc.CertName]
		if !ok || cc.CertPath == "" || cc.KeyPath == "" {
			continue
		}
		tc, err := tls.LoadX509KeyPair(cc.CertPath, cc.KeyPath)
		if err != nil {
			logger.Printf(`{"level":"warn","msg":"failed loading custom cert","host":%q,"cert":%q,"err":%q}`, domain, hc.CertName, err.Error())
			continue
		}
		custom[domain] = &tc
	}

	leHostSet := map[string]struct{}{}
	minRenewDays := 0
	addLEHost := func(domain string, renewDays int) {
		domain = normalizeHost(domain)
		if domain == "" {
			return
		}
		leHostSet[domain] = struct{}{}
		if renewDays > 0 && (minRenewDays == 0 || renewDays < minRenewDays) {
			minRenewDays = renewDays
		}
	}
	for domain, hc := range hosts {
		if !hc.SSL {
			continue
		}
		if hc.AutoCert {
			addLEHost(domain, 0)
			continue
		}
		if hc.CertName == "" {
			continue
		}
		cc, ok := certs[hc.CertName]
		if ok && cc.Type == "letsencrypt" && cc.AutoGenerate {
			renewDays := 0
			if cc.AutoRenew {
				renewDays = cc.RenewDays
			}
			addLEHost(domain, renewDays)
		}
	}
	for _, cc := range certs {
		if cc.Type != "letsencrypt" || !cc.AutoGenerate || cc.Domain == "" {
			continue
		}
		renewDays := 0
		if cc.AutoRenew {
			renewDays = cc.RenewDays
		}
		addLEHost(cc.Domain, renewDays)
	}
	leHosts := make([]string, 0, len(leHostSet))
	for domain := range leHostSet {
		leHosts = append(leHosts, domain)
	}
	sort.Strings(leHosts)
	certManager.HostPolicy = autocert.HostWhitelist(leHosts...)
	if minRenewDays > 0 {
		certManager.RenewBefore = time.Duration(minRenewDays) * 24 * time.Hour
	} else {
		certManager.RenewBefore = defaultRenewBefore
	}

	users := make(map[string]UserConfig, len(mcfg.Users))
	for k, v := range mcfg.Users {
		users[k] = v
	}
	plugins := make(map[string]PluginConfig, len(mcfg.Plugins))
	for k, v := range mcfg.Plugins {
		plugins[k] = v
	}
	streams := make([]StreamProxyConfig, len(mcfg.StreamProxies))
	copy(streams, mcfg.StreamProxies)

	s := &ConfigSnapshot{
		Hosts:         hosts,
		Certs:         certs,
		CustomCerts:   custom,
		LEHosts:       leHosts,
		Users:         users,
		StreamProxies: streams,
		Plugins:       plugins,
		Settings:      mcfg.Settings,
	}
	snapV.Store(s)
}

func getSnap() *ConfigSnapshot {
	v := snapV.Load()
	if v == nil {
		return &ConfigSnapshot{
			Hosts:         map[string]HostConfig{},
			Certs:         map[string]CertConfig{},
			CustomCerts:   map[string]*tls.Certificate{},
			LEHosts:       nil,
			Users:         map[string]UserConfig{},
			StreamProxies: nil,
			Plugins:       map[string]PluginConfig{},
			Settings:      mcfg.Settings,
		}
	}
	return v.(*ConfigSnapshot)
}

func isUsingAutoCert(domain string) bool {
	s := getSnap()
	hc, ok := s.Hosts[domain]
	if !ok || !hc.SSL {
		return false
	}
	if hc.AutoCert {
		return true
	}
	if hc.CertName == "" {
		return false
	}
	cc, ok := s.Certs[hc.CertName]
	if !ok {
		return false
	}
	return cc.Type == "letsencrypt" && cc.AutoGenerate
}

func setHealth(host, backend string, h BackendHealth) {
	healthMu.Lock()
	defer healthMu.Unlock()
	m, ok := healthByHost[host]
	if !ok {
		m = map[string]BackendHealth{}
		healthByHost[host] = m
	}
	m[backend] = h
}

func getHealth(host string) map[string]BackendHealth {
	healthMu.RLock()
	defer healthMu.RUnlock()
	src, ok := healthByHost[host]
	if !ok {
		return map[string]BackendHealth{}
	}
	out := make(map[string]BackendHealth, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func pickHealthyBackend(host string, backends []string) (string, bool) {
	hm := getHealth(host)
	var healthy []string
	for _, b := range backends {
		if st, ok := hm[b]; ok && st.Healthy {
			healthy = append(healthy, b)
		}
	}
	if len(healthy) > 0 {
		idx := atomic.AddUint32(&rrIdx, 1) % uint32(len(healthy))
		return healthy[idx], true
	}
	idx := atomic.AddUint32(&rrIdx, 1) % uint32(len(backends))
	return backends[idx], false
}

func healthCheckOnce(host string, backend string, checkPath string) BackendHealth {
	start := time.Now()
	res := BackendHealth{LastCheck: start}
	u, err := url.Parse(backend)
	if err != nil || u.Scheme == "" || u.Host == "" {
		res.Healthy = false
		res.LastError = "invalid backend url"
		return res
	}
	d := net.Dialer{Timeout: healthTimeout}
	conn, err := d.Dial("tcp", u.Host)
	if err != nil {
		res.Healthy = false
		res.LastError = err.Error()
		res.LatencyMS = time.Since(start).Milliseconds()
		return res
	}
	_ = conn.Close()

	client := &http.Client{
		Timeout:   healthTimeout,
		Transport: sharedTransport,
	}
	path := checkPath
	if path == "" {
		path = healthPath
	}
	tryPaths := []string{path, "/"}
	var lastErr error
	var status int
	for _, p := range tryPaths {
		probeURL := *u
		probeURL.Path = p
		probeURL.RawQuery = ""
		req, _ := http.NewRequest(http.MethodGet, probeURL.String(), nil)
		req.Header.Set("User-Agent", "proxy-healthcheck/1.0")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		status = resp.StatusCode
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if status < 500 {
			res.Healthy = true
			res.StatusCode = status
			res.LatencyMS = time.Since(start).Milliseconds()
			return res
		}
		lastErr = fmt.Errorf("status %d", status)
	}
	res.Healthy = false
	if lastErr != nil {
		res.LastError = lastErr.Error()
	}
	res.StatusCode = status
	res.LatencyMS = time.Since(start).Milliseconds()
	return res
}

func startHealthChecker(ctx context.Context) {
	t := time.NewTicker(healthInterval)
	defer t.Stop()
	run := func() {
		s := getSnap()
		for host, hc := range s.Hosts {
			if len(hc.Backends) == 0 {
				continue
			}
			for _, b := range hc.Backends {
				h := healthCheckOnce(host, b, hc.HealthCheckPath)
				setHealth(host, b, h)
			}
		}
	}
	run()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// Add these two methods to support Hijacking (required for WebSockets)
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errors.New("underlying ResponseWriter does not implement http.Hijacker")
}

func (w *statusWriter) Flush() {
	if fl, ok := w.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func recordTraffic(ts time.Time, bytes int64) {
	day := ts.UTC().Format("2006-01-02")
	trafficMu.Lock()
	defer trafficMu.Unlock()
	point := trafficByDay[day]
	if point == nil {
		point = &trafficPoint{Day: day}
		trafficByDay[day] = point
	}
	point.Count++
	if bytes > 0 {
		point.Bytes += bytes
	}
	cutoff := ts.UTC().AddDate(0, 0, -30).Format("2006-01-02")
	for key := range trafficByDay {
		if key < cutoff {
			delete(trafficByDay, key)
		}
	}
}

func trafficTrend(days int) []trafficPoint {
	if days <= 0 {
		return nil
	}
	now := time.Now().UTC()
	points := make([]trafficPoint, 0, days)
	trafficMu.Lock()
	defer trafficMu.Unlock()
	for i := days - 1; i >= 0; i-- {
		day := now.AddDate(0, 0, -i).Format("2006-01-02")
		if point, ok := trafficByDay[day]; ok {
			points = append(points, *point)
		} else {
			points = append(points, trafficPoint{Day: day})
		}
	}
	return points
}

func accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := r.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = newReqID()
			r.Header.Set("X-Request-Id", reqID)
		}
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		host := normalizeHost(r.Host)
		backend := r.Header.Get("X-Proxy-Backend")
		backendHost := ""
		backendScheme := ""
		if backendURL, err := url.Parse(backend); err == nil {
			backendHost = backendURL.Host
			backendScheme = backendURL.Scheme
		}
		dur := time.Since(start).Milliseconds()
		if sw.status == 0 {
			sw.status = 200
		}
		proxySummary := fmt.Sprintf("%s (Domain) proxied to %s (Backend)", host, backend)
		logger.Printf(`{"level":"info","msg":"proxy_response","req_id":%q,"host":%q,"backend":%q,"summary":%q,"method":%q,"path":%q,"status":%d}`,
			reqID, host, backend, proxySummary, r.Method, r.URL.RequestURI(), sw.status)
		recordTraffic(time.Now(), sw.bytes)
		if atomic.LoadUint32(&logLevel) == logLevelDebug {
			proto := "http"
			if r.TLS != nil {
				proto = "https"
			}
			logger.Printf(`{"level":"debug","msg":"proxy_response_detail","req_id":%q,"remote":%q,"host":%q,"backend":%q,"backend_host":%q,"backend_scheme":%q,"summary":%q,"method":%q,"path":%q,"proto":%q,"status":%d,"bytes":%d,"dur_ms":%d}`,
				reqID, r.RemoteAddr, host, backend, backendHost, backendScheme, proxySummary, r.Method, r.URL.RequestURI(), proto, sw.status, sw.bytes, dur)
		}
	})
}

func geoCountryFromHeaders(r *http.Request) string {
	headers := []string{"CF-IPCountry", "X-Geo-Country", "X-Country-Code", "X-Geo-Country-Code"}
	for _, header := range headers {
		code := strings.TrimSpace(r.Header.Get(header))
		if code != "" {
			return strings.ToUpper(code)
		}
	}
	return ""
}

func pickBackendForRequest(host string, cfg HostConfig, r *http.Request) string {
	if len(cfg.GeoRouting) > 0 {
		if country := geoCountryFromHeaders(r); country != "" {
			if backend, ok := cfg.GeoRouting[country]; ok {
				return backend
			}
		}
		if backend, ok := cfg.GeoRouting["DEFAULT"]; ok {
			return backend
		}
		if backend, ok := cfg.GeoRouting["GLOBAL"]; ok {
			return backend
		}
	}
	strategy := normalizeLoadBalancing(cfg.LoadBalancing)
	if strategy == "" {
		strategy = "round_robin"
	}
	switch strategy {
	case "none":
		if len(cfg.Backends) == 0 {
			return ""
		}
		return cfg.Backends[0]
	case "random":
		return pickRandomBackend(host, cfg.Backends)
	case "ip_hash":
		return pickIPHashBackend(host, cfg.Backends, getClientIP(r))
	case "least_latency":
		if backend := pickLeastLatencyBackend(host, cfg.Backends); backend != "" {
			return backend
		}
		return pickRoundRobinBackend(host, cfg.Backends)
	default:
		return pickRoundRobinBackend(host, cfg.Backends)
	}
}

func pickRoundRobinBackend(host string, backends []string) string {
	backend, _ := pickHealthyBackend(host, backends)
	return backend
}

func pickRandomBackend(host string, backends []string) string {
	candidates := healthyBackendsFor(host, backends)
	if len(candidates) == 0 {
		candidates = backends
	}
	if len(candidates) == 0 {
		return ""
	}
	rngMu.Lock()
	idx := rng.Intn(len(candidates))
	rngMu.Unlock()
	return candidates[idx]
}

func pickIPHashBackend(host string, backends []string, clientIP string) string {
	candidates := healthyBackendsFor(host, backends)
	if len(candidates) == 0 {
		candidates = backends
	}
	if len(candidates) == 0 {
		return ""
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(clientIP))
	idx := int(h.Sum32()) % len(candidates)
	return candidates[idx]
}

func pickLeastLatencyBackend(host string, backends []string) string {
	hm := getHealth(host)
	var selected string
	minLatency := int64(0)
	for _, b := range backends {
		st, ok := hm[b]
		if !ok || !st.Healthy {
			continue
		}
		if selected == "" || st.LatencyMS < minLatency {
			selected = b
			minLatency = st.LatencyMS
		}
	}
	return selected
}

func healthyBackendsFor(host string, backends []string) []string {
	if len(backends) == 0 {
		return nil
	}
	hm := getHealth(host)
	healthy := make([]string, 0, len(backends))
	for _, b := range backends {
		if st, ok := hm[b]; ok && st.Healthy {
			healthy = append(healthy, b)
		}
	}
	return healthy
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		out[k] = append([]string{}, v...)
	}
	return out
}

func mirrorRequest(r *http.Request, primary string, mirrors []string, body []byte) {
	if len(mirrors) == 0 {
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, mirror := range mirrors {
		mirror = strings.TrimSpace(mirror)
		if mirror == "" || mirror == primary {
			continue
		}
		u, err := url.Parse(mirror)
		if err != nil {
			continue
		}
		u.Path = singleJoiningSlash(u.Path, r.URL.Path)
		u.RawQuery = r.URL.RawQuery
		reqBody := bytes.NewReader(body)
		req, err := http.NewRequestWithContext(context.Background(), r.Method, u.String(), reqBody)
		if err != nil {
			continue
		}
		req.Header = cloneHeader(r.Header)
		req.Header.Set("X-Proxy-Mirror", "true")
		req.Header.Set("X-Forwarded-Host", r.Host)
		if req.Header.Get("X-Forwarded-Proto") == "" {
			if r.TLS != nil {
				req.Header.Set("X-Forwarded-Proto", "https")
			} else {
				req.Header.Set("X-Forwarded-Proto", "http")
			}
		}
		go func(req *http.Request) {
			resp, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}(req)
	}
}

func logSecurityIntegrationHints(integrations SecurityIntegrations, host, ip, reason string) {
	if integrations.Fail2Ban {
		logger.Printf(`{"level":"warn","msg":"fail2ban hint","host":%q,"ip":%q,"reason":%q}`, host, ip, reason)
	}
	if integrations.CrowdSec {
		logger.Printf(`{"level":"warn","msg":"crowdsec hint","host":%q,"ip":%q,"reason":%q}`, host, ip, reason)
	}
}

func proxyHandler(w http.ResponseWriter, r *http.Request, isHTTPS bool) {
	host := normalizeHost(r.Host)
	if host == "" {
		http.Error(w, "400 Bad Request - Missing host", http.StatusBadRequest)
		return
	}

	s := getSnap()
	cfg, ok := s.Hosts[host]
	if !ok || len(cfg.Backends) == 0 {
		http.Error(w, "502 Bad Gateway - No backend configured", http.StatusBadGateway)
		return
	}

	if isHTTPS && !cfg.SSL {
		http.Error(w, "403 Forbidden - This domain does not support HTTPS", http.StatusForbidden)
		return
	}

	if !isHTTPS && cfg.SSL {
		httpsURL := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
		return
	}

	isWSUpgrade := strings.EqualFold(r.Header.Get("Connection"), "upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket")

	if isWSUpgrade && !cfg.WebSocket {
		http.Error(w, "403 Forbidden - WebSocket proxying disabled", http.StatusForbidden)
		return
	}

	clientIP := getClientIP(r)
	if matched, rule := ipInList(clientIP, cfg.Denylist); matched {
		logger.Printf(`{"level":"warn","msg":"request denied by denylist","host":%q,"ip":%q,"rule":%q}`, host, clientIP, rule)
		logSecurityIntegrationHints(cfg.SecurityIntegrations, host, clientIP, "denylist:"+rule)
		http.Error(w, "403 Forbidden - Access denied", http.StatusForbidden)
		return
	}
	if len(cfg.Allowlist) > 0 {
		if matched, _ := ipInList(clientIP, cfg.Allowlist); !matched {
			logger.Printf(`{"level":"warn","msg":"request rejected (not in allowlist)","host":%q,"ip":%q}`, host, clientIP)
			logSecurityIntegrationHints(cfg.SecurityIntegrations, host, clientIP, "allowlist")
			http.Error(w, "403 Forbidden - Access restricted", http.StatusForbidden)
			return
		}
	}
	if cfg.RateLimitPerMinute > 0 {
		key := host + "|" + clientIP
		if !requestLimiter.Allow(key, cfg.RateLimitPerMinute) {
			logger.Printf(`{"level":"warn","msg":"rate limit exceeded","host":%q,"ip":%q,"limit_per_min":%d}`, host, clientIP, cfg.RateLimitPerMinute)
			logSecurityIntegrationHints(cfg.SecurityIntegrations, host, clientIP, "rate_limit")
			http.Error(w, "429 Too Many Requests - Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}
	var bodyBytes []byte
	if (cfg.WAFEnabled && !isWSUpgrade) || len(cfg.MirrorBackends) > 0 {
		bodyBytes, _ = readRequestBody(r, 2<<20)
	}
	if cfg.WAFEnabled && !isWSUpgrade {
		profile := normalizeWAFProfile(cfg.WAFProfile)
		if match, blocked := wafDetect(r, profile, cfg.WAFRules, bodyBytes); blocked {
			logger.Printf(`{"level":"warn","msg":"waf blocked request","host":%q,"ip":%q,"rule":%q,"path":%q}`, host, clientIP, match, r.URL.RequestURI())
			logSecurityIntegrationHints(cfg.SecurityIntegrations, host, clientIP, "waf:"+match)
			http.Error(w, "403 Forbidden - Request blocked", http.StatusForbidden)
			return
		}
	}

	// Domain authentication
	if cfg.RequireAuth {
		user := getSession(r)
		if user == "" {
			if r.URL.Path == "/_proxy_login" {
				if r.Method == "POST" {
					r.ParseForm()
					u := r.FormValue("user")
					p := r.FormValue("pass")
					if checkUser(u, p, s) {
						setSession(w, r, u)
						red := r.FormValue("return")
						if red == "" {
							red = "/"
						}
						http.Redirect(w, r, red, 302)
						return
					}
					serveLoginForm(w, r, host, "Invalid credentials")
					return
				}
				serveLoginForm(w, r, host, "")
				return
			}
			returnURL := url.QueryEscape(r.RequestURI)
			http.Redirect(w, r, "/_proxy_login?return="+returnURL, 302)
			return
		}
	}

	// Pick backend
	backend := pickBackendForRequest(host, cfg, r)
	r.Header.Set("X-Proxy-Backend", backend)
	if len(cfg.MirrorBackends) > 0 {
		mirrorRequest(r, backend, cfg.MirrorBackends, bodyBytes)
	}

	u, err := url.Parse(backend)
	if err != nil {
		http.Error(w, "502 Bad Gateway - Invalid backend", http.StatusBadGateway)
		return
	}

	insecure := false
	if u.Scheme == "https" {
		insecure = u.Query().Get("insecure") == "true"
		u.RawQuery = ""
	}

	// Common fallback paths
	fallbackPaths := []string{
		"/websocket",
		"/ws",
		"/socket",
		"/api/ws",
		"/api/socket",
		"/api/websocket",
		"/notifications/hub",
		"/hub",
		"/sock",
		"/stream",
	}

	rp := httputil.NewSingleHostReverseProxy(u)

	tr := sharedTransport.Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	rp.Transport = tr

	rp.FlushInterval = 50 * time.Millisecond

	rp.Director = func(req *http.Request) {
		req.URL.Scheme = u.Scheme
		req.URL.Host = u.Host
		req.URL.Path = singleJoiningSlash(u.Path, req.URL.Path)
		if u.RawQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = u.RawQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = u.RawQuery + "&" + req.URL.RawQuery
		}

		req.Host = u.Host
		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", host)
		}
		if req.Header.Get("X-Forwarded-Proto") == "" {
			proto := "http"
			if req.TLS != nil {
				proto = "https"
			}
			req.Header.Set("X-Forwarded-Proto", proto)
		}
	}

	// Track attempted paths
	attemptedPaths := make(map[string]bool)

	// ModifyResponse: intercept 404 and retry fallback paths
	rp.ModifyResponse = func(resp *http.Response) error {
		attemptedPaths[resp.Request.URL.Path] = true

		blocks := cfg.ExploitBlocks
		if blocks.FrameOptions {
			resp.Header.Set("X-Frame-Options", "SAMEORIGIN")
		}
		if blocks.XSSProtection {
			resp.Header.Set("X-XSS-Protection", "1; mode=block")
		}
		if blocks.ContentTypeOptions {
			resp.Header.Set("X-Content-Type-Options", "nosniff")
		}
		if blocks.ContentSecurityPolicy {
			resp.Header.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:")
		}
		if blocks.StrictTransport {
			resp.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if blocks.ReferrerPolicy {
			resp.Header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		}
		if cfg.OriginShield {
			resp.Header.Del("Server")
			resp.Header.Del("X-Powered-By")
			resp.Header.Del("X-AspNet-Version")
			resp.Header.Del("X-AspNetMvc-Version")
			resp.Header.Set("Server", "PuffProxy")
		}

		// Only retry if it's a WebSocket request and we got 404
		if !isWSUpgrade || resp.StatusCode != http.StatusNotFound {
			return nil
		}

		// Try fallback paths
		for _, fallback := range fallbackPaths {
			if attemptedPaths[fallback] {
				continue
			}

			newPath := fallback
			if strings.HasSuffix(resp.Request.URL.Path, "/current") {
				base := strings.TrimSuffix(resp.Request.URL.Path, "/current")
				newPath = base + fallback
			}

			logger.Printf(`{"level":"info","msg":"websocket 404 fallback","host":%q,"trying_path":%q}`, host, newPath)

			// Clone request with new path
			fallbackReq := r.Clone(r.Context())
			fallbackReq.URL.Path = newPath
			fallbackReq.RequestURI = newPath

			// Serve the fallback request
			rp.ServeHTTP(w, fallbackReq)
			return fmt.Errorf("retrying with fallback path")
		}

		// No fallback worked
		return nil
	}

	// ErrorHandler for network errors
	rp.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		logger.Printf(`{"level":"error","msg":"upstream connection error","host":%q,"path":%q,"err":%q}`, host, req.URL.Path, err.Error())
		http.Error(w, "502 Bad Gateway - Backend unreachable", http.StatusBadGateway)
	}

	rp.ServeHTTP(w, r)
}

// Helper: check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func triggerLECertIssuance(domain string) {
	triggerLECertIssuanceFor(domain, "")
}

func triggerLECertIssuanceFor(domain string, certName string) {
	go func() {
		hello := &tls.ClientHelloInfo{
			ServerName: domain,
		}
		cert, err := certManager.GetCertificate(hello)
		if err != nil {
			logger.Printf(`{"level":"warn","msg":"autocert immediate issuance failed","host":%q,"err":%q}`, domain, err.Error())
			return
		}
		certPath, keyPath, err := writeLECertFiles(certName, domain, cert)
		if err != nil {
			logger.Printf(`{"level":"warn","msg":"failed writing LE cert files","host":%q,"err":%q}`, domain, err.Error())
			return
		}
		if certName != "" {
			mu.Lock()
			if cfg, ok := mcfg.Certs[certName]; ok {
				cfg.CertPath = certPath
				cfg.KeyPath = keyPath
				mcfg.Certs[certName] = cfg
				if err := saveConfigToDiskLocked(); err != nil {
					logError("failed to save config after LE cert write", err)
				} else {
					publishSnapshotLocked()
				}
			}
			mu.Unlock()
		}
		leaf := cert.Leaf
		if leaf != nil {
			expires := leaf.NotAfter.Format("2006-01-02")
			logger.Printf(`{"level":"info","msg":"autocert certificate obtained","host":%q,"expires":%q}`, domain, expires)
		} else {
			logger.Printf(`{"level":"info","msg":"autocert certificate obtained","host":%q}`, domain)
		}
	}()
}

func writeLECertFiles(certName string, domain string, cert *tls.Certificate) (string, string, error) {
	base := sanitizeCertFileName(certName)
	if base == "" {
		base = sanitizeCertFileName(domain)
	}
	if base == "" {
		return "", "", errors.New("missing cert name/domain for filename")
	}
	dir := filepath.Join(cacheDir, "letsencrypt")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", err
	}
	certPath := filepath.Join(dir, base+".cert.pem")
	keyPath := filepath.Join(dir, base+".key.pem")
	certPEM := &bytes.Buffer{}
	for _, der := range cert.Certificate {
		_ = pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	if certPEM.Len() == 0 {
		return "", "", errors.New("no certificate data")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM.Bytes(), 0600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		_ = os.Remove(certPath)
		return "", "", err
	}
	return certPath, keyPath, nil
}

func sanitizeCertFileName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		certManager.HTTPHandler(nil).ServeHTTP(w, r)
		return
	}
	proxyHandler(w, r, false)
}

func httpsHandler(w http.ResponseWriter, r *http.Request) {
	proxyHandler(w, r, true)
}

func getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := normalizeHost(hello.ServerName)
	if domain == "" {
		return nil, fmt.Errorf("missing server name")
	}

	s := getSnap()
	hc, ok := s.Hosts[domain]
	if !ok || !hc.SSL {
		return nil, fmt.Errorf("no SSL config for %s", domain)
	}

	// Use Let's Encrypt (autocert) if AutoCert is enabled
	if hc.AutoCert {
		// Important: use the original hello info so autocert sees the correct SNI
		return certManager.GetCertificate(hello)
	}

	// Otherwise, use custom certificate if configured
	if hc.CertName != "" {
		customCert, ok := s.CustomCerts[domain]
		if !ok {
			return nil, fmt.Errorf("custom certificate not loaded for %s", domain)
		}
		return customCert, nil
	}

	return nil, fmt.Errorf("no certificate available for %s", domain)
}

type apiResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	ip := getClientIP(r)
	want := csrfTokenForIP(ip)
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		_ = r.ParseForm()
		got = r.FormValue("csrf")
	}
	if got != want {
		http.Error(w, "403 Forbidden - CSRF token mismatch", http.StatusForbidden)
		return false
	}
	return true
}

func adminIndexHandler(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	data := struct {
		IsLogin bool
		CSRF    string
	}{
		IsLogin: false,
		CSRF:    csrfTokenForIP(ip),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = uiTmpl.Execute(w, data)
}

func adminAPIConfigHandler(w http.ResponseWriter, r *http.Request) {
	s := getSnap()

	// === Hosts as array (always array, even empty) ===
	type hostView struct {
		Domain               string                   `json:"domain"`
		SSL                  bool                     `json:"ssl"`
		AutoCert             bool                     `json:"auto_cert"`
		CertName             string                   `json:"cert_name"`
		Backends             []string                 `json:"backends"`
		GeoRouting           map[string]string        `json:"geo_routing"`
		MirrorBackends       []string                 `json:"mirror_backends"`
		Health               map[string]BackendHealth `json:"health"`
		Webhook              string                   `json:"webhook"`
		ExploitBlocks        ExploitBlockConfig       `json:"exploit_blocks"`
		LoadBalancing        string                   `json:"load_balancing"`
		HealthCheckPath      string                   `json:"health_check_path"`
		SecurityTemplate     string                   `json:"security_template"`
		SecurityIntegrations SecurityIntegrations     `json:"security_integrations"`
		RequireAuth          bool                     `json:"require_auth"`
		WebSocket            bool                     `json:"websocket"`
		WAFEnabled           bool                     `json:"waf_enabled"`
		WAFProfile           string                   `json:"waf_profile"`
		WAFRules             map[string]bool          `json:"waf_rules"`
		Allowlist            []string                 `json:"allowlist"`
		Denylist             []string                 `json:"denylist"`
		RateLimitPerMinute   int                      `json:"rate_limit_per_minute"`
		OriginShield         bool                     `json:"origin_shield"`
	}

	hosts := make([]hostView, 0) // ← explicitly start as empty slice
	for domain, hc := range s.Hosts {
		h := getHealth(domain)
		hosts = append(hosts, hostView{
			Domain:               domain,
			SSL:                  hc.SSL,
			AutoCert:             hc.AutoCert,
			CertName:             hc.CertName,
			Backends:             append([]string{}, hc.Backends...),
			GeoRouting:           hc.GeoRouting,
			MirrorBackends:       append([]string{}, hc.MirrorBackends...),
			Health:               h,
			Webhook:              hc.Webhook,
			ExploitBlocks:        hc.ExploitBlocks,
			LoadBalancing:        hc.LoadBalancing,
			HealthCheckPath:      hc.HealthCheckPath,
			SecurityTemplate:     hc.SecurityTemplate,
			SecurityIntegrations: hc.SecurityIntegrations,
			RequireAuth:          hc.RequireAuth,
			WebSocket:            hc.WebSocket,
			WAFEnabled:           hc.WAFEnabled,
			WAFProfile:           hc.WAFProfile,
			WAFRules:             hc.WAFRules,
			Allowlist:            append([]string{}, hc.Allowlist...),
			Denylist:             append([]string{}, hc.Denylist...),
			RateLimitPerMinute:   hc.RateLimitPerMinute,
			OriginShield:         hc.OriginShield,
		})
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Domain < hosts[j].Domain })

	// === Certs as array (always array) ===
	type certView struct {
		Name         string `json:"name"`
		Type         string `json:"type"`
		AutoGenerate bool   `json:"auto_generate"`
		AutoRenew    bool   `json:"auto_renew"`
		RenewDays    int    `json:"renew_days"`
		Domain       string `json:"domain"`
		CertPath     string `json:"cert_path"`
		KeyPath      string `json:"key_path"`
	}

	certs := make([]certView, 0) // ← explicitly empty slice
	for name, c := range s.Certs {
		certs = append(certs, certView{
			Name:         name,
			Type:         c.Type,
			AutoGenerate: c.AutoGenerate,
			AutoRenew:    c.AutoRenew,
			RenewDays:    c.RenewDays,
			Domain:       c.Domain,
			CertPath:     c.CertPath,
			KeyPath:      c.KeyPath,
		})
	}
	sort.Slice(certs, func(i, j int) bool { return certs[i].Name < certs[j].Name })

	// === LE hosts and users (already slices) ===
	leHosts := s.LEHosts
	if leHosts == nil {
		leHosts = []string{}
	}

	type userView struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	users := make([]userView, 0)
	for u, cfg := range s.Users {
		role := cfg.Role
		if role == "" {
			role = "admin"
		}
		users = append(users, userView{Username: u, Role: role})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })

	streams := make([]StreamProxyConfig, len(s.StreamProxies))
	copy(streams, s.StreamProxies)

	plugins := make([]PluginConfig, 0, len(s.Plugins))
	for _, plugin := range s.Plugins {
		plugins = append(plugins, plugin)
	}
	sort.Slice(plugins, func(i, j int) bool { return plugins[i].Name < plugins[j].Name })

	// === Send response with arrays only ===
	writeJSON(w, 200, map[string]any{
		"hosts":          hosts, // always [] — even when empty
		"certs":          certs, // always [] — even when empty
		"le_hosts":       leHosts,
		"users":          users,
		"stream_proxies": streams,
		"plugins":        plugins,
		"settings":       s.Settings,
		"templates":      hostTemplates,
		"traffic_trend":  trafficTrend(14),
	})
}

func adminAPILogsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	level := atomic.LoadUint32(&logLevel)
	writeJSON(w, 200, map[string]any{
		"level": levelToString(level),
		"logs":  logs.list(level),
	})
}

func adminAPILogLevelHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "editor") {
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	var payload struct {
		Level string `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid json"})
		return
	}
	if err := setLogLevel(payload.Level); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, 200, apiResp{OK: true})
}

func adminAPILogsClearHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "editor") {
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	var payload struct {
		Range string `json:"range"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid json"})
		return
	}
	switch payload.Range {
	case "all":
		logs.clearAll()
	case "last24h":
		logs.clearSince(time.Now().Add(-24 * time.Hour))
	default:
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid range"})
		return
	}
	writeJSON(w, 200, apiResp{OK: true})
}

type hostUpsertReq struct {
	Domain               string               `json:"domain"`
	Backends             []string             `json:"backends"`
	GeoRouting           map[string]string    `json:"geo_routing"`
	MirrorBackends       []string             `json:"mirror_backends"`
	SSL                  bool                 `json:"ssl"`
	CertName             string               `json:"cert_name"`
	Webhook              string               `json:"webhook"`
	ExploitBlocks        ExploitBlockConfig   `json:"exploit_blocks"`
	BlockExploits        *bool                `json:"block_exploits"`
	LoadBalancing        string               `json:"load_balancing"`
	HealthCheckPath      string               `json:"health_check_path"`
	SecurityTemplate     string               `json:"security_template"`
	SecurityIntegrations SecurityIntegrations `json:"security_integrations"`
	RequireAuth          bool                 `json:"require_auth"`
	WebSocket            bool                 `json:"websocket"`
	WAFEnabled           bool                 `json:"waf_enabled"`
	WAFProfile           string               `json:"waf_profile"`
	WAFRules             map[string]bool      `json:"waf_rules"`
	Allowlist            []string             `json:"allowlist"`
	Denylist             []string             `json:"denylist"`
	RateLimitPerMinute   int                  `json:"rate_limit_per_minute"`
	OriginShield         bool                 `json:"origin_shield"`
}

func adminAPIHostUpsert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "editor") {
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	var req hostUpsertReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid json"})
		return
	}

	domain := normalizeHost(req.Domain)
	if err := validateHostnameStrict(domain); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid hostname: " + err.Error()})
		return
	}
	if len(req.Backends) == 0 {
		writeJSON(w, 400, apiResp{OK: false, Error: "at least one backend is required"})
		return
	}
	valid := make([]string, 0, len(req.Backends))
	for _, b := range req.Backends {
		b = strings.TrimSpace(b)
		if b == "" {
			continue
		}
		if err := validateBackendURL(b); err != nil {
			writeJSON(w, 400, apiResp{OK: false, Error: err.Error()})
			return
		}
		valid = append(valid, b)
	}
	if len(valid) == 0 {
		writeJSON(w, 400, apiResp{OK: false, Error: "no valid backends"})
		return
	}
	for _, mirror := range req.MirrorBackends {
		if strings.TrimSpace(mirror) == "" {
			continue
		}
		if err := validateBackendURL(strings.TrimSpace(mirror)); err != nil {
			writeJSON(w, 400, apiResp{OK: false, Error: "invalid mirror backend: " + err.Error()})
			return
		}
	}
	for _, backend := range req.GeoRouting {
		if strings.TrimSpace(backend) == "" {
			continue
		}
		if err := validateBackendURL(strings.TrimSpace(backend)); err != nil {
			writeJSON(w, 400, apiResp{OK: false, Error: "invalid geo backend: " + err.Error()})
			return
		}
	}

	blocks := req.ExploitBlocks
	if req.BlockExploits != nil {
		blocks = exploitBlockConfigAll(*req.BlockExploits)
	}
	securityTemplate := normalizeSecurityTemplate(req.SecurityTemplate)
	if securityTemplate != "custom" {
		if tmpl, ok := securityTemplates[securityTemplate]; ok {
			blocks = tmpl
		}
	}
	loadBalancing := normalizeLoadBalancing(req.LoadBalancing)
	if loadBalancing == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid load balancing strategy"})
		return
	}
	healthPath := normalizeHealthCheckPath(req.HealthCheckPath)
	if req.HealthCheckPath != "" && healthPath == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "health check path must start with / and contain no spaces"})
		return
	}

	mu.Lock()

	// Remember previous config to detect new LE domains
	oldHC, hadOld := mcfg.Hosts[domain]
	oldWasLE := hadOld && oldHC.SSL && (oldHC.AutoCert || (oldHC.CertName != "" && func() bool {
		if cc, ok := mcfg.Certs[oldHC.CertName]; ok {
			return cc.Type == "letsencrypt" && cc.AutoGenerate
		}
		return false
	}()))

	if req.RateLimitPerMinute < 0 {
		mu.Unlock()
		writeJSON(w, 400, apiResp{OK: false, Error: "rate_limit_per_minute must be non-negative"})
		return
	}
	allowlist := normalizeIPList(req.Allowlist)
	if len(allowlist) != len(req.Allowlist) {
		mu.Unlock()
		writeJSON(w, 400, apiResp{OK: false, Error: "allowlist contains invalid IP/CIDR entries"})
		return
	}
	denylist := normalizeIPList(req.Denylist)
	if len(denylist) != len(req.Denylist) {
		mu.Unlock()
		writeJSON(w, 400, apiResp{OK: false, Error: "denylist contains invalid IP/CIDR entries"})
		return
	}

	hc := HostConfig{
		Backends:             valid,
		GeoRouting:           normalizeGeoRouting(req.GeoRouting),
		MirrorBackends:       normalizeBackends(req.MirrorBackends),
		SSL:                  req.SSL,
		Webhook:              strings.TrimSpace(req.Webhook),
		ExploitBlocks:        blocks,
		LoadBalancing:        loadBalancing,
		HealthCheckPath:      healthPath,
		SecurityTemplate:     securityTemplate,
		SecurityIntegrations: req.SecurityIntegrations,
		RequireAuth:          req.RequireAuth,
		WebSocket:            req.WebSocket,
		WAFEnabled:           req.WAFEnabled,
		WAFProfile:           normalizeWAFProfile(req.WAFProfile),
		WAFRules:             normalizeWAFRules(req.WAFRules),
		Allowlist:            allowlist,
		Denylist:             denylist,
		RateLimitPerMinute:   req.RateLimitPerMinute,
		OriginShield:         req.OriginShield,
	}

	if req.SSL {
		if req.CertName == "_auto" {
			hc.AutoCert = true
			hc.CertName = ""
		} else if strings.TrimSpace(req.CertName) != "" {
			if _, ok := mcfg.Certs[req.CertName]; !ok {
				mu.Unlock()
				writeJSON(w, 400, apiResp{OK: false, Error: "selected certificate does not exist"})
				return
			}
			hc.AutoCert = false
			hc.CertName = req.CertName
		}
	}

	mcfg.Hosts[domain] = hc

	if err := saveConfigToDiskLocked(); err != nil {
		mu.Unlock()
		logError("failed to save config after host upsert", err)
		writeJSON(w, 500, apiResp{OK: false, Error: "failed to save config"})
		return
	}

	cleanupUnusedCertFilesLocked()
	publishSnapshotLocked()
	mu.Unlock()

	// Trigger immediate cert issuance if this domain now uses Let's Encrypt
	isLE := hc.SSL && (hc.AutoCert || (hc.CertName != "" && func() bool {
		if cc, ok := mcfg.Certs[hc.CertName]; ok {
			return cc.Type == "letsencrypt" && cc.AutoGenerate
		}
		return false
	}()))

	if isLE && (!hadOld || !oldWasLE) {
		certName := ""
		if hc.CertName != "" {
			if cc, ok := mcfg.Certs[hc.CertName]; ok && cc.Type == "letsencrypt" && cc.AutoGenerate {
				certName = hc.CertName
			}
		}
		triggerLECertIssuanceFor(domain, certName)
	}

	// Refresh health checks
	for _, b := range valid {
		setHealth(domain, b, healthCheckOnce(domain, b, hc.HealthCheckPath))
	}

	recordAudit(r, "host.upsert", domain, "updated proxy host")
	streamManager.sync(getSnap().StreamProxies)
	writeJSON(w, 200, apiResp{OK: true})
}

type hostDeleteReq struct {
	Domain string `json:"domain"`
}

func adminAPIHostDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "editor") {
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	var req hostDeleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid json"})
		return
	}
	domain := normalizeHost(req.Domain)
	if domain == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "domain required"})
		return
	}
	mu.Lock()
	delete(mcfg.Hosts, domain)

	if err := saveConfigToDiskLocked(); err != nil {
		mu.Unlock()
		logError("failed to save config after host delete", err)
		writeJSON(w, 500, apiResp{OK: false, Error: "failed to save config"})
		return
	}
	cleanupUnusedCertFilesLocked()
	publishSnapshotLocked() // this rebuilds LEHosts whitelist, removing deleted domain
	mu.Unlock()

	recordAudit(r, "host.delete", domain, "deleted proxy host")
	streamManager.sync(getSnap().StreamProxies)
	writeJSON(w, 200, apiResp{OK: true})
}

type certUpsertReq struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	AutoGenerate bool   `json:"auto_generate"`
	AutoRenew    bool   `json:"auto_renew"`
	RenewDays    int    `json:"renew_days"`
	Domain       string `json:"domain"`
}

func adminAPICertUpsertJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "editor") {
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	var req certUpsertReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid json"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "certificate name required"})
		return
	}
	domain := normalizeHost(req.Domain)
	if req.Type != "letsencrypt" && req.Type != "custom" {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid certificate type"})
		return
	}
	if req.Type != "letsencrypt" || !req.AutoGenerate {
		writeJSON(w, 400, apiResp{OK: false, Error: "for custom/manual certs use the upload endpoint"})
		return
	}
	if domain == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "domain required for Let's Encrypt"})
		return
	}
	if err := validateHostnameStrict(domain); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid domain: " + err.Error()})
		return
	}
	if req.RenewDays < 0 {
		writeJSON(w, 400, apiResp{OK: false, Error: "renew_days must be positive"})
		return
	}
	if req.AutoRenew && req.RenewDays == 0 {
		req.RenewDays = 7
	}
	mu.Lock()
	if existing, ok := mcfg.Certs[name]; ok {
		if existing.CertPath != "" {
			_ = os.Remove(existing.CertPath)
		}
		if existing.KeyPath != "" {
			_ = os.Remove(existing.KeyPath)
		}
	}
	mcfg.Certs[name] = CertConfig{
		Type:         req.Type,
		AutoGenerate: req.AutoGenerate,
		AutoRenew:    req.AutoRenew,
		RenewDays:    req.RenewDays,
		Domain:       domain,
		CertPath:     "",
		KeyPath:      "",
	}
	if err := saveConfigToDiskLocked(); err != nil {
		mu.Unlock()
		logError("failed to save config after cert upsert", err)
		writeJSON(w, 500, apiResp{OK: false, Error: "failed to save config"})
		return
	}
	publishSnapshotLocked()
	mu.Unlock()
	recordAudit(r, "cert.upsert", name, "updated certificate configuration")
	triggerLECertIssuanceFor(domain, name)
	writeJSON(w, 200, apiResp{OK: true})
}

func adminAPICertUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "editor") {
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "bad upload"})
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	certType := strings.TrimSpace(r.FormValue("type"))
	autoGenerate := r.FormValue("auto_generate") == "true"
	autoRenew := r.FormValue("auto_renew") == "true"
	renewDays := 0
	if v := strings.TrimSpace(r.FormValue("renew_days")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			renewDays = parsed
		} else {
			writeJSON(w, 400, apiResp{OK: false, Error: "invalid renew_days"})
			return
		}
	}
	if name == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "certificate name required"})
		return
	}
	if certType != "custom" && certType != "letsencrypt" {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid certificate type"})
		return
	}
	if certType != "letsencrypt" {
		autoGenerate = false
		autoRenew = false
		renewDays = 0
	}
	if certType == "letsencrypt" && autoGenerate {
		writeJSON(w, 400, apiResp{OK: false, Error: "for auto-generate certs use the upsert endpoint"})
		return
	}
	if renewDays < 0 {
		writeJSON(w, 400, apiResp{OK: false, Error: "renew_days must be positive"})
		return
	}
	if autoRenew && renewDays == 0 {
		renewDays = 7
	}
	needsFiles := true
	var certPath, keyPath string
	if needsFiles {
		certFile, _, err := r.FormFile("cert_file")
		if err != nil {
			writeJSON(w, 400, apiResp{OK: false, Error: "cert_file required"})
			return
		}
		keyFile, _, err := r.FormFile("key_file")
		if err != nil {
			_ = certFile.Close()
			writeJSON(w, 400, apiResp{OK: false, Error: "key_file required"})
			return
		}
		defer certFile.Close()
		defer keyFile.Close()
		certBytes, err := io.ReadAll(certFile)
		if err != nil {
			writeJSON(w, 500, apiResp{OK: false, Error: "failed reading cert_file"})
			return
		}
		keyBytes, err := io.ReadAll(keyFile)
		if err != nil {
			writeJSON(w, 500, apiResp{OK: false, Error: "failed reading key_file"})
			return
		}
		if _, err := tls.X509KeyPair(certBytes, keyBytes); err != nil {
			writeJSON(w, 400, apiResp{OK: false, Error: "invalid cert/key pair: " + err.Error()})
			return
		}
		customDir := filepath.Join(cacheDir, "custom")
		if err := os.MkdirAll(customDir, 0700); err != nil {
			writeJSON(w, 500, apiResp{OK: false, Error: "failed creating cert directory"})
			return
		}
		certPath = filepath.Join(customDir, name+".cert.pem")
		keyPath = filepath.Join(customDir, name+".key.pem")
		if err := os.WriteFile(certPath, certBytes, 0600); err != nil {
			writeJSON(w, 500, apiResp{OK: false, Error: "failed writing cert"})
			return
		}
		if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
			_ = os.Remove(certPath)
			writeJSON(w, 500, apiResp{OK: false, Error: "failed writing key"})
			return
		}
	}
	mu.Lock()
	if existing, ok := mcfg.Certs[name]; ok && !needsFiles {
		if existing.CertPath != "" {
			_ = os.Remove(existing.CertPath)
		}
		if existing.KeyPath != "" {
			_ = os.Remove(existing.KeyPath)
		}
	}
	mcfg.Certs[name] = CertConfig{
		Type:         certType,
		AutoGenerate: autoGenerate,
		AutoRenew:    autoRenew,
		RenewDays:    renewDays,
		Domain:       "",
		CertPath:     certPath,
		KeyPath:      keyPath,
	}
	if err := saveConfigToDiskLocked(); err != nil {
		mu.Unlock()
		logError("failed to save config after cert upload", err)
		writeJSON(w, 500, apiResp{OK: false, Error: "failed to save config"})
		return
	}
	publishSnapshotLocked()
	mu.Unlock()
	recordAudit(r, "cert.upload", name, "uploaded certificate")
	writeJSON(w, 200, apiResp{OK: true})
}

type certDeleteReq struct {
	Name string `json:"name"`
}

func adminAPICertDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "editor") {
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	var req certDeleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid json"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "name required"})
		return
	}
	mu.Lock()
	if c, ok := mcfg.Certs[name]; ok {
		if c.CertPath != "" {
			_ = os.Remove(c.CertPath)
		}
		if c.KeyPath != "" {
			_ = os.Remove(c.KeyPath)
		}
		delete(mcfg.Certs, name)
	}
	for dom, hc := range mcfg.Hosts {
		if hc.CertName == name {
			hc.CertName = ""
			hc.AutoCert = false
			mcfg.Hosts[dom] = hc
		}
	}
	if err := saveConfigToDiskLocked(); err != nil {
		mu.Unlock()
		logError("failed to save config after cert delete", err)
		writeJSON(w, 500, apiResp{OK: false, Error: "failed to save config"})
		return
	}
	publishSnapshotLocked()
	mu.Unlock()
	recordAudit(r, "cert.delete", name, "deleted certificate")
	writeJSON(w, 200, apiResp{OK: true})
}

type userUpsertReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func adminAPIUserUpsert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	var req userUpsertReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid json"})
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "username required"})
		return
	}
	if req.Password == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "password required"})
		return
	}
	role := normalizeUserRole(req.Role)
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		logError("failed to hash password", err)
		writeJSON(w, 500, apiResp{OK: false, Error: "internal error"})
		return
	}
	mu.Lock()
	mcfg.Users[username] = UserConfig{Password: string(hash), Role: role}
	if err := saveConfigToDiskLocked(); err != nil {
		mu.Unlock()
		logError("failed to save config after user upsert", err)
		writeJSON(w, 500, apiResp{OK: false, Error: "failed to save config"})
		return
	}
	publishSnapshotLocked()
	mu.Unlock()
	recordAudit(r, "user.upsert", username, "created user")
	writeJSON(w, 200, apiResp{OK: true})
}

type userUpdateReq struct {
	Previous string `json:"previous"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func adminAPIUserUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	var req userUpdateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid json"})
		return
	}
	prev := strings.TrimSpace(req.Previous)
	username := strings.TrimSpace(req.Username)
	if prev == "" || username == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "previous and username required"})
		return
	}

	mu.Lock()
	existingUser, ok := mcfg.Users[prev]
	if !ok {
		mu.Unlock()
		writeJSON(w, 404, apiResp{OK: false, Error: "user not found"})
		return
	}
	if prev != username {
		if _, exists := mcfg.Users[username]; exists {
			mu.Unlock()
			writeJSON(w, 400, apiResp{OK: false, Error: "username already exists"})
			return
		}
		delete(mcfg.Users, prev)
	}
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			mu.Unlock()
			logError("failed to hash password", err)
			writeJSON(w, 500, apiResp{OK: false, Error: "internal error"})
			return
		}
		existingUser.Password = string(hash)
	}
	if req.Role != "" {
		existingUser.Role = normalizeUserRole(req.Role)
	}
	mcfg.Users[username] = existingUser
	if err := saveConfigToDiskLocked(); err != nil {
		mu.Unlock()
		logError("failed to save config after user update", err)
		writeJSON(w, 500, apiResp{OK: false, Error: "failed to save config"})
		return
	}
	publishSnapshotLocked()
	mu.Unlock()
	recordAudit(r, "user.update", username, "updated user")
	writeJSON(w, 200, apiResp{OK: true})
}

type userDeleteReq struct {
	Username string `json:"username"`
}

func adminAPIUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	var req userDeleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid json"})
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "username required"})
		return
	}
	mu.Lock()
	delete(mcfg.Users, username)
	if err := saveConfigToDiskLocked(); err != nil {
		mu.Unlock()
		logError("failed to save config after user delete", err)
		writeJSON(w, 500, apiResp{OK: false, Error: "failed to save config"})
		return
	}
	publishSnapshotLocked()
	mu.Unlock()
	recordAudit(r, "user.delete", username, "deleted user")
	writeJSON(w, 200, apiResp{OK: true})
}

type streamUpsertReq struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Listen   string `json:"listen"`
	Backend  string `json:"backend"`
	Enabled  bool   `json:"enabled"`
}

func adminAPIStreamUpsert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "editor") {
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	var req streamUpsertReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid json"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "name required"})
		return
	}
	protocol := strings.ToLower(strings.TrimSpace(req.Protocol))
	if protocol == "" {
		protocol = "tcp"
	}
	if protocol != "tcp" && protocol != "udp" {
		writeJSON(w, 400, apiResp{OK: false, Error: "protocol must be tcp or udp"})
		return
	}
	listen := strings.TrimSpace(req.Listen)
	if listen == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "listen address required"})
		return
	}
	if _, _, err := net.SplitHostPort(listen); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid listen address"})
		return
	}
	backend := strings.TrimSpace(req.Backend)
	if backend == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "backend required"})
		return
	}
	if _, _, err := net.SplitHostPort(backend); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid backend address"})
		return
	}
	cfg := StreamProxyConfig{
		Name:     name,
		Protocol: protocol,
		Listen:   listen,
		Backend:  backend,
		Enabled:  req.Enabled,
	}
	mu.Lock()
	found := false
	for i, existing := range mcfg.StreamProxies {
		if strings.EqualFold(existing.Name, name) {
			mcfg.StreamProxies[i] = cfg
			found = true
			break
		}
	}
	if !found {
		mcfg.StreamProxies = append(mcfg.StreamProxies, cfg)
	}
	if err := saveConfigToDiskLocked(); err != nil {
		mu.Unlock()
		logError("failed to save config after stream upsert", err)
		writeJSON(w, 500, apiResp{OK: false, Error: "failed to save config"})
		return
	}
	publishSnapshotLocked()
	mu.Unlock()
	recordAudit(r, "stream.upsert", name, "updated stream proxy")
	streamManager.sync(getSnap().StreamProxies)
	writeJSON(w, 200, apiResp{OK: true})
}

type streamDeleteReq struct {
	Name string `json:"name"`
}

func adminAPIStreamDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "editor") {
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	var req streamDeleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid json"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "name required"})
		return
	}
	mu.Lock()
	filtered := mcfg.StreamProxies[:0]
	for _, proxy := range mcfg.StreamProxies {
		if strings.EqualFold(proxy.Name, name) {
			continue
		}
		filtered = append(filtered, proxy)
	}
	mcfg.StreamProxies = filtered
	if err := saveConfigToDiskLocked(); err != nil {
		mu.Unlock()
		logError("failed to save config after stream delete", err)
		writeJSON(w, 500, apiResp{OK: false, Error: "failed to save config"})
		return
	}
	publishSnapshotLocked()
	mu.Unlock()
	recordAudit(r, "stream.delete", name, "deleted stream proxy")
	streamManager.sync(getSnap().StreamProxies)
	writeJSON(w, 200, apiResp{OK: true})
}

type pluginUpdateReq struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

func adminAPIPluginUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	var req pluginUpdateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid json"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "name required"})
		return
	}
	mu.Lock()
	plugin, ok := mcfg.Plugins[name]
	if !ok {
		plugin = PluginConfig{Name: name}
	}
	plugin.Enabled = req.Enabled
	mcfg.Plugins[name] = plugin
	if err := saveConfigToDiskLocked(); err != nil {
		mu.Unlock()
		logError("failed to save config after plugin update", err)
		writeJSON(w, 500, apiResp{OK: false, Error: "failed to save config"})
		return
	}
	publishSnapshotLocked()
	mu.Unlock()
	recordAudit(r, "plugin.update", name, fmt.Sprintf("enabled=%t", req.Enabled))
	writeJSON(w, 200, apiResp{OK: true})
}

type configImportReq struct {
	Format  string `json:"format"`
	Payload string `json:"payload"`
}

func marshalYAML(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var data any
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", err
	}
	var b strings.Builder
	writeYAML(&b, data, 0)
	return b.String(), nil
}

func writeYAML(b *strings.Builder, v any, indent int) {
	prefix := strings.Repeat("  ", indent)
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			b.WriteString(prefix)
			b.WriteString(key)
			b.WriteString(":")
			switch child := val[key].(type) {
			case map[string]any, []any:
				b.WriteString("\n")
				writeYAML(b, child, indent+1)
			default:
				b.WriteString(" ")
				b.WriteString(formatYAMLScalar(child))
				b.WriteString("\n")
			}
		}
	case []any:
		for _, item := range val {
			b.WriteString(prefix)
			b.WriteString("-")
			switch child := item.(type) {
			case map[string]any, []any:
				b.WriteString("\n")
				writeYAML(b, child, indent+1)
			default:
				b.WriteString(" ")
				b.WriteString(formatYAMLScalar(child))
				b.WriteString("\n")
			}
		}
	default:
		b.WriteString(prefix)
		b.WriteString(formatYAMLScalar(val))
		b.WriteString("\n")
	}
}

func formatYAMLScalar(v any) string {
	switch val := v.(type) {
	case nil:
		return "null"
	case string:
		if val == "" || strings.ContainsAny(val, ":\n#\"'") {
			return strconv.Quote(val)
		}
		return val
	case bool:
		if val {
			return "true"
		}
		return "false"
	case float64:
		if val == math.Trunc(val) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%v", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

func decodeConfigPayload(format string, payload []byte) ([]byte, error) {
	if format == "yaml" || format == "yml" {
		if json.Valid(payload) {
			return payload, nil
		}
		return nil, errors.New("yaml import supports JSON-compatible payloads only")
	}
	return payload, nil
}

func adminAPIConfigExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "viewer") {
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	mu.Lock()
	defer mu.Unlock()
	switch format {
	case "yaml", "yml":
		data, err := marshalYAML(mcfg)
		if err != nil {
			writeJSON(w, 500, apiResp{OK: false, Error: "failed to export yaml"})
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
		_, _ = w.Write([]byte(data))
	default:
		data, err := json.MarshalIndent(mcfg, "", "  ")
		if err != nil {
			writeJSON(w, 500, apiResp{OK: false, Error: "failed to export json"})
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(data)
	}
}

func adminAPIConfigImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	var req configImportReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid json"})
		return
	}
	payload := strings.TrimSpace(req.Payload)
	if payload == "" {
		writeJSON(w, 400, apiResp{OK: false, Error: "payload required"})
		return
	}
	format := strings.ToLower(strings.TrimSpace(req.Format))
	raw := []byte(payload)
	decoded, err := decodeConfigPayload(format, raw)
	if err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: err.Error()})
		return
	}
	raw = decoded
	cfg, _, err := decodeConfigBytes(raw)
	if err != nil {
		writeJSON(w, 400, apiResp{OK: false, Error: "invalid config payload"})
		return
	}
	mu.Lock()
	mcfg = cfg
	if err := saveConfigToDiskLocked(); err != nil {
		mu.Unlock()
		logError("failed to save config after import", err)
		writeJSON(w, 500, apiResp{OK: false, Error: "failed to save config"})
		return
	}
	cleanupUnusedCertFilesLocked()
	publishSnapshotLocked()
	mu.Unlock()
	recordAudit(r, "config.import", "config", "imported configuration")
	streamManager.sync(getSnap().StreamProxies)
	writeJSON(w, 200, apiResp{OK: true})
}

func adminAPIAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, apiResp{OK: false, Error: "method not allowed"})
		return
	}
	if !requireRole(w, r, "viewer") {
		return
	}
	writeJSON(w, 200, map[string]any{
		"logs": audits.list(),
	})
}

func adminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			adminLoginHandler(w, r)
			return
		}
		s := getSnap()
		if len(s.Users) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		user := getSession(r)
		if user == "" {
			returnURL := r.URL.String()
			http.Redirect(w, r, "/login?return="+url.QueryEscape(returnURL), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func adminLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}
		u := r.FormValue("user")
		p := r.FormValue("pass")
		s := getSnap()
		if checkUser(u, p, s) {
			setSession(w, r, u)
			red := r.FormValue("return")
			if red == "" {
				red = "/admin"
			}
			http.Redirect(w, r, red, http.StatusFound)
			return
		}
		serveAdminLoginForm(w, r, "Invalid credentials")
		return
	}
	serveAdminLoginForm(w, r, "")
}

func buildFallbackLoginHTML(host, action, returnURL, errorMsg string) string {
	escapedHost := html.EscapeString(host)
	escapedAction := html.EscapeString(action)
	escapedReturn := html.EscapeString(returnURL)
	var errorBlock string
	if errorMsg != "" {
		errorBlock = fmt.Sprintf("<p style='color:#b42318;'>%s</p>", html.EscapeString(errorMsg))
	}
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login - %s</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 400px; margin: 4rem auto; padding: 0 1.5rem; }
    form { display: flex; flex-direction: column; gap: 1rem; }
    input { padding: 0.6rem 0.7rem; font-size: 1rem; border-radius: 8px; border: 1px solid #d0d5dd; }
    button { padding: 0.75rem; font-size: 1rem; border-radius: 8px; border: 1px solid #d0d5dd; background: #2563eb; color: #fff; cursor: pointer; }
  </style>
</head>
<body>
  <h2>Login required for %s</h2>
  %s
  <form method="post" action="%s">
    <input type="hidden" name="return" value="%s">
    <label>Username<br><input type="text" name="user" autocomplete="username" required></label>
    <label>Password<br><input type="password" name="pass" autocomplete="current-password" required></label>
    <button type="submit">Login</button>
  </form>
</body>
</html>`, escapedHost, escapedHost, errorBlock, escapedAction, escapedReturn)
}

func renderTemplateWithFallback(w http.ResponseWriter, data any, fallbackHTML string) {
	var buf bytes.Buffer
	if err := uiTmpl.Execute(&buf, data); err != nil {
		logError("failed to render login template", err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(fallbackHTML))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func serveAdminLoginForm(w http.ResponseWriter, r *http.Request, errorMsg string) {
	returnURL := r.URL.Query().Get("return")
	if returnURL == "" {
		returnURL = "/admin"
	}

	var errorHTML template.HTML
	if errorMsg != "" {
		errorHTML = template.HTML(fmt.Sprintf("<p style='color:red;'>%s</p>", html.EscapeString(errorMsg)))
	}

	data := struct {
		IsLogin   bool
		Host      string
		ErrorMsg  template.HTML
		ReturnURL string
		Action    string
	}{
		IsLogin:   true,
		Host:      "Admin Panel",
		ErrorMsg:  errorHTML,
		ReturnURL: returnURL,
		Action:    "/login",
	}

	fallback := buildFallbackLoginHTML("Admin Panel", "/login", returnURL, errorMsg)
	renderTemplateWithFallback(w, data, fallback)
}

func serveLoginForm(w http.ResponseWriter, r *http.Request, host, errorMsg string) {
	returnURL := r.URL.Query().Get("return")
	if returnURL == "" {
		returnURL = "/"
	}

	var errorHTML template.HTML
	if errorMsg != "" {
		errorHTML = template.HTML(fmt.Sprintf("<p style='color:red;'>%s</p>", html.EscapeString(errorMsg)))
	}

	data := struct {
		IsLogin   bool
		Host      string
		ErrorMsg  template.HTML
		ReturnURL string
		Action    string
	}{
		IsLogin:   true,
		Host:      html.EscapeString(host),
		ErrorMsg:  errorHTML,
		ReturnURL: returnURL,
		Action:    "/_proxy_login",
	}

	fallback := buildFallbackLoginHTML(host, "/_proxy_login", returnURL, errorMsg)
	renderTemplateWithFallback(w, data, fallback)
}

func setSession(w http.ResponseWriter, r *http.Request, user string) {
	h := hmac.New(sha256.New, csrfK)
	h.Write([]byte(user))
	sig := base64.StdEncoding.EncodeToString(h.Sum(nil))
	secure := r.TLS != nil ||
		strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") ||
		strings.EqualFold(r.Header.Get("X-Forwarded-Ssl"), "on")
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    user + "." + sig,
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func getSession(r *http.Request) string {
	c, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 {
		return ""
	}
	user, sig := parts[0], parts[1]
	h := hmac.New(sha256.New, csrfK)
	h.Write([]byte(user))
	expected := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if sig != expected {
		return ""
	}
	return user
}

func checkUser(username, password string, s *ConfigSnapshot) bool {
	user, ok := s.Users[username]
	if !ok {
		return false
	}
	if user.Password == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) == nil
}

func userRole(username string, s *ConfigSnapshot) string {
	if username == "" {
		return ""
	}
	user, ok := s.Users[username]
	if !ok {
		return ""
	}
	role := strings.TrimSpace(user.Role)
	if role == "" {
		return "admin"
	}
	return normalizeUserRole(role)
}

func roleRank(role string) int {
	switch strings.ToLower(role) {
	case "admin":
		return 3
	case "editor":
		return 2
	case "viewer":
		return 1
	default:
		return 0
	}
}

func normalizeUserRole(role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	switch role {
	case "admin", "editor", "viewer":
		return role
	default:
		return "viewer"
	}
}

func requireRole(w http.ResponseWriter, r *http.Request, role string) bool {
	s := getSnap()
	if len(s.Users) == 0 {
		return true
	}
	user := getSession(r)
	if roleRank(userRole(user, s)) < roleRank(role) {
		http.Error(w, "403 Forbidden - insufficient role", http.StatusForbidden)
		return false
	}
	return true
}

func logError(msg string, err error) {
	if err != nil {
		logger.Printf(`{"level":"error","msg":%q,"err":%q}`, msg, err.Error())
	}
}

func recordAudit(r *http.Request, action, target, detail string) {
	user := "system"
	if r != nil {
		if sessionUser := getSession(r); sessionUser != "" {
			user = sessionUser
		}
	}
	entry := auditEntry{
		Time:   time.Now().Format(time.RFC3339),
		User:   user,
		Action: action,
		Target: target,
		Detail: detail,
	}
	audits.add(entry)
	logger.Printf(`{"level":"info","msg":"audit","user":%q,"action":%q,"target":%q,"detail":%q}`, entry.User, entry.Action, entry.Target, entry.Detail)
}

func startHTTP3Server(handler http.Handler, port int, settings GlobalSettings) {
	_ = handler
	if settings.HTTP3Enabled {
		logger.Printf(`{"level":"warn","msg":"http3 support unavailable (build without quic module)","addr":%q}`, fmt.Sprintf(":%d/udp", port))
	}
}

func startHTTPServer(port int, handler http.Handler) {
	addr := fmt.Sprintf(":%d", port)
	logger.Printf(`{"level":"info","msg":"http listening","addr":%q}`, addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Fatal(srv.ListenAndServe())
}

func startHTTPSServer(port int, handler http.Handler) {
	addr := fmt.Sprintf(":%d", port)
	httpsSrv := &http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: getCertificate,
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       2 * time.Minute,
	}

	logger.Printf(`{"level":"info","msg":"https proxy listening","addr":%q}`, addr)
	log.Fatal(httpsSrv.ListenAndServeTLS("", ""))
}

func ensureWorkingDir() {
	if err := os.MkdirAll(workingDir, 0755); err != nil {
		log.Fatalf("Failed to create working dir: %v", err)
	}
	if err := os.Chdir(workingDir); err != nil {
		log.Fatalf("Failed to set working dir: %v", err)
	}
}

func main() {
	upgradeConfig := flag.Bool("upgrade-config", false, "Upgrade the config file and exit.")
	flag.Parse()

	ensureWorkingDir()
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		log.Fatalf("Failed to create cache dir: %v", err)
	}

	configExists := true
	if _, err := os.Stat(configFile); err != nil {
		if os.IsNotExist(err) {
			configExists = false
		} else {
			log.Fatalf("config check error: %v", err)
		}
	}

	changed, err := loadConfigFromDisk()
	if err != nil {
		log.Fatalf("loadConfig error: %v", err)
	}
	if *upgradeConfig {
		if !configExists {
			fmt.Println("No config file found; skipping upgrade.")
			return
		}
		if changed {
			fmt.Println("Config upgraded.")
		} else {
			fmt.Println("Config already up to date.")
		}
		return
	}
	if err := ensureAdminUser(); err != nil {
		log.Fatalf("ensure admin error: %v", err)
	}

	mu.Lock()
	cleanupUnusedCertFilesLocked()
	publishSnapshotLocked()
	mu.Unlock()
	streamManager.sync(getSnap().StreamProxies)

	go func() {
		for {
			time.Sleep(24 * time.Hour)
			s := getSnap()
			for _, domain := range s.LEHosts {
				hello := &tls.ClientHelloInfo{ServerName: domain}
				if _, err := certManager.GetCertificate(hello); err != nil {
					logger.Printf(`{"level":"warn","msg":"autocert warmup failed","host":%q,"err":%q}`, domain, err.Error())
				}
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go startHealthChecker(ctx)

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/admin", adminIndexHandler)
	adminMux.HandleFunc("/admin/api/config", adminAPIConfigHandler)
	adminMux.HandleFunc("/admin/api/logs", adminAPILogsHandler)
	adminMux.HandleFunc("/admin/api/logs/level", adminAPILogLevelHandler)
	adminMux.HandleFunc("/admin/api/logs/clear", adminAPILogsClearHandler)
	adminMux.HandleFunc("/admin/api/audit", adminAPIAuditLogs)
	adminMux.HandleFunc("/admin/api/host/upsert", adminAPIHostUpsert)
	adminMux.HandleFunc("/admin/api/host/delete", adminAPIHostDelete)
	adminMux.HandleFunc("/admin/api/stream/upsert", adminAPIStreamUpsert)
	adminMux.HandleFunc("/admin/api/stream/delete", adminAPIStreamDelete)
	adminMux.HandleFunc("/admin/api/cert/upsert", adminAPICertUpsertJSON)
	adminMux.HandleFunc("/admin/api/cert/upload", adminAPICertUpload)
	adminMux.HandleFunc("/admin/api/cert/delete", adminAPICertDelete)
	adminMux.HandleFunc("/admin/api/plugins/update", adminAPIPluginUpdate)
	adminMux.HandleFunc("/admin/api/config/export", adminAPIConfigExport)
	adminMux.HandleFunc("/admin/api/config/import", adminAPIConfigImport)
	adminMux.HandleFunc("/admin/api/user/upsert", adminAPIUserUpsert)
	adminMux.HandleFunc("/admin/api/user/update", adminAPIUserUpdate)
	adminMux.HandleFunc("/admin/api/user/delete", adminAPIUserDelete)
	adminMux.HandleFunc("/login", adminLoginHandler)
	adminMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	})

	go func() {
		logger.Printf(`{"level":"info","msg":"admin ui listening","addr":":8081","note":"remote access enabled; consider firewalling"}`)
		srv := &http.Server{
			Addr:              ":8081",
			Handler:           adminAuthMiddleware(adminMux),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       2 * time.Minute,
		}
		log.Fatal(srv.ListenAndServe())
	}()

	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/", httpsHandler)

	settings := getSnap().Settings
	plainHandler := accessLogMiddleware(http.HandlerFunc(httpHandler))
	for _, port := range settings.HTTPPorts {
		go startHTTPServer(port, plainHandler)
	}

	proxyHandler := accessLogMiddleware(proxyMux)
	for _, port := range settings.HTTPSPorts {
		go startHTTP3Server(proxyHandler, port, settings)
		go startHTTPSServer(port, proxyHandler)
	}

	select {}
}
