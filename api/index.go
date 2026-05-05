package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	dnsJson = "application/dns-json"
	dnsMsg  = "application/dns-message"
)

var (
	cidrArr    []*net.IPNet
	httpClient *http.Client
)

var (
	path    = "/dns-query"
	doh     = "https://1.1.1.1/dns-query"
	dohJson = "https://1.1.1.1/dns-query"
)

func init() {
	if env, b := os.LookupEnv("DOH_QUERY_PATH"); b && env != "" {
		path = env
	}
	if env, b := os.LookupEnv("DOH_QUERY_URL"); b && env != "" {
		doh = env
	}
	if env, b := os.LookupEnv("DOH_QUERY_JSON_URL"); b && env != "" {
		dohJson = env
	}

	maxCidrBlocks := []string{
		"127.0.0.1/8",    // localhost
		"10.0.0.0/8",     // 24-bit block
		"172.16.0.0/12",  // 20-bit block
		"192.168.0.0/16", // 16-bit block
		"169.254.0.0/16", // link local address
		"::1/128",        // localhost IPv6
		"fc00::/7",       // unique local address IPv6
		"fe80::/10",      // link local address IPv6
	}
	cidrArr = make([]*net.IPNet, len(maxCidrBlocks))
	for i, maxCidrBlock := range maxCidrBlocks {
		_, cidr, _ := net.ParseCIDR(maxCidrBlock)
		cidrArr[i] = cidr
	}

	httpClient = &http.Client{
		Timeout: time.Second * 3,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{
					KeepAlive: 60 * time.Second,
				}
				return dialer.DialContext(ctx, network, addr)
			},
			MaxIdleConns:        150,
			MaxIdleConnsPerHost: 50,
			MaxConnsPerHost:     100,
			IdleConnTimeout:     60 * time.Second,
			ForceAttemptHTTP2:   true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != path {
		http.NotFound(w, r)
		return
	}

	method := r.Method
	if method == http.MethodGet && r.URL.Query().Has("dns") {
		get(w, r)
		return
	} else if method == http.MethodGet && r.Header.Get("Accept") == dnsJson {
		getJson(w, r)
		return
	} else if method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), dnsMsg) {
		post(w, r)
		return
	}

	http.NotFound(w, r)
}

func get(w http.ResponseWriter, r *http.Request) {
	api := fmt.Sprintf("%s?dns=%s", doh, r.URL.Query().Get("dns"))
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, api, nil)
	if err != nil {
		log.Printf("new request failed: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	req.Header.Set("Accept", dnsMsg)
	req.Header.Set("X-Forwarded-For", realIp(r))

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("do request failed: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	defer closeResp(resp)
	relayResponse(w, resp)
}

func getJson(w http.ResponseWriter, r *http.Request) {
	api := fmt.Sprintf("%s?%s", dohJson, r.URL.RawQuery)
	req, err := http.NewRequest(http.MethodGet, api, nil)
	if err != nil {
		log.Printf("new request failed: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	req.Header.Set("Accept", dnsJson)
	req.Header.Set("X-Forwarded-For", realIp(r))

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("do request failed: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	defer closeResp(resp)
	relayResponse(w, resp)
}

func post(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("read request body failed: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, doh, bytes.NewReader(body))
	if err != nil {
		log.Printf("new request failed: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	req.Header.Set("Accept", dnsMsg)
	req.Header.Set("Content-Type", dnsMsg)
	req.Header.Set("X-Forwarded-For", realIp(r))

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("do request failed: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	defer closeResp(resp)
	relayResponse(w, resp)
}

func relayResponse(w http.ResponseWriter, resp *http.Response) {
	if resp == nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = dnsMsg
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(resp.StatusCode)

	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("copy response body failed: %v", err)
	}
}

func closeResp(resp *http.Response) {
	if resp != nil {
		if err := resp.Body.Close(); err != nil {
			log.Printf("close response body failed: %v", err)
		}
	}
}

// https://github.com/tomasen/realip/blob/master/realip.go
func realIp(r *http.Request) string {
	xRealIP := r.Header.Get("X-Real-Ip")
	xForwardedFor := r.Header.Get("X-Forwarded-For")

	if xRealIP == "" && xForwardedFor == "" {
		var remoteIP string
		if strings.ContainsRune(r.RemoteAddr, ':') {
			remoteIP, _, _ = net.SplitHostPort(r.RemoteAddr)
		} else {
			remoteIP = r.RemoteAddr
		}

		return remoteIP
	}

	for _, address := range strings.Split(xForwardedFor, ",") {
		address = strings.TrimSpace(address)
		isPrivate, err := isPrivateAddress(address)
		if !isPrivate && err == nil {
			return address
		}
	}

	return xRealIP
}

func isPrivateAddress(address string) (bool, error) {
	ipAddress := net.ParseIP(address)
	if ipAddress == nil {
		return false, errors.New("address is not valid")
	}

	for i := range cidrArr {
		if cidrArr[i].Contains(ipAddress) {
			return true, nil
		}
	}

	return false, nil
}
