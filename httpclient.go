package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var httpc *http.Client
var faviconCache = sync.Map{} // host -> hash
func initHTTPClient(timeout time.Duration, skipVerify bool) {
	httpc = &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			MaxIdleConns:        500,
			IdleConnTimeout:     20 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify, MinVersion: tls.VersionTLS10,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					// 👇 加上 CBC 的老套件
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA}},
		},
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 { // 默认跟随最多10次，避免循环
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// getRedirectURL 会请求目标 URL，如果返回 403/401，则尝试解析前端跳转，返回最终 URL

// getRedirectURL 会请求目标 URL，如果返回 403/401，则尝试解析前端跳转，返回最终 URL
//
//	func getRedirectURL(ctx context.Context, target string) string {
//		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
//		if err != nil {
//			return target
//		}
//		req.Header.Set("User-Agent", "Mozilla/5.0 ...")
//
//		resp, err := httpc.Do(req)
//		if err != nil || resp == nil {
//			return target
//		}
//		defer resp.Body.Close()
//
//		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
//		bodyStr := string(body)
//		finalURL := target
//
//		// 定义所有可能的重定向正则表达式
//		redirectRegexes := []*regexp.Regexp{
//			// 匹配 <meta> 标签中的跳转
//			regexp.MustCompile(`(?i)<meta[^>]+url=['"]?([^'">]+)['"]?`),
//			// 匹配 window.top.location 和 window.location
//			regexp.MustCompile(`(?i)window\.(?:location|top\.location)(?:\.href)?\s*=\s*['"]([^'"]+)['"]`),
//			// 匹配 <frame> 和 <frameset> 标签
//			regexp.MustCompile(`(?i)<(?:frameset|frame)[^>]+src=['"]?([^'"]+)['"]?`),
//		}
//
//		// 循环遍历所有正则表达式进行匹配
//		for _, re := range redirectRegexes {
//			if matches := re.FindStringSubmatch(bodyStr); len(matches) == 2 {
//				finalURL = strings.TrimSpace(matches[1])
//				// 匹配成功，跳出循环
//				break
//			}
//		}
//
//		/// 如果没有任何匹配，返回原始URL
//		if finalURL == target {
//			return target
//		}
//
//		// 拼接成完整 URL
//		parsedTarget, err := url.Parse(target)
//		if err != nil {
//			return target
//		}
//		parsedFinal, err := url.Parse(finalURL)
//		if err != nil {
//			return target
//		}
//
//		if !parsedFinal.IsAbs() {
//			// 相对路径拼接成完整 URL
//			finalURL = parsedTarget.Scheme + "://" + parsedTarget.Host + parsedFinal.Path
//			if parsedFinal.RawQuery != "" {
//				finalURL += "?" + parsedFinal.RawQuery
//			}
//		}
//
//		return finalURL
//	}
func getRedirectURL(ctx context.Context, target string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return target
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 ...")

	// 不让 http.Client 自动跟随 301/302，这样我们才能自己拿 Location 头
	httpc := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 阻止自动跳转
		},
	}

	resp, err := httpc.Do(req)
	if err != nil || resp == nil {
		return target
	}
	defer resp.Body.Close()

	// 如果状态码是 301/302，就解析 Location 头
	if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound {
		loc := resp.Header.Get("Location")
		if loc == "" {
			return target
		}

		parsedTarget, err := url.Parse(target)
		if err != nil {
			return target
		}
		parsedLoc, err := url.Parse(loc)
		if err != nil {
			return target
		}

		// 如果是相对路径，拼接成绝对路径
		if !parsedLoc.IsAbs() {
			loc = parsedTarget.ResolveReference(parsedLoc).String()
		}

		return loc
	}

	// --------- 以下是 403/401 前端跳转解析 ----------
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	bodyStr := string(body)
	finalURL := target

	redirectRegexes := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<meta[^>]+url=['"]?([^'">]+)['"]?`),
		regexp.MustCompile(`(?i)window\.(?:location|top\.location)(?:\.href)?\s*=\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`(?i)<(?:frameset|frame)[^>]+src=['"]?([^'"]+)['"]?`),
	}

	for _, re := range redirectRegexes {
		if matches := re.FindStringSubmatch(bodyStr); len(matches) == 2 {
			finalURL = strings.TrimSpace(matches[1])
			break
		}
	}

	if finalURL == target {
		return target
	}

	parsedTarget, err := url.Parse(target)
	if err != nil {
		return target
	}
	parsedFinal, err := url.Parse(finalURL)
	if err != nil {
		return target
	}

	if !parsedFinal.IsAbs() {
		finalURL = parsedTarget.ResolveReference(parsedFinal).String()
	}

	return finalURL
}
