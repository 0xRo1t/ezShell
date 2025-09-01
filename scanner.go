package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html/charset"
)

// 扫描任务
type scanTask struct {
	Index int
	URL   string
}

// 扫描结果
type scanResult struct {
	InputURL string   `json:"input_url"` // 原始 URL
	FinalURL string   `json:"final_url"` // 带路径的 URL
	Status   string   `json:"status"`    // HTTP 状态码
	Title    string   `json:"title"`     // 页面标题
	Matches  []string `json:"matches"`   // 指纹匹配结果
	Path     string   `json:"path"`      // 匹配路径
	Err      string   `json:"err"`       // 错误信息
	Body     string   `json:"-"`
	BodyLen  int      `json:"body_len"`
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	urls := splitLines(r.URL.Query().Get("urls"))
	if len(urls) == 0 {
		http.Error(w, "no urls provided", 400)
		return
	}

	// 为本次扫描创建所有必需的通道
	fingerprintTaskCh := make(chan string, 100)
	fingerprintResultCh := make(chan scanResult, 100)
	nucleiTaskQueue := make(chan ScanTask, 100)
	taskDoneCh := make(chan bool) // 为本次扫描创建新的状态通道

	var nucleiWg sync.WaitGroup

	// 启动本次扫描所需的所有工作协程，并将新的通道传递给它们
	go startFingerprintWorkers(config.Concurrency, fingerprintTaskCh, fingerprintResultCh, taskDoneCh)
	//go startNucleiWorkers(config.NucleiConcurrency, nucleiTaskQueue, &nucleiWg, taskDoneCh)
	go startNucleiWorkers(config.NucleiConcurrency, nucleiTaskQueue, &nucleiWg, taskDoneCh)
	go startResultProcessor(fingerprintResultCh, nucleiTaskQueue, &nucleiWg, taskDoneCh)
	go statusUpdater(taskDoneCh)

	// 重置全局状态
	globalState.mu.Lock()
	globalState.Total = len(urls)
	globalState.Done = 0
	globalState.Status = "扫描中"
	globalState.start = time.Now()
	globalState.mu.Unlock()

	// 将所有 URL 任务发送到指纹扫描队列，然后立即返回
	go func() {
		for _, u := range urls {
			fingerprintTaskCh <- u
		}
		close(fingerprintTaskCh)
	}()

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "[+] Scan tasks submitted. Check the database for results.")
}

// scanOne 扫描单个 URL + pathList
// 这里的第二个参数 raw  其实就是url
func scanOne(ctx context.Context, raw string) []scanResult {
	// 这里去除空格
	in := strings.TrimSpace(raw)
	// 这里利用 ensureHTTP 对 url添加http:// https:// 头
	target := ensureHTTP(in)

	redirect_target := getRedirectURL(ctx, target)
	//fmt.Printf("【+】原url [%s]  跳转url [%s]\n", target, redirect_target)

	var results []scanResult
	// 这里对跳转的url扫描
	mainRes_redirect := scanURL(ctx, redirect_target, in, "")
	results = append(results, mainRes_redirect)
	if strings.Contains(mainRes_redirect.Err, "Connection") {
		fmt.Printf("链接失败 [%s] %s\n", mainRes_redirect.FinalURL, mainRes_redirect.Err)
		return results
	}

	// ============ 新增逻辑：提取所有 <a href="..."> 链接 ============
	req, err := http.NewRequestWithContext(ctx, "GET", redirect_target, nil)
	if err != nil {
		return results
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 ...")

	resp, err := httpc.Do(req)
	if err != nil || resp == nil {
		return results
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	bodyStr := string(body)

	// 匹配所有 <a href="...">
	re := regexp.MustCompile(`(?i)<a[^>]+href=['"]?([^'">]+)['"]?`)
	matches := re.FindAllStringSubmatch(bodyStr, -1)

	parsedBase, _ := url.Parse(redirect_target)
	visited := make(map[string]bool)

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		link := strings.TrimSpace(m[1])
		if link == "" {
			continue
		}

		// 转换成绝对路径
		parsedLink, err := url.Parse(link)
		if err != nil {
			continue
		}
		if !parsedLink.IsAbs() {
			link = parsedBase.ResolveReference(parsedLink).String()
		}

		// 去重
		if visited[link] {
			continue
		}
		visited[link] = true

		//fmt.Printf("【发现子链接】 %s\n", link)
		// 这里需要对子链接判断跳转，因为发现了一些 子链接也是会 302跳转 然后有资产的
		redirect_target1 := getRedirectURL(ctx, link)
		// 调用 scanURL 扫描子链接
		subRes := scanURL(ctx, link, in, "")
		sub_redit := scanURL(ctx, redirect_target1, in, "")
		results = append(results, subRes)
		results = append(results, sub_redit)
	}
	//===============
	// 根 URL 扫描
	mainRes := scanURL(ctx, target, in, "")
	results = append(results, mainRes)
	if strings.Contains(mainRes.Err, "Connection") {
		fmt.Printf("链接失败 [%s] %s\n", mainRes.FinalURL, mainRes.Err)
		return results
	}

	rootBodyLen := len(mainRes.Body)

	// 根url + path扫描
	for _, p := range pathList {
		fullURL := strings.TrimRight(target, "/") + p
		//fmt.Printf("扫描 ==== %s\n", fullURL)
		pathRes := scanURL(ctx, fullURL, in, p)
		if len(pathRes.Body) == rootBodyLen {
			//fmt.Printf("[-] drop %s, len(/) = len(%s) (%d)\n", fullURL, p, rootBodyLen)
			continue
		}
		// 只返回可访问的路径或状态码为 200/401/403
		//if pathRes.Status == "200" || pathRes.Status == "401" || pathRes.Status == "403" {
		results = append(results, pathRes)

	}

	//for i, r := range results {
	//	matches := strings.Join(r.Matches, ", ")
	//	fmt.Printf("[%d] FinalURL: %s| inputurl: [%s] | Status: %s | Title: %s | Matches: %s | Err: %s\n",
	//		i, r.FinalURL, r.InputURL, r.Status, r.Title, matches, r.Err)
	//
	//}
	return results
}

func decodeToUTF8(contentType string, body []byte) (string, error) {
	reader, err := charset.NewReader(bytes.NewReader(body), contentType)
	if err != nil {
		return string(body), err
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return string(body), err
	}
	return string(decoded), nil
}

// scanURL 对单个 URL 或路径进行扫描 + 指纹匹配
func scanURL(ctx context.Context, target string, input string, path string) scanResult {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	//fmt.Println("drop by Connection failed")
	if err != nil {
		//return scanResult{
		//	InputURL: input,
		//	FinalURL: target,
		//	Status:   "drop by Connection failed",
		//	Err:      err.Error(),
		//	Path:     path,
		//}
		return scanResult{
			InputURL: input,
			FinalURL: target,
			Status:   "drop by Connection failed",
			Title:    "",
			Matches:  nil,
			Path:     path,
			Err:      "drop by Connection failed",
		}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36")

	// 这里是连接失败的
	resp, err := httpc.Do(req)
	if err != nil || resp == nil {
		//fmt.Printf("[-] Error scanning %s: %v | drop by Connection failed\n", target, err) // 添加调试日志
		//return scanResult{
		//	InputURL: input,
		//	FinalURL: target,
		//	Status:   "Connection failed",
		//	Err:      "drop by Connection failed",
		//	Path:     path,
		//}
		return scanResult{
			InputURL: input,
			FinalURL: target,
			Status:   "drop by Connection failed",
			Title:    "",
			Matches:  nil,
			Path:     path,
			Err:      "drop by Connection failed",
		}
	}
	defer resp.Body.Close()

	//finalURL := resp.Request.URL.String()
	status := fmt.Sprintf("%d", resp.StatusCode)
	headers := flattenHeaders(resp.Header)

	var body []byte
	var title string

	// 移除 io.LimitReader，直接读取全部响应体
	//body, _ = io.ReadAll(resp.Body)  // 这个是读取全部的body了
	const maxBodySize = 2 * 1024 * 1024 // 2MB
	limitedReader := io.LimitReader(resp.Body, maxBodySize)
	body, _ = io.ReadAll(limitedReader) // 这里是读取2mb的body

	bodyUTF8, _ := decodeToUTF8(resp.Header.Get("Content-Type"), body)
	title = extractTitleWithEncoding(resp, body)

	if path == "" {
		if len(body) == 0 || len(bodyUTF8) == 0 {
			//fmt.Printf("[-] %s Body 长度为 0，丢弃\n", target)

			return scanResult{
				InputURL: input,
				FinalURL: target,
				Status:   status,
				Path:     "/",
				Err:      "drop by 0 body",
			}
		}

		for _, code := range errorStatusCodes {
			if resp.StatusCode == code {
				//fmt.Printf("[-] %s 过滤状态码 【%d】\n", target, code)
				return scanResult{
					InputURL: input,
					FinalURL: target,
					Status:   status,
					Path:     "/",
					Err:      "drop by status code",
				}
			}
		}
	}

	if path != "" {
		if len(body) == 0 || len(bodyUTF8) == 0 {
			//fmt.Printf(" %s Body 长度为 0，丢弃\n", target)
			return scanResult{
				InputURL: input,
				FinalURL: target,
				Status:   status,
				Path:     path,
				Err:      "drop by 0 body",
			}
		}
		lcBody := strings.ToLower(string(body))
		lcBody_uft8 := strings.ToLower(string(bodyUTF8))

		// fmt.Printf("Normalized response body length: %d\n", len(lcBody))
		// fmt.Printf("Normalized response body (start):\n%s\n", lcBody[:min(len(lcBody), 200)]) // 打印前200个字符
		// fmt.Printf("Normalized response body (end):\n%s\n", lcBody[max(0, len(lcBody)-200):]) // 打印后200个字符

		for _, code := range errorStatusCodes {

			if resp.StatusCode == code {
				//fmt.Printf("[-] %s 过滤状态码 【%d】\n", target, code)
				return scanResult{
					InputURL: input,
					FinalURL: target,
					Status:   status,
					Path:     path,
					Err:      "drop by status code",
				}
			}
		}

		// 根据 ez.conf 里面的 error_keywords 过滤
		for _, kw := range errorKeywords {

			if strings.Contains(lcBody, strings.ToLower(kw)) || strings.Contains(lcBody_uft8, strings.ToLower(kw)) {
				//fmt.Printf("[-] %s 过滤 关键词 【%s】\n", target, kw)
				return scanResult{
					InputURL: input,
					FinalURL: target,
					Status:   status,
					Path:     path,
					Err:      "drop by error_keywords",
				}
			}
		}

	}

	// 指纹匹配（与逻辑：所有 keyword 必须匹配）
	matches := []string{}
	lcBody := strings.ToLower(string(body))
	for _, f := range config.Fingerprint {
		if len(f.Keyword) == 0 {
			continue
		}
		switch f.Method {
		case "keyword":
			switch f.Location {
			case "header":
				// header 与逻辑
				allMatched := true
				for _, kw := range f.Keyword {
					kw = strings.TrimSpace(kw)
					if kw == "" {
						continue
					}
					if !strings.Contains(headers, kw) {
						allMatched = false
						break
					}
				}
				if allMatched {
					matches = append(matches, f.CMS)
				}
			case "title":
				// title 与逻辑
				allMatched := true
				for _, kw := range f.Keyword {
					kw = strings.TrimSpace(kw)
					if kw == "" {
						continue
					}
					if !strings.Contains(strings.ToLower(title), strings.ToLower(kw)) {
						allMatched = false
						break
					}
				}
				if allMatched {
					matches = append(matches, f.CMS)
				}
			default: // body 与逻辑
				allMatched := true
				for _, kw := range f.Keyword {
					kw = strings.TrimSpace(kw)
					if kw == "" {
						continue // 跳过空字符串
					}
					if !strings.Contains(lcBody, strings.ToLower(kw)) {
						allMatched = false
						break
					}
				}
				if allMatched {
					matches = append(matches, f.CMS)
				}
			}
		case "faviconhash":
			if v, ok := faviconCache.Load(target); ok && anyEquals(f.Keyword, v.(string)) {
				matches = append(matches, f.CMS)
			}
		}
	}

	errMsg := ""
	if resp.StatusCode == 404 {
		errMsg = "页面 404，但匹配指纹"
	}

	// 核心改动：如果 path 不为空且没有匹配到指纹，则丢弃
	// ----------------------------------------------------
	//fmt.Printf("检查 match是不是空的")
	if path != "" && len(matches) == 0 {
		fmt.Printf("[-] %s%s 没有匹配到指纹，丢弃\n", input, path)
		return scanResult{
			InputURL: input,
			FinalURL: target,
			Matches:  matches, // 空切片
			Path:     path,
			Err:      "drop by no fingerprint match on path",
			BodyLen:  len(body),
		}
	}
	return scanResult{
		InputURL: input,
		FinalURL: target,
		Status:   status,
		Title:    title,
		Matches:  unique(matches),
		Path:     path,
		Err:      errMsg,
		Body:     string(body), // 内部判断用
		BodyLen:  len(body),    // 前端显示
	}
}
