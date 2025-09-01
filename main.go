package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Fingerprint struct {
	CMS      string   `json:"cms"`
	Keyword  []string `json:"keyword"`
	Location string   `json:"location"`
	Method   string   `json:"method"`
}

// 配置文件结构
type Config struct {
	Fingerprint []Fingerprint `json:"fingerprint"`
	// 并发数量不放在 JSON，而在 Go 默认设置
	Concurrency       int `json:"-"`
	NucleiConcurrency int `json:"-"` // 新增的 Nuclei 并发数量
	Timeout           time.Duration
}

func readConfFile(filename string) map[string]string {
	m := make(map[string]string)
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("读取配置失败: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		m[key] = value
	}
	return m
}
func parseBool(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	return s == "true" || s == "1" || s == "yes"
}

var config Config
var needBodyGlobal bool
var needFaviGlobal bool
var pathList []string
var username, password, port string
var needSkipVerifyGlobal bool
var errorKeywords []string
var errorStatusCodes []int
var nucleiTemplatesDir string
var nucleiExecPath string

func parseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
func loadPathList(file string) []string {
	f, err := os.Open(file)
	if err != nil {
		log.Printf("读取 path 文件失败: %v", err)
		return nil
	}
	defer f.Close()

	var paths []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			paths = append(paths, line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("读取 path 文件出错: %v", err)
	}
	return paths
}

type FingerprintFile struct {
	Fingerprint []Fingerprint `json:"fingerprint"`
}

// 加载指纹 JSON
func loadFingerPrint(filePath string) []Fingerprint {
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("打开指纹文件失败: %v", err)
	}
	defer f.Close()

	var fpFile FingerprintFile
	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&fpFile); err != nil {
		log.Fatalf("解析指纹文件失败: %v", err)
	}

	return fpFile.Fingerprint
}

func loadConfig() {
	confMap := readConfFile("ez.conf")

	// nuclei的路径设置
	nucleiExecPath = confMap["nuclei_exec_path"]
	nucleiTemplatesDir = confMap["nuclei_templates"]

	if nucleiExecPath == "" {
		log.Fatalf("错误: 未在 ez.conf 中配置 nuclei_exec_path。")
	}

	if nucleiTemplatesDir == "" {
		log.Println("警告: 未在 ez.conf 中配置 nuclei_templates，将跳过 nuclei 扫描功能。")
	} else {
		log.Println("正在加载 Nuclei 模板...")
		if err := InitNucleiTemplates(nucleiTemplatesDir); err != nil {
			log.Fatalf("加载 Nuclei 模板失败: %v", err)
		}
		log.Println("Nuclei 模板加载完成。")
	}
	// 基本配置
	username = confMap["username"]
	password = confMap["passwd"]
	port = confMap["port"]
	if port == "" {
		port = "60000"
	}

	// 全局变量  这里前两个参数实际上没用到 needBodyGlobal  needFaviGlobal
	needBodyGlobal = parseBool(confMap["need_body"])
	needFaviGlobal = parseBool(confMap["need_favicon"])
	config.Concurrency = parseInt(confMap["concurrency"])
	config.NucleiConcurrency = parseInt(confMap["nuclei_concurrency"])

	fmt.Println("线程数量", config.Concurrency)
	config.Timeout = time.Duration(parseInt(confMap["timeout"])) * time.Second
	pathList = loadPathList(confMap["path_file"])
	needSkipVerifyGlobal = parseBool(confMap["skip_verify"])
	config.Fingerprint = loadFingerPrint(confMap["finger_file"])
	if v, ok := confMap["error_keywords"]; ok {
		for _, k := range strings.Split(v, ",") {
			k = strings.TrimSpace(k)
			if k != "" {
				errorKeywords = append(errorKeywords, k)
			}
		}
	}

	// 状态码
	if v, ok := confMap["error_status_codes"]; ok {
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				code, err := strconv.Atoi(s)
				if err == nil {
					errorStatusCodes = append(errorStatusCodes, code)
				}
			}
		}
	}
}

// Basic Auth 包装
func basicAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != username || p != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// 包装静态文件服务器，要求登录
func authFileServer(dir http.Dir, prefix string) http.HandlerFunc {
	fs := http.StripPrefix(prefix, http.FileServer(dir))
	return basicAuth(func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})
}

// 主页处理
func handleIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/web/index.html", http.StatusFound)
}

// ================================================================
var (
	// 指纹扫描任务队列 (由 handleScan 生产)

	nucleiTasksAdded = make(map[string]bool)
	// 保护 map 的并发访问
	nucleiTasksMutex sync.Mutex
)

// =========================== 状态 =========================== ===========================
type scanState struct {
	Total   int     `json:"total"`
	Done    int     `json:"done"`
	Status  string  `json:"status"`
	Elapsed float64 `json:"elapsed"`
	mu      sync.Mutex
	start   time.Time
}

// 定义一个全局的状态实例，并用一个通道来接收任务完成信号
var globalState = &scanState{}

// 状态路由（由前端轮询）
func handleScanStatus(w http.ResponseWriter, r *http.Request) {
	globalState.mu.Lock()
	defer globalState.mu.Unlock()

	elapsed := time.Since(globalState.start).Seconds()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  globalState.Status,
		"done":    globalState.Done,
		"total":   globalState.Total,
		"elapsed": elapsed,
	})
}

// 状态更新器：一个独立的 goroutine 负责更新 globalState
func statusUpdater(taskDoneCh <-chan bool) {
	for {

		_, ok := <-taskDoneCh
		if !ok {
			break
		}
		// 收到信号后，安全地更新状态
		globalState.mu.Lock()
		globalState.Done++

		// 检查是否所有任务都已完成
		if globalState.Done == globalState.Total {
			globalState.Status = "扫描结束"
		}
		globalState.mu.Unlock()
	}
}

// =========================== 状态 =========================== ===========================
// 任务结构体
type ScanTask struct {
	URL  string
	Tags []string
}

// 生产指纹扫描结果到 fingerprintResultCh
func startFingerprintWorkers(numWorkers int, taskCh <-chan string, resultCh chan<- scanResult, taskDoneCh chan<- bool) {
	var wg sync.WaitGroup
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			for url := range taskCh { // 从指纹队列里 遍历，这里拿出来一个 url 之后这个url就不在队列里面了，不需要清理
				results := scanOne(context.Background(), url)

				for _, r := range results {
					resultCh <- r // 这里把 指纹结果 r  放在 队列里面
				}
				// 在这里发送一个信号，表示一个URL的指纹扫描任务完成
				taskDoneCh <- true // 新家的
			}
		}()
	}
	// 启动一个 goroutine，在所有 worker 完成后关闭结果通道
	go func() {
		wg.Wait()
		close(resultCh)
	}()
}

// startNucleiWorkers：启动 Nuclei 扫描工作协程池
func startNucleiWorkers(numWorkers int, taskCh <-chan ScanTask, wg *sync.WaitGroup, taskDoneCh chan<- bool) {
	for i := 0; i < numWorkers; i++ {
		go func() {
			for task := range taskCh { // 这里从 nuclei任务队列拿出结果
				nucleiResults, err := run_Nuclei(task.URL, task.Tags)
				if err != nil {
					log.Printf("[-] Nuclei scan for %s failed: %v", task.URL, err)

					continue
				}
				for _, nucRes := range nucleiResults {
					if err := saveNucleiResult(nucRes); err != nil {
						log.Printf("[-] Failed to save nuclei result for %s: %v", nucRes.Host, err)
					}
				}
				wg.Done() // 任务完成后 让计数器-1
				taskDoneCh <- true
			}
		}()
	}
}

func startResultProcessor(resultCh <-chan scanResult, taskCh chan<- ScanTask, wg *sync.WaitGroup, taskDoneCh chan<- bool) {
	// 使用一个 map 来防止重复的 URL 被添加到 nuclei 队列
	nucleiTasksAdded := make(map[string]bool)
	nucleiTasksMutex := sync.Mutex{}

	for r := range resultCh { // 这里从指纹队列拿出来对应的结果
		if strings.Contains(r.Err, "drop") {
			continue
		}

		if err := saveResult(r); err != nil {
			log.Println("保存指纹结果失败:", err)
		}

		if len(r.Matches) > 0 {
			// 创建一个包含所有需要扫描的URL的切片
			urlsToScan := []string{r.InputURL}
			// 如果最终URL和原始URL不同，则也将其添加到扫描列表
			if r.FinalURL != r.InputURL {
				urlsToScan = append(urlsToScan, r.FinalURL)
			}

			for _, urlToScan := range urlsToScan {
				nucleiTasksMutex.Lock()
				if !nucleiTasksAdded[urlToScan] {
					nucleiTasksAdded[urlToScan] = true
					nucleiTasksMutex.Unlock()

					task := ScanTask{
						URL:  urlToScan,
						Tags: r.Matches,
					}
					wg.Add(1) // 只为每个唯一的URL调用一次 Add(1)
					taskCh <- task
					//fmt.Printf("[+] Nuclei 任务已加入队列: %s  [%s]\n", task.URL, strings.Join(task.Tags, ", "))
				} else {
					nucleiTasksMutex.Unlock()
				}
			}
		}
	}
	wg.Wait()
	close(taskCh)
}

// ================================================================

func main() {

	loadConfig()
	initHTTPClient((config.Timeout)*time.Second, needSkipVerifyGlobal)
	mux := http.NewServeMux()

	// == 这三个是鉴权 并且需要 web目录的
	mux.HandleFunc("/", basicAuth(handleIndex))
	mux.HandleFunc("/web/", authFileServer(http.Dir("web"), "/web/"))
	mux.HandleFunc("/scan", basicAuth(handleScan))
	mux.HandleFunc("/api/scan-status", basicAuth(handleScanStatus))
	// == 这三个是鉴权 并且需要 web目录的
	mux.HandleFunc("/web/history", basicAuth(func(w http.ResponseWriter, r *http.Request) {
		results, err := loadResults()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		var sb strings.Builder
		for i, res := range results {
			matchesStr := "未识别"
			if len(res.Matches) > 0 {
				matchesStr = strings.Join(res.Matches, ", ")
			}
			path := res.Path
			if path == "" {
				path = "/"
			}
			sb.WriteString(fmt.Sprintf(`
            <tr>
                <td>%d</td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td>%d</td>
            </tr>
        `, i+1, res.FinalURL, path, matchesStr, res.Status, res.Title, res.BodyLen))
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(sb.String()))
	}))

	// 漏洞发现历史记录
	mux.HandleFunc("/web/vulnerabilities", basicAuth(func(w http.ResponseWriter, r *http.Request) {
		results, err := loadNucleiResults()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		// 返回 JSON 格式的数据
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	}))

	if err := initDB(); err != nil {
		panic(err)
	}

	log.Printf("Listening on http://127.0.0.1:%s ...", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
