package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

func initDB() error {
	var err error
	db, err = sql.Open("sqlite", "./db.db")

	// 切换到 WAL 模式
	_, err = db.Exec("PRAGMA journal_mode=WAL;")
	if err != nil {
		log.Fatal("[-] Failed to set WAL mode:", err)
	}

	if err != nil {
		return err
	}
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_url TEXT,
            final_url TEXT,
            status TEXT,
            title TEXT,
            matches TEXT,
            path TEXT,
            err TEXT,
            body_len INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(final_url, path) 
        )
    `)
	if err != nil {
		return fmt.Errorf("failed to create scan_results table: %w", err)
	}
	// 创建新的漏洞发现结果表
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS nuclei_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			template_id TEXT,
			host TEXT,
			url TEXT,
			matched_at TEXT,
			severity TEXT,
			name TEXT,
			tags TEXT,
			request TEXT,
			response TEXT,
			extracted_urls TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(template_id, url,created_at)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create nuclei_results table: %w", err)
	}
	return err
}

func saveResult(r scanResult) error {
	// 存为 JSON 更安全
	matchesJSON, _ := json.Marshal(r.Matches)
	_, err := db.Exec(`INSERT OR REPLACE INTO scan_results (input_url, final_url, status, title, matches, path, err, body_len) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.InputURL, r.FinalURL, r.Status, r.Title, string(matchesJSON), r.Path, r.Err, r.BodyLen)
	return err
}

// 扫描结果示例结构
func loadResults() ([]scanResult, error) {
	rows, err := db.Query(`SELECT input_url, final_url, status, title, matches, path, err, body_len FROM scan_results ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []scanResult
	for rows.Next() {
		var r scanResult
		var matchesStr string
		if err := rows.Scan(&r.InputURL, &r.FinalURL, &r.Status, &r.Title, &matchesStr, &r.Path, &r.Err, &r.BodyLen); err != nil {
			return nil, err
		}
		if matchesStr != "" {
			json.Unmarshal([]byte(matchesStr), &r.Matches)
			//r.Matches = strings.Split(matchesStr, ",")
		}
		results = append(results, r)
	}
	return results, nil
}

// 保存漏洞信息
func saveNucleiResult(r nucleiResult) error {
	// 将 info.Tags 和 ExtractedURLs 转换为 JSON 字符串
	tagsJSON, _ := json.Marshal(r.Info.Tags)
	extractedURLsJSON, _ := json.Marshal(r.ExtractedURLs)
	createdAt := time.Now()
	//log.Printf("Saving nuclei result with created_at: %s", createdAt.Format(time.RFC3339))
	// 使用 INSERT OR REPLACE 插入或更新记录，以 template_id 和 url 为唯一键
	_, err := db.Exec(`
		INSERT OR REPLACE INTO nuclei_results (
			template_id, host, url, matched_at, severity, name, tags, request, response, extracted_urls,created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.TemplateID, r.Host, r.URL, r.MatchedAt, r.Info.Severity, r.Info.Name, string(tagsJSON), r.Request, r.Response, string(extractedURLsJSON), createdAt.Format("2006-01-02 15:04:05"))

	if err != nil {
		return fmt.Errorf("failed to save nuclei result: %w", err)
	}
	return nil
}

// loadNucleiResults 函数，用于加载漏洞发现结果
func loadNucleiResults() ([]nucleiResult, error) {
	rows, err := db.Query(`SELECT template_id, host, url, matched_at, severity, name, tags, request, response, extracted_urls ,created_at FROM nuclei_results ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []nucleiResult
	for rows.Next() {
		var r nucleiResult
		var tagsStr, extractedURLsStr string
		var infoName, infoSeverity string
		if err := rows.Scan(&r.TemplateID, &r.Host, &r.URL, &r.MatchedAt, &infoSeverity, &infoName, &tagsStr, &r.Request, &r.Response, &extractedURLsStr, &r.CreatedAt); err != nil {
			return nil, err
		}

		r.Info.Name = infoName
		r.Info.Severity = infoSeverity

		if tagsStr != "" {
			json.Unmarshal([]byte(tagsStr), &r.Info.Tags)
		}
		if extractedURLsStr != "" {
			json.Unmarshal([]byte(extractedURLsStr), &r.ExtractedURLs)
		}
		// log.Printf("模板ID: %s", r.TemplateID)
		// log.Printf("主机: %s", r.Host)
		// log.Printf("URL: %s", r.URL)
		// log.Printf("严重性: %s", r.Info.Severity)
		// log.Printf("漏洞名称: %s", r.Info.Name)
		// log.Printf("标签: %v", r.Info.Tags)
		// log.Printf("请求包: %s", r.Request)
		// log.Printf("响应包: %s", r.Response)
		// log.Printf("提取的URL: %v", r.ExtractedURLs)
		// log.Printf("创建时间: %s", r.CreatedAt.Format("2006-01-02 15:04:05"))
		results = append(results, r)
	}
	return results, nil
}
