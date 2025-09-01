package main

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strings"

	"golang.org/x/net/html/charset"
)

// 辅助函数
func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func ensureHTTP(s string) string {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return s
	}
	return "http://" + s
}

func flattenHeaders(h map[string][]string) string {
	var b strings.Builder
	for k, v := range h {
		b.WriteString(strings.ToLower(k) + ":" + strings.Join(v, ",") + "\n")
	}
	return b.String()
}

func extractTitleWithEncoding(resp *http.Response, b []byte) string {
	// 用 charset.NewReader 将原始字节转 UTF-8
	reader, err := charset.NewReader(bytes.NewReader(b), resp.Header.Get("Content-Type"))
	if err != nil {
		return "" // 转码失败直接返回空
	}
	utf8Bytes, err := io.ReadAll(reader)
	if err != nil {
		return ""
	}

	re := regexp.MustCompile(`(?is)<\s*title[^>]*>(.*?)</\s*title\s*>`)
	if m := re.FindSubmatch(utf8Bytes); len(m) == 2 {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

func anyEquals(list []string, v string) bool {
	for _, k := range list {
		if strings.TrimSpace(k) == strings.TrimSpace(v) {
			return true
		}
	}
	return false
}

func unique(in []string) []string {
	m := map[string]struct{}{}
	out := []string{}
	for _, s := range in {
		if _, ok := m[s]; !ok {
			m[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

var genericTagsBlacklist = map[string]struct{}{
	"nc":     {},
	"http":   {},
	"server": {},
	// 根据需要，你可以在这里添加更多通用词
}

// extractAndCleanTags 提取并清理指纹标签，以生成更精确的匹配关键词。
func extractAndCleanTags(tags []string) []string {
	cleanedTags := []string{}
	for _, tag := range tags {
		normalizedTag := strings.ToLower(strings.TrimSpace(tag))
		if normalizedTag == "" {
			continue
		}

		// 找第一个空格、短横线或下划线的位置
		index := strings.IndexAny(normalizedTag, " -_")
		if index > 0 {
			normalizedTag = normalizedTag[:index]
		}

		cleanedTags = append(cleanedTags, normalizedTag)
	}
	return unique(cleanedTags)
}

// removeDuplicates 从切片中移除重复项。
func removeDuplicates(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	j := 0
	for _, v := range s {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			s[j] = v
			j++
		}
	}
	return s[:j]
}
