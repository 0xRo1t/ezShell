package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// NucleiTemplate represents a simplified structure of a Nuclei template for tag extraction.
type NucleiTemplate struct {
	Info struct {
		Name string          `yaml:"name"`
		Tags StringOrStrings `yaml:"tags"`
	} `yaml:"info"`
}

// StringOrStrings handles unmarshaling a string or a slice of strings from YAML.
type StringOrStrings []string

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *StringOrStrings) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var multi []string
	if err := unmarshal(&multi); err == nil {
		*s = multi
		return nil
	}
	var single string
	if err := unmarshal(&single); err == nil {
		*s = strings.Split(single, ",")
		return nil
	}
	return fmt.Errorf("failed to unmarshal tags as string or []string")
}

// Global variable to store all loaded Nuclei tags as a set for quick lookup.
var loadedNucleiTags = make(map[string]struct{})

// InitNucleiTemplates recursively loads tags from all YAML files in the specified directory.

func InitNucleiTemplates(dir string) error {
	log.Println("Loading Nuclei templates...")

	// Add a defer function to print the collected tags after the function returns.
	defer func() {
		log.Println("Collected Nuclei tags:")
		var tags []string
		for tag := range loadedNucleiTags {
			tags = append(tags, tag)
		}
		// for i := 0; i < len(tags); i++ {
		// 	for j := i + 1; j < len(tags); j++ {
		// 		if tags[i] > tags[j] {
		// 			tags[i], tags[j] = tags[j], tags[i]
		// 		}
		// 	}
		// }

		// for _, tag := range tags {
		// 	log.Printf("- %s", tag)
		// }
		log.Printf("Total unique tags collected: %d", len(tags))
	}()

	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err // Propagate the error.
		}
		// Skip directories and files that don't end with .yaml or .yml.
		if info.IsDir() || (!strings.HasSuffix(info.Name(), ".yaml") && !strings.HasSuffix(info.Name(), ".yml")) {
			return nil
		}

		// Read the file content.
		content, err := os.ReadFile(path)
		if err != nil {
			log.Printf("Failed to read file %s: %v", path, err)
			return nil // Continue walking even if one file fails.
		}

		// Unmarshal the YAML content into the struct.
		var t NucleiTemplate
		err = yaml.Unmarshal(content, &t)
		if err != nil {
			// Log the error but continue to the next file.
			log.Printf("Failed to parse YAML file %s: %v", path, err)
			return nil
		}

		for _, tag := range t.Info.Tags {
			if strings.TrimSpace(tag) != "" {
				loadedNucleiTags[strings.TrimSpace(tag)] = struct{}{}
			}
		}

		return nil
	})
}

type nucleiResult struct {
	TemplateID  string `json:"template-id"`
	Host        string `json:"host"`
	MatchedAt   string `json:"matched-at"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	Request     string `json:"request"`
	Response    string `json:"response"`
	IP          string `json:"ip"`
	CurlCommand string `json:"curl-command"`
	Info        struct {
		Name        string   `json:"name"`
		Author      []string `json:"author"`
		Tags        []string `json:"tags"`
		Description string   `json:"description"`
		Severity    string   `json:"severity"`
	} `json:"info"`
	ExtractedURLs []string  `json:"extracted-urls"`
	CreatedAt     time.Time `json:"vuln-time"` // Added CreatedAt field
}

// 这里的传参 tags 是 匹配到的指纹，也就是 finger.json 里面的内容
func run_Nuclei(url string, tags []string) ([]nucleiResult, error) {
	if nucleiTemplatesDir == "" {
		return nil, fmt.Errorf("[-] nuclei templates directory is not set")
	}
	//fmt.Printf("[+] 匹配到的指纹标签: [%s]\n", strings.Join(tags, ","))

	cleanedTags := extractAndCleanTags(tags)
	//fmt.Printf("[+] 提取并清洗后的标签: [%s]\n", strings.Join(cleanedTags, ","))

	var validTags []string

	for _, cleanedTag := range cleanedTags {
		for loadedTag := range loadedNucleiTags {
			// 核心逻辑: 检查 Nuclei 模板标签是否是清理后标签的子串
			// 这里太过于宽松
			if cleanedTag == loadedTag || strings.HasPrefix(cleanedTag, loadedTag) {
				// 新增的黑名单检查
				if _, isBlacklisted := genericTagsBlacklist[loadedTag]; !isBlacklisted {
					//fmt.Printf("[+] 清理后的标签 [ %s ] 包含 Nuclei 模板标签 [ %s ] %s\n", cleanedTag, loadedTag, url)
					validTags = append(validTags, loadedTag)
				}
			}
		}
	}

	// 第三步: 移除可能存在的重复项。
	uniqueValidTags := removeDuplicates(validTags)
	// 如果没有找到任何有效的标签，就跳过扫描。
	if len(uniqueValidTags) == 0 {
		fmt.Printf("[-] 没有找到有效的 Nuclei 模板标签，跳过对 %s 的扫描。\n", url)
		return nil, nil
	}
	// 动态构建 tags 参数，去重
	tagsArg := strings.Join(removeDuplicates(validTags), ",")
	fmt.Printf("[+] nuclei-scan: %s: [%s]\n", url, tagsArg)
	cmdArgs := []string{
		"-u", url,
		"-tags", tagsArg,
		"-silent",
		"-j",
		"-t", nucleiTemplatesDir,
		"-s", "high, critical",
	}
	//fmt.Printf("[+] Executing nuclei command: %s %s\n", nucleiExecPath, strings.Join(cmdArgs, " "))
	cmd := exec.Command(nucleiExecPath, cmdArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("[-] nuclei command failed for URL %s with tags %s. Stderr: %s\n", url, tags, stderr.String())
		return nil, fmt.Errorf("[-] nuclei command failed: %w, stderr: %s", err, stderr.String())
	}

	// 解析 JSON 输出
	var results []nucleiResult
	// Nuclei 的 -json 模式每行一个 JSON 对象
	scanner := json.NewDecoder(&stdout)
	for scanner.More() {
		var r nucleiResult
		if err := scanner.Decode(&r); err != nil {
			//fmt.Printf("[-] Error decoding nuclei JSON output: %v\n", err)
			continue
		}

		// 修复 URL 为空的问题
		//if r.URL == "" {
		//	if r.MatchedAt != "" {
		//		r.URL = r.Host
		//		fmt.Println("======用host替换url========")
		//	} else if r.Host != "" {
		//		r.URL = r.IP
		//		fmt.Println("======用 ip 替换url========")
		//	}
		//}
		// 过滤掉没有漏洞信息的匹配项
		if r.MatchedAt != "" {
			r.URL = r.MatchedAt
			results = append(results, r)
		}
	}

	// 直接在这里打印扫描结果
	if len(results) == 0 {
		fmt.Println("[+] Scan completed. No vulnerabilities found.")
	} else {
		fmt.Printf("[+] Scan completed. Found %d vulnerabilities:\n", len(results))
		for _, result := range results {
			fmt.Println("--------------------------------------------------")
			fmt.Printf("Template ID: %s\n", result.TemplateID)
			fmt.Printf("[+] Vuln Name: [%s] [%s]\n", result.Info.Name, result.URL)
			fmt.Printf("Severity: %s\n", result.Info.Severity)
			fmt.Printf("Host: [%s]\n", result.Host)
			fmt.Printf("Type: %s\n", result.Type)
			fmt.Printf("URL: %s\n", result.URL)
			if result.Info.Description != "" {
				fmt.Printf("Description: %s\n", result.Info.Description)
			}
			// if len(result.Info.Author) > 0 {
			// 	fmt.Printf("Author(s): %s\n", strings.Join(result.Info.Author, ", "))
			// }
			// if len(result.Info.Tags) > 0 {
			// 	fmt.Printf("Tags: %s\n", strings.Join(result.Info.Tags, ", "))
			// }
			if result.Request != "" {
				fmt.Printf("\n--------------- Request ---------------%s\n", result.Request)
			}
			if result.Response != "" {
				fmt.Printf("\n--------------- Response ---------------%s\n", result.Response)
			}
			// if result.CurlCommand != "" {
			// 	fmt.Printf("\n--- cURL Command ---\n%s\n", result.CurlCommand)
			// }
			fmt.Println("--------------------------------------------------")
		}
	}
	return results, nil
}
