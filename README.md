## 垃圾poc需要改进
wanhu-ezoffice-downloadservlet-filedownload.yaml
seeyon_dee_weakpasswd
seeyon-a8-default-login

## powershell下 编译命令
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -o ezShell main.go httpclient.go scanner.go database.go nuclei.go retags.go

$env:GOOS="windows"
$env:GOARCH="amd64"
go build -o ezShell.exe main.go httpclient.go scanner.go database.go nuclei.go retags.go

## 命令选择
nuclei -id fast* -u 123.58.224.8:32166 -silent
[fastjson-1-2-47-rce] [http] [critical] http://123.58.224.8:32166

可以利用 yaml模板里面的 id参数模糊匹配poc 但是存在一个问题，如果是一些id为 cve的就没办法扫描了

## 2025.8.19 21:58  集成了 nuclei的漏扫
## 需要完善的是 主动式扫描 https://139.224.220.166 比如这个站点，它里面就有一个 nacos的url 以及集成了很多 带指纹的站点，这个时候 如果可以主动扫描这些站点，资产供给面瞬间就变多了

## 优化
需要考虑一下 访问根url的时候 要不要过过滤关键词， 以及发现有些200的站点被过滤了，因为 关键词 error

## 还是因为跳转的问题
http://123.232.15.58:8072/ 访问这个页面跳转到下面的， 这个页面没有指纹，但是跳转的有 导致没扫到
http://123.232.15.58:8072/login/login.php

## bug
我的程序出bug了，在大规模扫描的时候发现有如下错误 
1. url为空，漏洞名 严重性 模板ID Tags 这五项均为 N/A 
2. 模板ID 出现 cluster-2832cd88eedd8886375e41c61630a1f3830f37af2e25a0c4d5c3846dde0d9d39 这样的字符 
