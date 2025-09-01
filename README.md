## 工作流
从fofa 这种平台拉出来url，直接放进 输入框去扫描 url + path.txt 里面的路径，然后去扫描指纹
扫描指纹完成后，利用 nuclei去漏扫

## powershell下 编译命令
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -o ezShell main.go httpclient.go scanner.go database.go nuclei.go retags.go

$env:GOOS="windows"
$env:GOARCH="amd64"
go build -o ezShell.exe main.go httpclient.go scanner.go database.go nuclei.go retags.go


## 2025.8.19 21:58  集成了 nuclei的漏扫
需要完善的是 主动式扫描 https://139.224.220.166 比如这个站点，它里面就有一个 nacos的url 以及集成了很多 带指纹的站点，这个时候 如果可以主动扫描这些站点，资产供给面瞬间就变多了

## 优化
需要考虑一下 访问根url的时候 要不要过过滤关键词， 以及发现有些200的站点被过滤了，因为 关键词 error

## 还是因为跳转的问题
http://123.232.15.58:8072/ 访问这个页面跳转到下面的， 这个页面没有指纹，但是跳转的有 导致没扫到
http://123.232.15.58:8072/login/login.php

