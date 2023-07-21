package core

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type Config struct {
	WAFSpecialChar  bool
	UploadWhitelist string
	SQLBlacklist    *regexp.Regexp
	URLBlacklist    map[string]struct{} // URL协议黑名单
	PHPBlacklist    *regexp.Regexp
}

type MyHandler struct {
	Config *Config
}

func DataCatch(targeturl string) {
	// 创建配置对象
	config := &Config{
		WAFSpecialChar:  true,
		SQLBlacklist:    regexp.MustCompile(`drop |dumpfile\b|INTO FILE|union select|outfile\b|load_file\b|multipoint\(`),
		UploadWhitelist: "(jpg|png|gif)",
		PHPBlacklist:    regexp.MustCompile("/phar|zip|compress.bzip2|compress.zlib/i"),
		URLBlacklist: map[string]struct{}{
			"file":   {},
			"gopher": {},
			"dict":   {},
		},
	}
	// 目标服务器地址
	fmt.Println("目标服务器地址是：", targeturl)
	targetURL, err := url.Parse(targeturl)
	if err != nil {
		log.Fatal(err)
	}

	// 创建反向代理
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// 修改请求的Host头
	proxy.Director = func(req *http.Request) {
		req.Host = targetURL.Host
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
	}

	// 添加自定义的RoundTripper
	proxy.Transport = &myTransport{
		Config: config,
	}

	// 注册处理函数
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 代理请求
		proxy.ServeHTTP(w, r)
	})

	// 启动服务器
	fmt.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

// 自定义的RoundTripper
type myTransport struct {
	Config    *Config
	timestamp string
}

func (t *myTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	//验证客户信息
	filename := "ipblacklist.txt"
	clientIP := t.extractIP(req)
	found, err := readIPAddressesFromFile(filename, clientIP)
	if err != nil {
		fmt.Printf("Error reading file: %s\n", err)
		return nil, fmt.Errorf("Error reading file")
	}
	if found {
		// 处理拒绝访问的情况，例如记录日志、返回错误等
		log.Println("Access Denied:", clientIP)
		t.writeAttackLog("Catch attack: < IPBlacklist > ", req.Header, "")
		return nil, fmt.Errorf("Access Denied")
	}

	// 获取请求头部信息
	headers := req.Header

	// 获取请求数据
	requestData := ""
	// 打印请求信息
	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		log.Println(err)
	} else {
		//fmt.Println(string(dump))
		queryParams := req.URL.Query()
		for key, values := range queryParams {
			// fmt.Printf("Key: %s\n", key)
			for _, value := range values {
				// fmt.Printf("Value: %s\n", value)
				// 对参数进行检查和过滤，防止 SQL 注入
				if t.isSQLInjection(value) {
					// 处理 SQL 注入的情况，例如记录日志、返回错误等
					log.Println("SQL Injection detected:", value)
					t.writeAttackLog("Catch attack: < SQLI > ", headers, requestData)
					// 这里可以进行自定义的处理逻辑
					return nil, fmt.Errorf("SQL Injection detected")
				}
				if isSpecialChar(value) {
					// 处理特殊字符攻击的情况，例如记录日志、返回错误等
					log.Println("Special character attack detected:", value)
					t.writeAttackLog("Catch attack: < SpecialChar > ", headers, requestData)
					// 这里可以进行自定义的处理逻辑
					return nil, fmt.Errorf("Special character attack detected")
				}
				if t.isPHPunserialize(value) {
					log.Println("< phar unserialize >detected:", value)
					t.writeAttackLog("Catch attack: < phar unserialize >", headers, requestData)
					// 这里可以进行自定义的处理逻辑
					return nil, fmt.Errorf("< phar unserialize >detected:")
				}
				fmt.Println("要检测的key是", key)
				if strings.EqualFold(key, "url") {
					fmt.Println("检测到key是url")
					if t.isURLBlacklisted(value) {
						// 处理不安全的协议请求
						log.Println("Unsafe protocol detected:", key, "=", value)
						t.writeAttackLog("Catch attack: < SSRF > ", headers, requestData)
						return nil, fmt.Errorf("Unsafe protocol detected")
					}
					if IsSafeURL(value) {
						log.Println("Unsafe protocol detected:", value)
						t.writeAttackLog("Catch attack: < UnsafeProtocol > ", headers, requestData)
						return nil, fmt.Errorf("Unsafe protocol detected")
					}
				}
			}
		}
	}

	// 发送请求并获取响应
	resp, err := http.DefaultTransport.RoundTrip(req)

	// 打印响应信息
	dump, err = httputil.DumpResponse(resp, true)
	if err != nil {
		log.Println(err)
	} else {
		//fmt.Println(string(dump))
		// 将响应包保存到文件中
		err = ioutil.WriteFile("response.txt", dump, 0644)
		if err != nil {
			log.Println(err)
		}
	}

	// // 检查响应数据包中的 URL 是否在黑名单中
	// if resp != nil && resp.Body != nil {
	// 	defer resp.Body.Close()

	// 	// 读取响应数据包
	// 	respData, err := ioutil.ReadAll(resp.Body)
	// 	if err != nil {
	// 		log.Println(err)
	// 	} else {
	// 		// 判断响应数据包中的 URL 是否在黑名单中
	// 		respString := string(respData)
	// 		for protocol := range t.Config.URLBlacklist {
	// 			if strings.Contains(respString, protocol+"://") {
	// 				// 处理不安全的 URL 响应
	// 				log.Println("Unsafe URL in response detected:", protocol)
	// 				t.writeAttackLog("Catch attack: < UnsafeURLInResponse > ", headers, requestData)
	// 				return nil, fmt.Errorf("Unsafe URL in response detected")
	// 			}
	// 		}
	// 	}
	// }

	return resp, err
}

// 检查是否存在 SQL 注入的敏感字符或模式
func (t *myTransport) isSQLInjection(str string) bool {
	// 使用配置中的 SQL 注入黑名单进行匹配
	return t.Config.SQLBlacklist.MatchString(str)
}

// 检测php反序列化
func (t *myTransport) isPHPunserialize(str string) bool {

	return t.Config.PHPBlacklist.MatchString(str)
}

// 检查是否存在特殊字符攻击
func isSpecialChar(str string) bool {
	for _, char := range str {
		ascii := int(char)
		if ascii > 126 || ascii < 32 {
			if !contains([]int{9, 10, 13}, ascii) {
				return true
			}
		}
		if match, _ := regexp.MatchString(`[\|`+"`"+`;,'"<>]`, string(char)); match {
			return true
		}
	}
	return false
}

// 辅助函数：判断切片中是否包含指定元素
func contains(slice []int, element int) bool {
	for _, item := range slice {
		if item == element {
			return true
		}
	}
	return false
}

// 编写攻击日志
func (t *myTransport) writeAttackLog(alert string, headers http.Header, requestData string) {
	MaxLogSize := 102400
	tmp := fmt.Sprintf("%x", sha1.Sum([]byte("Syclover"))) + t.timestamp + fmt.Sprintf("%x", sha1.Sum([]byte("Syclover")))
	tmp += "[" + time.Now().Format("15:04:05") + "] {" + alert + "}\n"
	tmp += "SRC IP: " + headers.Get("X-Real-IP") + "\n"
	tmp += headers.Get("Request-Method") + " " + headers.Get("Request-URI") + " " + headers.Get("Server-Protocol") + "\n"
	for k, v := range headers {
		if k == "isself" {
			continue
		}
		tmp += k + ": " + v[0] + "\n"
	}
	if requestData != "" {
		tmp += "\n" + requestData + "\n"
	}
	err := ioutil.WriteFile("under_attack_log.txt", []byte(tmp), 0644)
	if err != nil {
		log.Println(err)
	}
	if fi, err := os.Stat("under_attack_log.txt"); err == nil {
		if fi.Size() > int64(MaxLogSize) {
			err = os.Remove("under_attack_log.txt")
			if err != nil {
				log.Println(err)
			}
		}
	}
}

// 检查 URL 协议是否在黑名单中
func (t *myTransport) isURLBlacklisted(protocol string) bool {
	_, blacklisted := t.Config.URLBlacklist[protocol]
	return blacklisted
}

// IsSafeURL 检查给定的 URL 是否安全访问。
// 通过确保 URL 的主机不是私有 IP 地址或回环地址，它执行 SSRF 防护。
func IsSafeURL(inputURL string) bool {
	u, err := url.Parse(inputURL)
	if err != nil {
		fmt.Println("解析 URL 时发生错误:", err)
		return false
	}

	// 检查 URL 的主机是否是私有 IP 地址或回环地址
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLoopback() || isPrivateIP(ip)) {
		return false
	}

	// 如果需要，可以在此处添加更多自定义检查，以适应特定的使用场景。

	return true
}

// 辅助函数：检查 IP 地址是否是私有 IP。
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// 私有 IP 地址范围
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{start: net.ParseIP("10.0.0.0"), end: net.ParseIP("10.255.255.255")},
		{start: net.ParseIP("172.16.0.0"), end: net.ParseIP("172.31.255.255")},
		{start: net.ParseIP("192.168.0.0"), end: net.ParseIP("192.168.255.255")},
	}

	// 检查 IP 地址是否在任何私有范围内
	for _, r := range privateRanges {
		if bytesBetween(ip, r.start, r.end) {
			return true
		}
	}

	return false
}

// 辅助函数：检查 IP 地址是否在给定范围内。
func bytesBetween(ip, start, end net.IP) bool {
	return bytesLessThanOrEqual(start, ip) && bytesLessThanOrEqual(ip, end)
}

// 辅助函数：比较两个 IP 地址的字节形式。
func bytesLessThanOrEqual(a, b net.IP) bool {
	return bytesCompare(a, b) <= 0
}

// 辅助函数：比较两个 IP 地址的字节形式。
func bytesCompare(a, b net.IP) int {
	// IPv4 地址小于 IPv6 地址
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}

	// 比较字节
	for i := 0; i < len(a); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}

	return 0
}

// 提取客户端的 IP 地址
func (t *myTransport) extractIP(req *http.Request) string {
	// 从请求头中获取真实客户端 IP 地址（适用于经过代理服务器的情况）
	clientIP := req.Header.Get("X-Real-IP")
	if clientIP == "" {
		clientIP = req.Header.Get("X-Forwarded-For")
	}

	// 如果没有设置真实客户端 IP 地址，使用 RemoteAddr 获取
	if clientIP == "" {
		_, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			clientIP = req.RemoteAddr
		}
	}

	return clientIP
}

func readIPAddressesFromFile(filename string, targetIP string) (bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ipAddress := scanner.Text()
		if ipAddress == targetIP {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, err
	}

	return false, nil
}
