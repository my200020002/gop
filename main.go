package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"log"
	"net/http"
	"net/url"

	"github.com/elazarl/goproxy"
)
var _caCert string =""
var _caKey string = ""

func main() {
	verbose := flag.Bool("v", true, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":8889", "proxy listen address")
	setproxy := flag.Bool("p", false, "set proxy 7890")
	setmitm := flag.Bool("m", false, "set mitm")
	flag.Parse()
	_caCertBytes, err := base64.StdEncoding.DecodeString(_caCert)
	if err != nil {
		log.Fatal(err)
	}
	_caKeyBytes, err := base64.StdEncoding.DecodeString(_caKey)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := parseCA(_caCertBytes, _caKeyBytes)
	if err != nil {
		log.Fatal(err)
	}
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose

	customCaMitm := &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(cert)}
	var customAlwaysMitm goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return customCaMitm, host
	}
	if *setproxy {
		proxy.Tr = &http.Transport{Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse("http://127.0.0.1:7890")
		}}
		proxy.ConnectDial = proxy.NewConnectDialToProxy("http://127.0.0.1:7890")
	}
	if *setmitm {
		proxy.OnRequest().HandleConnect(customAlwaysMitm)
	}
	// proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	// 	// 检查 Content-Type 是否为 image/jpeg 或 URL 是否以 .jpg 结尾
	// 	log.Println(resp.Request.URL.Path)
	// 	if resp.Header.Get("Content-Type") == "image/jpeg" || filepath.Ext(resp.Request.URL.Path) == ".jpg" {
	// 		// 创建文件保存路径
	// 		filePath := filepath.Join("D:\\", filepath.Base(resp.Request.URL.Path))
	// 		file, err := os.Create(filePath)
	// 		if err != nil {
	// 			log.Printf("无法创建文件 %s: %v", filePath, err)
	// 			return resp // 如果无法创建文件，继续处理响应
	// 		}
	// 		defer file.Close()

	// 		// 将响应内容写入文件
	// 		_, err = io.Copy(file, resp.Body)
	// 		if err != nil {
	// 			log.Printf("无法写入文件 %s: %v", filePath, err)
	// 		}

	// 		// 重置响应体，以便后续处理
	// 		resp.Body.Close()
	// 		resp.Body = io.NopCloser(file) // 如果需要返回文件的内容
	// 	}

	// 	return resp
	// })

	log.Fatal(http.ListenAndServe(*addr, proxy))
}
func parseCA(caCert, caKey []byte) (*tls.Certificate, error) {
	parsedCert, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return nil, err
	}
	if parsedCert.Leaf, err = x509.ParseCertificate(parsedCert.Certificate[0]); err != nil {
		return nil, err
	}
	return &parsedCert, nil
}
