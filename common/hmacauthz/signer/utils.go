package signer

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sort"
	"strings"
)

const (
	// AuthorizationHeader Authorization 请求头 HeaderKey.
	AuthorizationHeader = "authorization"
	// DateHeader Date 请求头 HeaderKey.
	DateHeader = "date"
	// SignatureNonceHeader Nonce 请求头 HeaderKey, 需拼接自定义头前缀, 如 x-cfs-signature-nonce.
	SignatureNonceHeader = "signature-nonce"
	// DateHeaderTimeFormat Date 请求头时间字符串格式.
	DateHeaderTimeFormat = http.TimeFormat
	// ContentAcceptHeader Accept 请求头 HeaderKey.
	ContentAcceptHeader = "accept"
	// ContentTypeHeader Content-Type 请求头 HeaderKey.
	ContentTypeHeader = "content-type"
	// ContentMD5Header Content-MD5 请求头 HeaderKey.
	ContentMD5Header = "content-md5"
)

// ComputeContentMD5 计算content md5.
func ComputeContentMD5(body []byte) string {
	h := md5.Sum(body)
	return base64.StdEncoding.EncodeToString(h[:])
}

// GenerateSignatureNonce 生成签名nonce.
func GenerateSignatureNonce(length int) string {
	nonceBytes := make([]byte, length)
	_, _ = rand.Read(nonceBytes)
	return base64.URLEncoding.EncodeToString(nonceBytes)
}

// GetSignatureNonceHeaderName 获取 Nonce 请求头 HeaderKey (拼接后, 如 x-cfs-signature-nonce).
func GetSignatureNonceHeaderName(customHeaderPrefix string) string {
	return getCustomHeaderName(customHeaderPrefix, SignatureNonceHeader)
}

// GetCustomDateHeaderName 获取自定义 Date 请求头 HeaderKey (拼接后, 如 x-cfs-date).
func GetCustomDateHeaderName(customHeaderPrefix string) string {
	return getCustomHeaderName(customHeaderPrefix, DateHeader)
}

func getCustomHeaderName(customHeaderPrefix, headerName string) string {
	if !strings.HasSuffix(customHeaderPrefix, "-") {
		return customHeaderPrefix + "-" + headerName
	}
	return customHeaderPrefix + headerName
}

// MapSorter Map 字典序排序器.
type MapSorter struct {
	Keys []string
	Vals []string
}

// NewSorter 创建 Map 字典序排序器.
func NewSorter(m map[string]string) *MapSorter {
	ms := &MapSorter{
		Keys: make([]string, 0, len(m)),
		Vals: make([]string, 0, len(m)),
	}

	for k, v := range m {
		ms.Keys = append(ms.Keys, k)
		ms.Vals = append(ms.Vals, v)
	}
	return ms
}

// Sort 对 Map 进行 Key 字典序排序.
func (ms *MapSorter) Sort() {
	sort.Sort(ms)
}

// Len 获取 Map 长度.
func (ms *MapSorter) Len() int {
	return len(ms.Vals)
}

// Less 比较 Key 为 i 和 j 的排序先后.
func (ms *MapSorter) Less(i, j int) bool {
	return bytes.Compare([]byte(ms.Keys[i]), []byte(ms.Keys[j])) < 0
}

// Swap 交换 Map 中 Key 为 i 和 j 的位置.
func (ms *MapSorter) Swap(i, j int) {
	ms.Vals[i], ms.Vals[j] = ms.Vals[j], ms.Vals[i]
	ms.Keys[i], ms.Keys[j] = ms.Keys[j], ms.Keys[i]
}
