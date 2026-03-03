package signer

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

var (
	defaultAuthorizationIdentifier = "mingting"                        // 默认 Authorization 请求头鉴权标识符
	defaultCustomHeaderPrefix      = "x-mingting-"                     // 默认自定义头前缀
	defaultSignHasher              = sha1.New                          // 默认 HMAC-HASH 签名函数
	defaultSignEncoder             = base64.StdEncoding.EncodeToString // 默认 HASH 签名编码函数
)

// Signer 请求签名.
type Signer struct {
	customHeaderPrefix      string                  // 自定义头前缀
	authorizationIdentifier string                  // Authorization 请求头鉴权标识符
	signHasher              func() hash.Hash        // HMAC-HASH 签名函数
	signEncoder             func(src []byte) string // HASH 签名编码函数
	authorizationHeader     string                  // 签名请求头 Key (Authorization)
}

// NewSigner 创建请求签名对象.
func NewSigner(opts ...Option) *Signer {
	s := &Signer{
		customHeaderPrefix:      strings.ToLower(defaultCustomHeaderPrefix),
		authorizationIdentifier: strings.ToLower(defaultAuthorizationIdentifier),
		signHasher:              defaultSignHasher,
		signEncoder:             defaultSignEncoder,
		authorizationHeader:     AuthorizationHeader,
	}
	for _, opt := range opts {
		opt.apply(s)
	}
	return s
}

// SignRequest 计算请求内容签名并添加到请求header.
func (v2 *Signer) SignRequest(accessKey, secretKey string, req *http.Request) {
	stringToSign := v2.getStringToSign(req.Method, req.URL.Path, req.URL.Query(), req.Header)
	signature := v2.doHmacHash(stringToSign, secretKey)
	authorization := v2.buildAuthorization(accessKey, signature)
	req.Header.Set(v2.authorizationHeader, authorization)
}

// VerifyRequest 计算请求内容签名，并和从请求header中提取的签名进行并对比校验.
func (v2 *Signer) VerifyRequest(
	ctx context.Context,
	lookup func(ctx context.Context, accessKey string) (secretKey string, err error),
	req *http.Request,
) error {
	authorization := req.Header.Get(v2.authorizationHeader)
	accessKey, actualSignature, err := v2.parseAuthorization(authorization)
	if err != nil {
		return err
	}
	secretKey, err := lookup(ctx, accessKey)
	if err != nil {
		return &SecretLookupError{RawError: err}
	}
	stringToSign := v2.getStringToSign(req.Method, req.URL.Path, req.URL.Query(), req.Header)
	expectedSignature := v2.doHmacHash(stringToSign, secretKey)
	if actualSignature != expectedSignature {
		return &SignatureNotMatchError{
			ExpectedSignature:  expectedSignature,
			ActualReqSignature: actualSignature,
			StringToSign:       stringToSign,
		}
	}
	return nil
}

// 获取用于签名的字符串
func (v2 *Signer) getStringToSign(method string, path string, query url.Values, header http.Header) string {
	date := header.Get(DateHeader)
	accept := header.Get(ContentAcceptHeader)
	contentType := header.Get(ContentTypeHeader)
	contentMD5 := header.Get(ContentMD5Header)
	canonicalizedHeaders := v2.getCanonicalizedHeaders(header)
	canonicalizedResource := getCanonicalizedResource(path, query)

	// StringToSign =
	//			HTTP-Verb + "\n" +
	//			Accept + "\n" +
	//			Content-MD5 + "\n" +
	//			Content-Type + "\n" +
	//			Date + "\n" +
	//			CanonicalizedHeaders +
	//			CanonicalizedResource
	stringToSign := strings.Join([]string{
		method, "\n", accept, "\n", contentMD5, "\n", contentType, "\n", date, "\n",
		canonicalizedHeaders, canonicalizedResource,
	}, "")
	return stringToSign
}

// 获取用于签名的拼接 Header
func (v2 *Signer) getCanonicalizedHeaders(headers http.Header) string {
	filtered := make(map[string]string)
	excluded := strings.ToLower(v2.authorizationHeader)
	for k := range headers {
		kLower := strings.ToLower(k)
		if kLower == excluded {
			continue
		}
		if strings.HasPrefix(kLower, v2.customHeaderPrefix) {
			filtered[kLower] = headers.Get(k)
		}
	}
	if len(filtered) == 0 {
		return ""
	}

	var canonicalizedHeaders []string
	sorter := NewSorter(filtered)
	sorter.Sort()
	for i := range sorter.Keys {
		headerStr := fmt.Sprintf("%s:%s", sorter.Keys[i], sorter.Vals[i])
		canonicalizedHeaders = append(canonicalizedHeaders, headerStr, "\n")
	}
	return strings.Join(canonicalizedHeaders, "")
}

// 获取用于签名的拼接 Query
func getCanonicalizedResource(pathName string, query url.Values) string {
	if !strings.HasPrefix(pathName, "/") {
		pathName = "/" + pathName
	}
	canonicalizedResource := pathName

	if len(query) == 0 {
		return canonicalizedResource
	}

	queryKeys := make([]string, 0, len(query))
	for key := range query {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)

	params := make([]string, 0, len(queryKeys))
	for _, queryKey := range queryKeys {
		queryVal := query.Get(queryKey)
		params = append(params, queryKey+"="+queryVal)
	}
	queryString := strings.Join(params, "&")
	canonicalizedResource += "?" + queryString
	return canonicalizedResource
}

// 计算签名字符串的 HMAC-HASH
func (v2 *Signer) doHmacHash(stringToSign, secret string) string {
	h := hmac.New(v2.signHasher, []byte(secret))
	_, _ = h.Write([]byte(stringToSign))
	return v2.signEncoder(h.Sum(nil))
}

func (v2 *Signer) buildAuthorization(accessKey, signature string) string {
	return fmt.Sprintf("%s %s:%s", v2.authorizationIdentifier, accessKey, signature)
}

func (v2 *Signer) parseAuthorization(authorization string) (accessKey, signature string, err error) {
	if authorization == "" {
		return "", "", ErrEmptyAuthorization
	}
	spaceIndex := strings.Index(authorization, " ")
	if spaceIndex == -1 {
		return "", "", ErrInvalidAuthorization
	}
	identifier := authorization[:spaceIndex]
	if identifier == "" || strings.ToLower(identifier) != v2.authorizationIdentifier {
		return "", "", ErrInvalidAuthorization
	}
	colonIndex := strings.Index(authorization, ":")
	if colonIndex == -1 || colonIndex <= spaceIndex+1 {
		return "", "", ErrInvalidAuthorization
	}
	accessKey = strings.TrimSpace(authorization[spaceIndex+1 : colonIndex])
	if accessKey == "" {
		return "", "", ErrInvalidAuthorization
	}
	signature = strings.TrimSpace(authorization[colonIndex+1:])
	if signature == "" {
		return "", "", ErrInvalidAuthorization
	}
	return
}
