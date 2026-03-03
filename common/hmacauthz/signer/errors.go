package signer

import (
	"errors"
	"fmt"
)

var (
	// ErrEmptyAuthorization 签名header值为空.
	ErrEmptyAuthorization = errors.New("signer: empty authorization value")
	// ErrInvalidAuthorization 签名header值不合法.
	ErrInvalidAuthorization = errors.New("signer: invalid authorization value")
)

// SecretLookupError 秘钥查找错误.
type SecretLookupError struct {
	RawError error
}

func (e *SecretLookupError) Error() string {
	return fmt.Sprintf("signer: secret lookup error: %s", e.RawError)
}

func (e *SecretLookupError) Unwrap() error {
	return e.RawError
}

// SignatureNotMatchError 签名不匹配错误.
type SignatureNotMatchError struct {
	ExpectedSignature  string // 预期签名(根据请求参数计算)
	ActualReqSignature string // 实际请求携带的签名
	StringToSign       string // 签名字符串
}

// Error 实现 error 接口.
func (e *SignatureNotMatchError) Error() string {
	return e.String()
}

// String 实现 string 接口.
func (e *SignatureNotMatchError) String() string {
	return fmt.Sprintf("signer: signature not match")
}
