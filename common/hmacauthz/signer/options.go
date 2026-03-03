package signer

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
	"strings"
)

// Option 鉴权相关配置项.
type Option interface {
	apply(s *Signer)
}

// optionFunc 设置配置函数.
type optionFunc func(s *Signer)

// apply 应用配置.
func (fn optionFunc) apply(s *Signer) {
	fn(s)
}

// WithCustomHeaderPrefix 指定自定义头前缀，如 x-cfs.
//
//	所有以自定义头前缀的请求头都会纳入签名计算，如 x-cfs-signature-nonce
func WithCustomHeaderPrefix(prefix string) Option {
	return optionFunc(func(s *Signer) {
		s.customHeaderPrefix = strings.ToLower(prefix)
	})
}

// WithAuthorizationIdentifier 指定 Authorization 请求头鉴权标识符.
//
//	Authorization 头格式形如 Authorization: {AuthIdentifier} {AccessKey}:{Signature}
//	仅 AuthIdentifier 为指定的标识符才会解析成功
func WithAuthorizationIdentifier(identifier string) Option {
	return optionFunc(func(s *Signer) {
		s.authorizationIdentifier = strings.ToLower(identifier)
	})
}

// WithHasher 指定 HMAC-HASH 签名函数.
func WithHasher(h func() hash.Hash) Option {
	return optionFunc(func(s *Signer) {
		s.signHasher = h
	})
}

// WithSha1 指定 SHA1 作为 HMAC-HASH 签名函数(默认).
//
//	均衡。一般用于日常业务场景
func WithSha1() Option {
	return optionFunc(func(s *Signer) {
		s.signHasher = sha1.New
	})
}

// WithSha256 指定 SHA256 作为 HMAC-HASH 签名函数.
//
//	严格。一般用于对安全要求非常高的业务场景
func WithSha256() Option {
	return optionFunc(func(s *Signer) {
		s.signHasher = sha256.New
	})
}

// WithMd5 指定 MD5 作为 HMAC-HASH 签名函数.
//
//	简单。一般用于对安全性要求较低的业务场景
func WithMd5() Option {
	return optionFunc(func(s *Signer) {
		s.signHasher = md5.New
	})
}

// WithHashEncoder 指定 HASH 签名编码函数.
//
//	默认：base64.StdEncoding.EncodeToString
func WithHashEncoder(enc func(src []byte) string) Option {
	return optionFunc(func(s *Signer) {
		s.signEncoder = enc
	})
}

// WithAuthorizationHeader 指定签名请求头 Key.
//
// 默认：Authorization
func WithAuthorizationHeader(header string) Option {
	return optionFunc(func(s *Signer) {
		s.authorizationHeader = header
	})
}
