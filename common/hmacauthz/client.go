package hmacauthz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mingting-tech/filexch-sdk-go/common/hmacauthz/signer"
)

type (
	// Client Hmacauth认证服务http客户端.
	Client struct {
		endpoint  string
		accessKey string
		secretKey string
		signer    *signer.Signer

		// 底层http客户端，默认为 http.DefaultClient
		HttpClient HttpClient
	}

	// HttpClient http客户端.
	HttpClient interface {
		Do(req *http.Request) (*http.Response, error)
	}
)

// NewClient 客户端初始化.
func NewClient(endpoint, accessKey, secretKey string) *Client {
	return &Client{
		endpoint:   endpoint,
		accessKey:  accessKey,
		secretKey:  secretKey,
		signer:     signer.NewSigner(),
		HttpClient: http.DefaultClient,
	}
}

// Do 发起请求.
//
//	method: http请求方法，例如 http.MethodPost
//	apiPath: api路径，例如/api/method
//	reqData: 请求数据，要求可json序列化.
func (cli *Client) Do(
	ctx context.Context,
	method,
	apiPath string,
	reqData interface{},
) (*HttpResponse, error) {

	// 创建请求
	apiUrl, err := url.JoinPath(cli.endpoint, apiPath)
	if err != nil {
		return nil, fmt.Errorf("build api url error: %w", err)
	}
	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return nil, fmt.Errorf("marshal request body error: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, apiUrl, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("build http request error: %w", err)
	}

	// 请求签名
	cli.signer.SignRequest(cli.accessKey, cli.secretKey, httpReq)

	// 发起请求
	httpClient := cli.HttpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("do request error: %w", err)
	}
	defer func() {
		_ = httpResp.Body.Close()
	}()
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("not http ok response: (%d)%s", httpResp.StatusCode, httpResp.Status)
	}

	// 响应处理
	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body error: %w", err)
	}
	resp := &HttpResponse{}
	if err = json.Unmarshal(respBody, resp); err != nil {
		return nil, fmt.Errorf("unmarshal response body error: %w", err)
	}
	if code := codes.Code(resp.GetRespCommon().GetCode()); code != codes.OK {
		return nil, status.Error(code, resp.GetRespCommon().String())
	}
	return resp, nil
}
