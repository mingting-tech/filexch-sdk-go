package filexch

import (
	"context"
	"net/http"

	servicepb "github.com/mingting-tech/filexch-sdk-go/api/service"
	"github.com/mingting-tech/filexch-sdk-go/common/hmacauthz"
)

// Client 文件交换查询服务客户端.
type Client struct {
	*hmacauthz.Client
}

// NewClient 初始化文件交换查询服务客户端.
func NewClient(endpoint, accessKey, secretKey string) *Client {
	return &Client{
		Client: hmacauthz.NewClient(endpoint, accessKey, secretKey),
	}
}

func (cli *Client) GetVersions(
	ctx context.Context,
	in *servicepb.GetVersionsRequest,
) (*servicepb.GetVersionsResponse, error) {
	const apiPath = "/filexch.api.service.QueryService/GetVersions"
	httpResp, err := cli.Do(ctx, http.MethodPost, apiPath, in)
	if err != nil {
		return nil, err
	}
	resp := &servicepb.GetVersionsResponse{}
	if err = httpResp.GetRespData().UnmarshalTo(resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (cli *Client) GetVersionFiles(
	ctx context.Context,
	in *servicepb.GetVersionFilesRequest,
) (*servicepb.GetVersionFilesResponse, error) {
	const apiPath = "/filexch.api.service.QueryService/GetVersionFiles"
	httpResp, err := cli.Do(ctx, http.MethodPost, apiPath, in)
	if err != nil {
		return nil, err
	}
	resp := &servicepb.GetVersionFilesResponse{}
	if err = httpResp.GetRespData().UnmarshalTo(resp); err != nil {
		return nil, err
	}
	return resp, nil
}
