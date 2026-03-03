package filexch

import (
	"net/http"
	"os"
	"testing"
	"time"

	servicepb "gopkg.mingting.cn/filexch/api/service"
)

func TestNewClient(t *testing.T) {
	// 初始化客户端
	var (
		accessKey = os.Getenv("MINGTING_ACCESS_KEY_ID")
		secretKey = os.Getenv("MINGTING_SECRET_ACCESS_KEY")
		recipient = os.Getenv("MINGTING_FILEXCH_RECIPIENT")
	)
	client := NewClient("https://ti-gateway.zhhainiao.com", accessKey, secretKey)
	client.HttpClient = &http.Client{
		Timeout: time.Second * 5,
	}

	// 查询最新版本
	ctx := t.Context()
	getVersResp, err := client.GetVersions(ctx, &servicepb.GetVersionsRequest{
		Recipient: recipient,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 获取版本文件下载信息
	versions := getVersResp.GetLatestVersions()
	t.Log(versions)
	if len(versions) > 0 {
		getVerFilesResp, err := client.GetVersionFiles(ctx, &servicepb.GetVersionFilesRequest{
			Recipient: recipient,
			Version:   versions[0],
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Log(getVerFilesResp.GetFiles())
	}
}
