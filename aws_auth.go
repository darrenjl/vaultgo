package vault

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

const (
	vaultAuthHeaderName  = "X-Vault-AWS-IAM-Server-ID"
	iamHTTPRequestMethod = "iam_http_request_method"
	iamRequestURL        = "iam_request_url"
	iamRequestHeaders    = "iam_request_headers"
	iamRequestBody       = "iam_request_body"
	role                 = "role"
)

func NewAwsAuth(c *Client, mountpoint, role, header string) (AuthProvider, error) {
	a := &awsAuth{
		Client:     c,
		mountPoint: mountpoint,
		role:       role,
		header:     header,
	}

	return a, nil
}

type awsAuth struct {
	Client     *Client
	mountPoint string
	role       string
	header     string
}

func (a awsAuth) Auth() (*AuthResponse, error) {
	stsSvc := sts.New(session.New())
	stsReq, _ := stsSvc.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})
	if a.header != "" {
		stsReq.HTTPRequest.Header.Add(vaultAuthHeaderName, a.header)
	}

	err := stsReq.Sign()
	if err != nil {
		return nil, err
	}

	headers, err := json.Marshal(stsReq.HTTPRequest.Header)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(stsReq.HTTPRequest.Body)
	if err != nil {
		return nil, err
	}

	d := make(map[string]interface{})
	d[iamHTTPRequestMethod] = stsReq.HTTPRequest.Method
	d[iamRequestURL] = base64.StdEncoding.EncodeToString([]byte(stsReq.HTTPRequest.URL.String()))
	d[iamRequestHeaders] = base64.StdEncoding.EncodeToString(headers)
	d[iamRequestBody] = base64.StdEncoding.EncodeToString(body)
	d[role] = a.role

	res := &AuthResponse{}

	err = a.Client.Write([]string{"v1", "auth", a.mountPoint, "login"}, d, res, &RequestOptions{
		SkipRenewal: true,
	})
	if err != nil {
		return nil, err
	}

	return res, nil
}
