package idclient

import (
	"context"
	"errors"
	"io/ioutil"
	"net/url"

	"github.com/function61/gokit/ezhttp"
	"github.com/function61/id/pkg/idtypes"
)

const (
	Function61 = "https://function61.com/id" // our ID server
)

type Client struct {
	serverBaseurl string
}

func New(serverBaseurl string) *Client {
	return &Client{serverBaseurl}
}

func (c *Client) UserByToken(ctx context.Context, token string) (*idtypes.User, error) {
	user := &idtypes.User{}
	_, err := ezhttp.Get(
		ctx,
		c.serverBaseurl+"/profile",
		ezhttp.AuthBearer(token),
		ezhttp.RespondsJson(user, true))
	return user, err
}

func (c *Client) loginUrl(returnAfterAuth string) string {
	return c.serverBaseurl + "?next=" + url.QueryEscape(returnAfterAuth)
}

func (c *Client) logoutUrl() string {
	return c.serverBaseurl + "/logout"
}

func (c *Client) obtainPublicKey(ctx context.Context) ([]byte, error) {
	res, err := ezhttp.Get(ctx, c.serverBaseurl+"/signer.pub")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	publicKey, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if len(publicKey) == 0 {
		return nil, errors.New("empty public key")
	}

	return publicKey, nil
}
