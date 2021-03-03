package idclient

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/url"

	"github.com/function61/gokit/ezhttp"
	"github.com/function61/id/pkg/idtypes"
	"gopkg.in/square/go-jose.v2"
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

func (c *Client) obtainPublicKey(ctx context.Context) (ed25519.PublicKey, error) {
	keySet := jose.JSONWebKeySet{}
	if _, err := ezhttp.Get(
		ctx,
		c.serverBaseurl+"/.well-known/jwks.json",
		ezhttp.RespondsJson(&keySet, true),
	); err != nil {
		return nil, err
	}

	if len(keySet.Keys) == 0 {
		return nil, fmt.Errorf("got %d key(s)", len(keySet.Keys))
	}

	// TODO: take into account multiple keys (key rollover)
	firstKey := keySet.Keys[0]

	keyInterface := firstKey.Public().Key

	return keyInterface.(ed25519.PublicKey), nil
}
