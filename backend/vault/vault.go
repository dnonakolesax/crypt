package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/sagikazarmark/crypt/backend"
)

type Client struct {
	client    *vault.Client
	vaults    map[string]string
	waitIndex uint64
}

func isVersionable(vtype string) bool {
	return vtype == "kv"
}

func isLeasable(vtype string) bool {
	return vtype == "database"
}

func (c *Client) ConfigureVault() error {
	vaults, err := c.client.System.InternalUiListEnabledVisibleMounts(context.Background())

	if err != nil {
		return err
	}
	c.vaults = make(map[string]string, len(vaults.Data.Secret))
	for vault, data := range vaults.Data.Secret {
		if strings.HasPrefix(vault, "sys/") || vault == "cubbyhole/" || vault == "identity/" {
			continue
		}
		dataMap := data.(map[string]any)
		c.vaults[vault] = dataMap["type"].(string)
	}
	return nil
}

func New(address string, login string, password string) (*Client, error) {
	vClient, err := vault.New(vault.WithAddress(address))
	if err != nil {
		return nil, err
	}
	resp, err := vClient.Auth.UserpassLogin(context.Background(), login, schema.UserpassLoginRequest{
		Password: password,
	})
	if err != nil {
		return nil, err
	}
	err = vClient.SetToken(resp.Auth.ClientToken)
	if err != nil {
		return nil, err
	}
	client := &Client{client: vClient, waitIndex: 0}

	err = client.ConfigureVault()

	if err != nil {
		return nil, err
	}

	return client, nil
}

func (c *Client) getKV2(mountPath string, key string, secretName string) ([]byte, int, error) {
	data, err := c.client.Secrets.KvV2Read(context.Background(), key, vault.WithMountPath(mountPath))
	if err != nil {
		return nil, 0, err
	}
	secret, ok := data.Data.Data[secretName].(string)

	if !ok {
		return nil, 0, fmt.Errorf("Secret ( %s ) does not exist.", secretName)
	}
	version, err := data.Data.Metadata["version"].(json.Number).Int64()
	if err != nil {
		return nil, 0, err
	}
	return []byte(secret), int(version), nil
}

func (c *Client) getDBCreds(mountPath string, role string) ([]byte, int, error) {
	data, err := c.client.Secrets.DatabaseGenerateCredentials(context.Background(), role, vault.WithMountPath(mountPath))
	if err != nil {
		return nil, 0, err
	}
	username := data.Data["username"].(string)
	password := data.Data["password"].(string)
	lifetime := data.LeaseDuration
	return []byte(username + ":" + password), lifetime, nil
}

func (c *Client) getVaultTypePath(key string) (string, string, error) {
	var vaultType, mountPath string
	for vault, vtype := range c.vaults {
		if strings.HasPrefix(key, vault) {
			vaultType = vtype
			mountPath = vault[:len(vault)-1]
			return vaultType, mountPath, nil
		}
	}
	return "", "", fmt.Errorf("Secrets engine for key ( %s ) does not exist.", key)
}

func (c *Client) get(key string) ([]byte, int, error) {
	vaultType, mountPath, err := c.getVaultTypePath(key)
	key = strings.TrimPrefix(key, mountPath+"/")
	if err != nil {
		return nil, 0, err
	}
	switch vaultType {
	case "kv":
		keyWithName := strings.Split(key, ":")
		return c.getKV2(mountPath, keyWithName[0], keyWithName[1])
	case "database":
		return c.getDBCreds(mountPath, key)
	}
	return nil, 0, fmt.Errorf("Vault type ( %s ) is not supported.", vaultType)
}

func (c *Client) Get(key string) ([]byte, error) {
	bts, _, err := c.get(key)
	return bts, err
}

func (c *Client) List(key string) (backend.KVPairs, error) {
	panic("Not implemented")
}

func (c *Client) Set(key string, value []byte) error {
	panic("Not implemented")
}

func (c *Client) WatchVersionable(key string, stop chan bool) chan *backend.Response {
	respChan := make(chan *backend.Response, 0)

	go func() {
		bytes, oldVersion, err := c.get(key)
		if err != nil {
			respChan <- &backend.Response{Value: nil, Error: err}
			return
		}
		respChan <- &backend.Response{Value: bytes, Error: err}

		tt := time.NewTicker(time.Second * 5)

		for {
			select {
			case <-stop:
				return
			case <-tt.C:
				bts, version, err := c.get(key)
				if err != nil {
					respChan <- &backend.Response{Value: nil, Error: err}
					return
				}
				if version > oldVersion {
					oldVersion = version
					respChan <- &backend.Response{Value: bts, Error: nil}
				}
			}
		}
	}()

	return respChan
}

func (c *Client) WatchLeasable(key string, stop chan bool) chan *backend.Response {
	respChan := make(chan *backend.Response, 0)

	go func() {
		bytes, leaseDuration, err := c.get(key)

		if err != nil {
			respChan <- &backend.Response{Value: bytes, Error: nil}
			return
		}
		respChan <- &backend.Response{Value: bytes, Error: nil}

		tt := time.NewTicker(time.Second * time.Duration(leaseDuration))

		for {
			select {
			case <-stop:
				return
			case <-tt.C:
				bts, ld, err := c.get(key)
				if err != nil {
					respChan <- &backend.Response{Value: nil, Error: err}
					return
				}
				respChan <- &backend.Response{Value: bts, Error: nil}
				if ld != leaseDuration {
					tt = time.NewTicker(time.Second * time.Duration(ld))
				}
			}
		}
	}()

	return respChan
}

func (c *Client) Watch(key string, stop chan bool) <-chan *backend.Response {
	respChan := make(chan *backend.Response, 0)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done() // Ожидаем формирования канала для секрета
		vtype, _, err := c.getVaultTypePath(key)
		if err != nil {
			respChan <- &backend.Response{Value: nil, Error: err}
			return
		}
		if isLeasable(vtype) {
			respChan = c.WatchLeasable(key, stop)
			return
		} else if isVersionable(vtype) {
			respChan = c.WatchVersionable(key, stop)
			return
		}
		respChan <- &backend.Response{Value: nil, Error: fmt.Errorf("Vault type ( %s ) is not watchable.", vtype)}
	}()
	wg.Wait()
	return respChan
}
