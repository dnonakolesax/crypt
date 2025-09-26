package vault

import (
	"testing"
	"os"
	"time"
	"strings"
	"github.com/stretchr/testify/assert"
)

var vaultAddr string = os.Getenv("VAULT_TEST_ADDR")
var vaultUsername string = os.Getenv("VAULT_TEST_USERNAME")
var vaultPassword string = os.Getenv("VAULT_TEST_PASSWORD")
var vaultReady string = os.Getenv("VAULT_READY")

func TestKV2(t *testing.T) {
	if vaultReady == "" {
		t.Log("Vault not ready, skipping test")
		return
	}
	
	println(vaultAddr, vaultUsername, vaultPassword)
	v, err := New("http://172.30.0.3:8200", vaultUsername, vaultPassword)

	assert.Nil(t, err)

	val, err := v.Get("sample/samplesecret:sampledata")

	assert.Nil(t, err)
	assert.Equal(t, []byte("samplevalue"), val)

	stopChan := make(chan bool)

	monitorChan := v.Watch("sample/samplesecret:sampledata", stopChan)

	timeout := time.NewTimer(time.Second*15)

	for {
		select {
		case <-timeout.C:
			stopChan <- true
			return
		case resp := <-monitorChan:
			assert.Nil(t, resp.Error)
		}
	}
}

func TestDatabase(t *testing.T) {
	if vaultReady == "" {
		t.Log("Vault not ready, skipping test")
		return
	}
	
	v, err := New(vaultAddr, vaultUsername, vaultPassword)
	
	assert.Nil(t, err)

	val, err := v.Get("database/kc-sesson-selector")
	
	assert.Nil(t, err)
	assert.True(t, strings.HasPrefix(string(val), "v-userpass-kc-sesso"))

	stopChan := make(chan bool)

	monitorChan := v.Watch("database/kc-sesson-selector", stopChan)

	timeout := time.NewTimer(time.Second*15)

	for {
		select {
		case <-timeout.C:
			stopChan <- true
			return
		case resp := <-monitorChan:
			assert.Nil(t, resp.Error)
			assert.True(t, strings.HasPrefix(string(val), "v-userpass-kc-sesso"))
		}
	}
}
