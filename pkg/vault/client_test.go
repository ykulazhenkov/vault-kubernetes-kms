package vault

import (
	"context"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/FalcoSuessgott/vault-kubernetes-kms/pkg/testutils"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type VaultSuite struct {
	suite.Suite

	tc    *testutils.TestContainer
	vault *Client
}

func TestNewClientUsesVaultCACert(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/token/lookup-self", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"data":{"id":"root","ttl":3600,"creation_ttl":3600}}`))
		require.NoError(t, err)
	}))
	defer server.Close()

	cert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	certFile := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(certFile, cert, 0o600))

	t.Setenv(vaultapi.EnvVaultCACert, certFile)

	_, err := NewClient(
		WithVaultAddress(server.URL),
		WithTokenAuth("root"),
	)
	require.NoError(t, err)
}

func (s *VaultSuite) TearDownSubTest() {
	err := s.tc.Terminate()
	if err != nil {
		log.Fatal(err)
	}
}

func (s *VaultSuite) SetupSubTest() {
	tc, err := testutils.StartTestContainer(
		"secrets enable transit",
		"write -f transit/keys/kms",
	)
	if err != nil {
		log.Fatal(err)
	}

	s.tc = tc

	vault, err := NewClient(
		WithVaultAddress(tc.URI),
		WithTokenAuth(tc.Token),
		WithTransit("transit", "kms"),
	)
	if err != nil {
		log.Fatal(err)
	}

	s.vault = vault
}

// nolint: funlen
func (s *VaultSuite) TestAuthMethods() {
	testCases := []struct {
		name    string
		prepCmd []string
		auth    func() (Option, error)
		err     bool
	}{
		{
			name: "basic approle auth",
			prepCmd: []string{
				"vault auth enable approle",
				"vault write auth/approle/role/kms token_ttl=1h",
			},
			auth: func() (Option, error) {
				roleID, secretID, err := s.tc.GetApproleCreds("approle", "kms")
				if err != nil {
					return nil, err
				}

				return WithAppRoleAuth("approle", roleID, secretID), nil
			},
		},
		{
			name: "invalid approle auth",
			err:  true,
			auth: func() (Option, error) {
				return WithAppRoleAuth("approle", "invalid", "invalid"), nil
			},
		},
		{
			name: "userpass auth",
			prepCmd: []string{
				"vault auth enable userpass",
				"vault write auth/userpass/users/kms-user password=kms-pass",
			},
			auth: func() (Option, error) {
				return WithUserPassAuth("userpass", "kms-user", "kms-pass"), nil
			},
		},
		{
			name: "invalid userpass auth",
			prepCmd: []string{
				"vault auth enable userpass",
				"vault write auth/userpass/users/kms-user password=kms-pass",
			},
			err: true,
			auth: func() (Option, error) {
				return WithUserPassAuth("userpass", "invalid", "invalid"), nil
			},
		},
		{
			name: "token auth",
			auth: func() (Option, error) {
				token, err := s.tc.GetToken("default", "1h")
				if err != nil {
					return nil, err
				}

				return WithTokenAuth(token), nil
			},
		},
		{
			name: "invalid token auth",
			auth: func() (Option, error) {
				return WithTokenAuth("invalidtoken"), nil
			},
			err: true,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			// prep vault
			for _, cmd := range tc.prepCmd {
				_, _, err := s.tc.Container.Exec(context.Background(), strings.Split(cmd, " "))
				s.Require().NoError(err, tc.name)
			}

			// perform auth
			auth, err := tc.auth()
			s.Require().NoError(err, "auth "+tc.name)

			_, err = NewClient(
				WithVaultAddress(s.tc.URI),
				WithTokenAuth(s.tc.Token),
				auth,
			)

			// assert
			s.Require().Equal(tc.err, err != nil, tc.name)
		})
	}
}

func TestVaultSuite(t *testing.T) {
	// github actions doesn't offer the docker sock, which we require for testing
	if runtime.GOOS != "windows" {
		suite.Run(t, new(VaultSuite))
	}
}
