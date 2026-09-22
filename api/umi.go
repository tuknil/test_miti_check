package main

// umi.go opens the ledger Postgres connection using an Azure User-Assigned
// Managed Identity (UMI). This is the PROD path (POSTGRES_ENV=PROD, the default):
// the workload runs on Azure (Container Apps / AKS / VM) with a UMI attached, and
// the Postgres password is a short-lived Entra ID access token acquired for that
// identity per physical connection, so it is always fresh.
//
// It mirrors the reference Python client:
//
//	credential = ManagedIdentityCredential(client_id=AZURE_CLIENT_ID)
//	token = credential.get_token("https://ossrdbms-aad.database.windows.net/.default")
//	psycopg.connect(host=PG_HOST, port=5432, dbname=PG_DATABASE, user=PG_USER,
//	                password=token.token, sslmode="require")
//
// Environment variables:
//
//	PG_HOST          e.g. a36889-e2-nprd-janus-pgs-01.postgres.database.azure.com
//	PG_DATABASE      e.g. janus_defense_generation
//	PG_USER          the UMI name as registered as a Postgres AAD principal
//	AZURE_CLIENT_ID  the UMI's client ID (NOT its object/principal ID)
//	PG_SSL_MODE      optional, defaults to "require"
//	PG_PORT          optional, defaults to "5432"
//	AZURE_POSTGRES_TOKEN_SCOPE  optional, defaults to the Azure Postgres scope

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// openUMIPostgres connects to Azure Database for PostgreSQL using a User-Assigned
// Managed Identity, refreshing the Entra ID token before every new connection.
func openUMIPostgres() (*sql.DB, error) {
	host := strings.TrimSpace(os.Getenv("PG_HOST"))
	database := strings.TrimSpace(os.Getenv("PG_DATABASE"))
	user := strings.TrimSpace(os.Getenv("PG_USER"))
	clientID := strings.TrimSpace(os.Getenv("AZURE_CLIENT_ID"))
	if host == "" || database == "" || user == "" || clientID == "" {
		return nil, fmt.Errorf("POSTGRES_ENV=PROD (UMI) requires PG_HOST, PG_DATABASE, PG_USER and AZURE_CLIENT_ID")
	}
	port := firstNonEmpty(strings.TrimSpace(os.Getenv("PG_PORT")), "5432")
	sslmode := firstNonEmpty(strings.TrimSpace(os.Getenv("PG_SSL_MODE")), "require")

	// Keyword/value DSN avoids URL-encoding pitfalls; the password (AAD token) is
	// injected per connection in BeforeConnect, never stored here.
	config, err := pgx.ParseConfig(fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s sslmode=%s", host, port, database, user, sslmode))
	if err != nil {
		return nil, fmt.Errorf("parse umi db config: %w", err)
	}

	cred, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
		ID: azidentity.ClientID(clientID),
	})
	if err != nil {
		return nil, fmt.Errorf("umi credential: %w", err)
	}
	scope := firstNonEmpty(strings.TrimSpace(os.Getenv("AZURE_POSTGRES_TOKEN_SCOPE")), azurePostgresDefaultScope)

	connector := stdlib.GetConnector(*config, stdlib.OptionBeforeConnect(
		func(ctx context.Context, cc *pgx.ConnConfig) error {
			tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
			if err != nil {
				return fmt.Errorf("acquire umi token: %w", err)
			}
			cc.Password = tok.Token // AAD token is the Postgres password
			return nil
		}))
	return sql.OpenDB(connector), nil
}
