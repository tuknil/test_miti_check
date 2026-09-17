package main

// db.go opens the Postgres connection for the run ledger. Two auth modes:
//
//   - DATABASE_AUTH_MODE=entra: Azure Database for PostgreSQL with Microsoft
//     Entra ID. The connection is built from DATABASE_HOST/PORT/NAME/USER/SSL_MODE
//     and the password is a short-lived Entra ID access token acquired per
//     connection (pgx BeforeConnect), so it is always fresh. The token is obtained
//     from an explicit service principal (AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET)
//     when set, else DefaultAzureCredential (e.g. a managed identity on Azure).
//
//   - anything else (default): DATABASE_URL with a static password (local/dev).

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// azurePostgresDefaultScope is the AAD token scope for Azure Database for
// PostgreSQL when AZURE_POSTGRES_TOKEN_SCOPE is not set.
const azurePostgresDefaultScope = "https://ossrdbms-aad.database.windows.net/.default"

// openLedgerDB opens the ledger database according to DATABASE_AUTH_MODE.
func openLedgerDB() (*sql.DB, error) {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("DATABASE_AUTH_MODE")), "entra") {
		return openEntraPostgres()
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://mc:mc@localhost:5432/mitigation?sslmode=disable"
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	return db, nil
}

// openEntraPostgres connects to Azure Postgres using an Entra ID token as the
// password, refreshed before every new physical connection.
func openEntraPostgres() (*sql.DB, error) {
	host := strings.TrimSpace(os.Getenv("DATABASE_HOST"))
	name := strings.TrimSpace(os.Getenv("DATABASE_NAME"))
	user := strings.TrimSpace(os.Getenv("DATABASE_USER"))
	if host == "" || name == "" || user == "" {
		return nil, fmt.Errorf("DATABASE_AUTH_MODE=entra requires DATABASE_HOST, DATABASE_NAME and DATABASE_USER")
	}
	port := firstNonEmpty(strings.TrimSpace(os.Getenv("DATABASE_PORT")), "5432")
	sslmode := firstNonEmpty(strings.TrimSpace(os.Getenv("DATABASE_SSL_MODE")), "verify-full")

	// Keyword/value DSN avoids URL-encoding pitfalls; the password is set per
	// connection in BeforeConnect, never here.
	config, err := pgx.ParseConfig(fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s sslmode=%s", host, port, name, user, sslmode))
	if err != nil {
		return nil, fmt.Errorf("parse db config: %w", err)
	}

	cred, err := newAzurePostgresCredential()
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	scope := firstNonEmpty(strings.TrimSpace(os.Getenv("AZURE_POSTGRES_TOKEN_SCOPE")), azurePostgresDefaultScope)

	connector := stdlib.GetConnector(*config, stdlib.OptionBeforeConnect(
		func(ctx context.Context, cc *pgx.ConnConfig) error {
			tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
			if err != nil {
				return fmt.Errorf("acquire entra token: %w", err)
			}
			cc.Password = tok.Token // AAD token is the Postgres password
			return nil
		}))
	return sql.OpenDB(connector), nil
}

// newAzurePostgresCredential prefers an explicit service principal
// (AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET all set); otherwise
// DefaultAzureCredential (env / managed identity / az login).
func newAzurePostgresCredential() (azcore.TokenCredential, error) {
	tenant := strings.TrimSpace(os.Getenv("AZURE_TENANT_ID"))
	clientID := strings.TrimSpace(os.Getenv("AZURE_CLIENT_ID"))
	secret := strings.TrimSpace(os.Getenv("AZURE_CLIENT_SECRET"))
	if tenant != "" && clientID != "" && secret != "" {
		return azidentity.NewClientSecretCredential(tenant, clientID, secret, nil)
	}
	return azidentity.NewDefaultAzureCredential(nil)
}
