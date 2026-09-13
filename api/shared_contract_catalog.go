package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"sort"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	attackMatchSemanticsSchemaID = "https://schemas.janus.internal/contracts/attack-match-semantics/attack-match-semantics-2.0.schema.json"
	candidateBundleSchemaID      = "https://schemas.janus.internal/contracts/candidate-bundle/candidate-bundle-1.0.schema.json"
	sharedCatalogDigestProfile   = "sha256-tab-delimited-schema-catalog-v1"
)

//go:embed contracts/shared-attack-contracts/manifest.json contracts/shared-attack-contracts/schemas/**/*.json contracts/shared-attack-contracts/profiles/*.json
var sharedContractFiles embed.FS

type sharedCatalogManifest struct {
	ManifestVersion int                        `json:"manifest_version"`
	BundleVersion   string                     `json:"bundle_version"`
	DigestProfile   string                     `json:"digest_profile"`
	BundleDigest    string                     `json:"bundle_digest"`
	Schemas         []sharedCatalogSchemaEntry `json:"schemas"`
}

type sharedCatalogSchemaEntry struct {
	ID           string `json:"$id"`
	RelativePath string `json:"relative_path"`
	SHA256       string `json:"sha256"`
	ByteLength   int64  `json:"byte_length"`
}

type sharedSchemaCatalog struct {
	compiled map[string]*jsonschema.Schema
}

var embeddedSharedCatalog, embeddedSharedCatalogErr = loadSharedSchemaCatalog(sharedContractFiles)
var embeddedRouteProfileErr = verifyEmbeddedRouteProfile(sharedContractFiles)

func verifyEmbeddedRouteProfile(files fs.FS) error {
	manifestBytes, err := fs.ReadFile(files, "contracts/shared-attack-contracts/profiles/manifest.json")
	if err != nil {
		return err
	}
	var manifest struct {
		ManifestVersion       int    `json:"manifest_version"`
		ProfileID             string `json:"profile_id"`
		ResolverID            string `json:"resolver_id"`
		RegistryID            string `json:"registry_id"`
		RelativePath          string `json:"relative_path"`
		SHA256                string `json:"sha256"`
		ByteLength            int64  `json:"byte_length"`
		ResolverProfileDigest string `json:"resolver_profile_digest"`
	}
	if err := decodeStrictJSON(manifestBytes, &manifest); err != nil {
		return err
	}
	if manifest.ManifestVersion != 1 || manifest.ProfileID != sharedV2ProfileID || manifest.ResolverID != sharedV2ResolverID || manifest.RegistryID != "janus-approved-test-routes" || manifest.RelativePath != "mc-http-route-profile.json" || manifest.ResolverProfileDigest != sharedV2ResolverProfileDigest {
		return errors.New("route profile manifest identity differs")
	}
	profileBytes, err := fs.ReadFile(files, "contracts/shared-attack-contracts/profiles/"+manifest.RelativePath)
	if err != nil || int64(len(profileBytes)) != manifest.ByteLength || sha256Value(profileBytes) != manifest.SHA256 {
		return errors.New("route profile bytes differ from manifest")
	}
	var profile struct {
		ProfileID  string                                              `json:"profile_id"`
		ResolverID string                                              `json:"resolver_id"`
		RegistryID string                                              `json:"registry_id"`
		Routes     map[string]struct{ Scheme, Authority, Path string } `json:"routes"`
	}
	if err := decodeStrictJSON(profileBytes, &profile); err != nil {
		return err
	}
	route, ok := profile.Routes["inventory-item-detail"]
	var profileValue any
	canonicalErr := decodeJSONAny(profileBytes, &profileValue)
	canonical, err := marshalRFC8785(profileValue)
	if canonicalErr != nil || err != nil || profile.ProfileID != sharedV2ProfileID || profile.ResolverID != sharedV2ResolverID || profile.RegistryID != "janus-approved-test-routes" || len(profile.Routes) != 1 || !ok || route.Scheme != "https" || route.Authority != "approved-mc-target.internal" || route.Path != "/inventory/items/42" || sha256Value(canonical) != manifest.ResolverProfileDigest {
		return errors.New("route profile content differs from approved registry")
	}
	return nil
}

func validateSharedSchema(schemaID string, document any) error {
	if embeddedSharedCatalogErr != nil {
		return fmt.Errorf("embedded shared-contract catalog integrity: %w", embeddedSharedCatalogErr)
	}
	schema := embeddedSharedCatalog.compiled[schemaID]
	if schema == nil {
		return fmt.Errorf("schema %s is not in the offline catalog", schemaID)
	}
	return schema.Validate(document)
}

func loadSharedSchemaCatalog(files fs.FS) (*sharedSchemaCatalog, error) {
	manifestBytes, err := fs.ReadFile(files, "contracts/shared-attack-contracts/manifest.json")
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var manifest sharedCatalogManifest
	if err := decodeStrictJSON(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if manifest.ManifestVersion != 1 || manifest.BundleVersion == "" || manifest.DigestProfile != sharedCatalogDigestProfile || len(manifest.Schemas) != 3 {
		return nil, errors.New("manifest identity, digest profile, or schema count is invalid")
	}
	entries := append([]sharedCatalogSchemaEntry(nil), manifest.Schemas...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	ids, paths := map[string]bool{}, map[string]bool{}
	documents := map[string]any{}
	hasher := sha256.New()
	for _, entry := range entries {
		if entry.ID == "" || ids[entry.ID] || entry.RelativePath == "" || paths[entry.RelativePath] || !validSHA256(entry.SHA256) || entry.ByteLength < 1 {
			return nil, errors.New("manifest contains an invalid or duplicate schema entry")
		}
		ids[entry.ID], paths[entry.RelativePath] = true, true
		path := "contracts/shared-attack-contracts/" + entry.RelativePath
		content, err := fs.ReadFile(files, path)
		if err != nil {
			return nil, fmt.Errorf("read schema %s: %w", entry.RelativePath, err)
		}
		if int64(len(content)) != entry.ByteLength || sha256Value(content) != entry.SHA256 {
			return nil, fmt.Errorf("schema %s differs from immutable manifest", entry.RelativePath)
		}
		var document any
		if err := decodeStrictJSON(content, &document); err != nil {
			return nil, fmt.Errorf("decode schema %s: %w", entry.RelativePath, err)
		}
		object, ok := document.(map[string]any)
		if !ok || object["$id"] != entry.ID {
			return nil, fmt.Errorf("schema %s $id differs from manifest", entry.RelativePath)
		}
		documents[entry.ID] = document
		fmt.Fprintf(hasher, "%s\t%s\t%s\t%d\n", entry.ID, entry.RelativePath, entry.SHA256, entry.ByteLength)
	}
	if got := "sha256:" + hex.EncodeToString(hasher.Sum(nil)); got != manifest.BundleDigest {
		return nil, fmt.Errorf("schema bundle digest differs: got %s", got)
	}
	for id, document := range documents {
		if err := verifyOfflineSchemaRefs(id, document, ids); err != nil {
			return nil, err
		}
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiler.AssertContent()
	for id, document := range documents {
		if err := compiler.AddResource(id, document); err != nil {
			return nil, fmt.Errorf("add schema resource %s: %w", id, err)
		}
	}
	compiled := map[string]*jsonschema.Schema{}
	for id := range documents {
		schema, err := compiler.Compile(id)
		if err != nil {
			return nil, fmt.Errorf("compile schema %s: %w", id, err)
		}
		compiled[id] = schema
	}
	return &sharedSchemaCatalog{compiled: compiled}, nil
}

func verifyOfflineSchemaRefs(baseID string, value any, known map[string]bool) error {
	base, err := url.Parse(baseID)
	if err != nil {
		return err
	}
	var walk func(any) error
	walk = func(current any) error {
		switch typed := current.(type) {
		case map[string]any:
			if raw, ok := typed["$ref"]; ok {
				ref, ok := raw.(string)
				if !ok {
					return fmt.Errorf("schema %s contains a non-string $ref", baseID)
				}
				parsed, err := url.Parse(ref)
				if err != nil {
					return fmt.Errorf("schema %s contains invalid $ref %q", baseID, ref)
				}
				resolved := base.ResolveReference(parsed)
				resolved.Fragment = ""
				if target := resolved.String(); target != baseID && !known[target] {
					return fmt.Errorf("schema %s references missing offline resource %s", baseID, target)
				}
			}
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value)
}

// decodeStrictJSON rejects duplicate object keys at every depth, trailing data,
// unknown fields for typed destinations, and non-I-JSON number syntax before a
// document is eligible for RFC 8785 verification.
func decodeStrictJSON(content []byte, target any) error {
	if err := rejectDuplicateJSONKeys(content); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if _, generic := target.(*any); !generic {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("JSON document contains trailing data")
	}
	return nil
}

func rejectDuplicateJSONKeys(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	var value func() error
	value = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if seen[key] {
					return fmt.Errorf("duplicate JSON object key %q", key)
				}
				seen[key] = true
				if err := value(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := value(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("JSON document contains trailing data")
		}
		return err
	}
	return nil
}
