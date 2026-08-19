package main

// substrate_aci.go is the ACA-compatible substrate adapter (LLD §3.3, §6.4).
//
// Azure Container Apps cannot mount the host Docker socket or launch sibling
// containers, so when the API runs on ACA the substrate is brought up as an
// Azure Container Instance (ACI) container group instead: create per run, reach
// it over the network, run the test, then delete it. The verdict logic is shared
// with the local-docker path — only the bring-up/teardown differ.
//
// It authenticates with DefaultAzureCredential (a managed identity on ACA, or
// env/az-cli locally) and needs, at minimum:
//   AZURE_SUBSCRIPTION_ID, MC_ACI_RESOURCE_GROUP, MC_ACI_REGION
// When those are unset the adapter returns a could-not-test reason rather than
// failing, so the mode is selectable everywhere; real execution needs Azure.

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance/v2"
)

const aciSubstratePort int32 = 8080

// bringUpACISubstrate creates a per-run ACI container group for the substrate.
func aciConfig() (subID, rg, region string, ok bool) {
	subID = os.Getenv("AZURE_SUBSCRIPTION_ID")
	rg = os.Getenv("MC_ACI_RESOURCE_GROUP")
	region = os.Getenv("MC_ACI_REGION")
	ok = subID != "" && rg != "" && region != ""
	return
}

// bringUpACISubstrate (mode "aci") authenticates with DefaultAzureCredential —
// managed identity on Azure, or env/az-cli locally.
func bringUpACISubstrate(ctx context.Context, out *RunOutcome, sub SubstrateSpec, runID string) (*substrate, string) {
	subID, rg, region, ok := aciConfig()
	if !ok {
		return nil, "azure ACI not configured (set AZURE_SUBSCRIPTION_ID, MC_ACI_RESOURCE_GROUP, MC_ACI_REGION)"
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, "azure credential unavailable: " + err.Error()
	}
	return bringUpACIWith(ctx, out, sub, runID, cred, subID, rg, region)
}

// bringUpACISPSubstrate (mode "aci-sp") authenticates with an explicit service
// principal (AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET) — portable
// to a laptop or ACA via env vars, no managed identity required.
func bringUpACISPSubstrate(ctx context.Context, out *RunOutcome, sub SubstrateSpec, runID string) (*substrate, string) {
	subID, rg, region, ok := aciConfig()
	if !ok {
		return nil, "azure ACI not configured (set AZURE_SUBSCRIPTION_ID, MC_ACI_RESOURCE_GROUP, MC_ACI_REGION)"
	}
	tenant := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	secret := os.Getenv("AZURE_CLIENT_SECRET")
	if tenant == "" || clientID == "" || secret == "" {
		return nil, "azure service principal not configured (set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)"
	}
	cred, err := azidentity.NewClientSecretCredential(tenant, clientID, secret, nil)
	if err != nil {
		return nil, "azure service principal credential error: " + err.Error()
	}
	return bringUpACIWith(ctx, out, sub, runID, cred, subID, rg, region)
}

// bringUpACIWith creates the per-run ACI container group using the given
// credential. Shared by the managed-identity and service-principal modes.
func bringUpACIWith(ctx context.Context, out *RunOutcome, sub SubstrateSpec, runID string, cred azcore.TokenCredential, subID, rg, region string) (*substrate, string) {
	// Don't attempt subscription-level resource-provider registration: that is a
	// one-time admin bootstrap (az provider register -n Microsoft.ContainerInstance),
	// not something the API's least-privilege identity should need or be able to do.
	opts := &arm.ClientOptions{DisableRPRegistration: true}
	factory, err := armcontainerinstance.NewClientFactory(subID, cred, opts)
	if err != nil {
		return nil, "azure client init failed: " + err.Error()
	}
	client := factory.NewContainerGroupsClient()

	name := aciName(runID) // valid container-group / DNS label
	group := armcontainerinstance.ContainerGroup{
		Location: to.Ptr(region),
		Properties: &armcontainerinstance.ContainerGroupPropertiesProperties{
			OSType:        to.Ptr(armcontainerinstance.OperatingSystemTypesLinux),
			RestartPolicy: to.Ptr(armcontainerinstance.ContainerGroupRestartPolicyNever),
			Containers: []*armcontainerinstance.Container{{
				Name: to.Ptr("substrate"),
				Properties: &armcontainerinstance.ContainerProperties{
					Image: to.Ptr(sub.Image),
					Ports: []*armcontainerinstance.ContainerPort{{Port: to.Ptr(aciSubstratePort)}},
					Resources: &armcontainerinstance.ResourceRequirements{
						Requests: &armcontainerinstance.ResourceRequests{
							CPU:        to.Ptr(envFloat("MC_ACI_CPU", 1.0)),
							MemoryInGB: to.Ptr(envFloat("MC_ACI_MEMORY_GB", 1.5)),
						},
					},
				},
			}},
			IPAddress: &armcontainerinstance.IPAddress{
				Type:         to.Ptr(armcontainerinstance.ContainerGroupIPAddressTypePublic),
				DNSNameLabel: to.Ptr(name),
				Ports: []*armcontainerinstance.Port{{
					Protocol: to.Ptr(armcontainerinstance.ContainerGroupNetworkProtocolTCP),
					Port:     to.Ptr(aciSubstratePort),
				}},
			},
		},
	}
	if creds := aciRegistryCredential(); creds != nil {
		group.Properties.ImageRegistryCredentials = []*armcontainerinstance.ImageRegistryCredential{creds}
	}

	out.Steps = append(out.Steps, "creating ACI container group "+name+" ("+sub.Image+") in "+rg+"/"+region)
	poller, err := client.BeginCreateOrUpdate(ctx, rg, name, group, nil)
	if err != nil {
		return nil, "ACI create failed: " + trimErr(err)
	}
	cleanup := aciDeleter(client, rg, name)

	resp, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		cleanup()
		return nil, "ACI provisioning failed: " + trimErr(err)
	}

	host := aciHost(resp.ContainerGroup)
	if host == "" {
		cleanup()
		return nil, "ACI group has no reachable address"
	}
	out.Substrate.ContainerID = name
	out.Substrate.HostPort = int(aciSubstratePort)
	if resp.Properties != nil && resp.Properties.IPAddress != nil && resp.Properties.IPAddress.Fqdn != nil {
		out.Substrate.FQDN = *resp.Properties.IPAddress.Fqdn
	}
	base := fmt.Sprintf("http://%s:%d", host, aciSubstratePort)
	out.Steps = append(out.Steps, "ACI group running at "+base)
	return &substrate{base: base, cleanup: cleanup}, ""
}

// aciHost prefers the assigned FQDN, falling back to the public IP.
func aciHost(g armcontainerinstance.ContainerGroup) string {
	if g.Properties == nil || g.Properties.IPAddress == nil {
		return ""
	}
	ip := g.Properties.IPAddress
	if ip.Fqdn != nil && *ip.Fqdn != "" {
		return *ip.Fqdn
	}
	if ip.IP != nil {
		return *ip.IP
	}
	return ""
}

// aciDeleter returns an idempotent teardown that issues the group delete. It does
// not block on completion (ACI removes it asynchronously); a fresh short-lived
// context is used so teardown still runs when the request context is done.
func aciDeleter(client *armcontainerinstance.ContainerGroupsClient, rg, name string) func() {
	var done bool
	return func() {
		if done {
			return
		}
		done = true
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := client.BeginDelete(c, rg, name, nil); err != nil {
			// Best-effort: log-only; an orphaned group is an ops concern, not a
			// reason to rewrite an already-durable domain result.
			fmt.Fprintf(os.Stderr, "aci: delete %s failed: %v\n", name, err)
		}
	}
}

// aciRegistryCredential builds registry auth for a private image, from
// MC_ACI_REGISTRY_* or the JFROG_* vars, if present.
func aciRegistryCredential() *armcontainerinstance.ImageRegistryCredential {
	server := firstNonEmpty(os.Getenv("MC_ACI_REGISTRY_SERVER"), os.Getenv("JFROG_REGISTRY"))
	user := firstNonEmpty(os.Getenv("MC_ACI_REGISTRY_USERNAME"), os.Getenv("JFROG_USER"))
	pass := firstNonEmpty(os.Getenv("MC_ACI_REGISTRY_PASSWORD"), os.Getenv("JFROG_TOKEN"))
	if server == "" || user == "" || pass == "" {
		return nil
	}
	return &armcontainerinstance.ImageRegistryCredential{
		Server:   to.Ptr(server),
		Username: to.Ptr(user),
		Password: to.Ptr(pass),
	}
}

// aciName normalizes runID to a valid container-group / DNS label:
// lowercase alphanumeric and hyphens, starting/ending alphanumeric, <= 63 chars.
func aciName(runID string) string {
	s := strings.ToLower(runID)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "mc-run"
	}
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-")
	}
	return out
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
