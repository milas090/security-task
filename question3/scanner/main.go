package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	// AWS SDK
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	// GCP SDK
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	// Azure SDK
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
)

// ---------------------------------------------------------------------------
// Output structs — these define the shape of the final JSON file.
// The task requires a nested structure: provider -> resources -> insecure_rules
// ---------------------------------------------------------------------------

// InsecureRule is one rule that allows inbound traffic from the internet.
type InsecureRule struct {
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	Source   string `json:"source"` // always 0.0.0.0/0
}

// AWSGroup is one EC2 security group with its insecure rules.
type AWSGroup struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

// GCPFirewall is one GCP firewall rule with its insecure rules.
type GCPFirewall struct {
	Name          string         `json:"name"`
	Network       string         `json:"network"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

// AzureNSG is one Azure Network Security Group with its insecure rules.
type AzureNSG struct {
	Name          string         `json:"name"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

// Result is the top-level output structure written to results.json.
type Result struct {
	AWS   struct {
		SecurityGroups []AWSGroup `json:"security_groups"`
	} `json:"aws"`
	GCP   struct {
		FirewallRules []GCPFirewall `json:"firewall_rules"`
	} `json:"gcp"`
	Azure struct {
		NSGs []AzureNSG `json:"nsgs"`
	} `json:"azure"`
}

// ---------------------------------------------------------------------------
// Fetcher interface — every cloud provider implements this.
// Each Fetch() returns a flat list of rules so main can handle them uniformly.
// ---------------------------------------------------------------------------

// Rule is the flat internal representation used while scanning.
// It gets grouped into the nested Result struct before output.
type Rule struct {
	Provider string
	Resource string // security group id, firewall name, NSG name
	ResName  string // human readable name (used by AWS)
	Protocol string
	Port     string
	Source   string
}

type Fetcher interface {
	Fetch(ctx context.Context) ([]Rule, error)
}

// ---------------------------------------------------------------------------
// AWS Fetcher
// Uses the AWS SDK to list EC2 security groups and find insecure inbound rules.
// Authentication is handled automatically via the default credential chain:
// environment variables → ~/.aws/credentials → IAM role
// ---------------------------------------------------------------------------

type AwsFetcher struct{}

func (f AwsFetcher) Fetch(ctx context.Context) ([]Rule, error) {
	fmt.Println("Scanning AWS...")

	// Load AWS config — reads credentials from environment or ~/.aws/credentials
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws: failed to load config: %w", err)
	}

	// Create the EC2 client
	client := ec2.NewFromConfig(cfg)

	// Call the AWS API to get all security groups
	resp, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("aws: failed to describe security groups: %w", err)
	}

	var rules []Rule

	// Loop over each security group
	for _, sg := range resp.SecurityGroups {
		id := ""
		name := ""
		if sg.GroupId != nil {
			id = *sg.GroupId
		}
		if sg.GroupName != nil {
			name = *sg.GroupName
		}

		// Loop over each inbound rule in this security group
		for _, perm := range sg.IpPermissions {
			protocol := "all"
			if perm.IpProtocol != nil {
				protocol = *perm.IpProtocol
			}

			port := "all"
			if perm.FromPort != nil {
				port = fmt.Sprintf("%d", *perm.FromPort)
			}

			// Check if any IP range allows traffic from 0.0.0.0/0
			for _, ipRange := range perm.IpRanges {
				if ipRange.CidrIp != nil && *ipRange.CidrIp == "0.0.0.0/0" {
					rules = append(rules, Rule{
						Provider: "aws",
						Resource: id,
						ResName:  name,
						Protocol: protocol,
						Port:     port,
						Source:   "0.0.0.0/0",
					})
				}
			}
		}
	}

	return rules, nil
}

// ---------------------------------------------------------------------------
// GCP Fetcher
// Uses the Google Cloud SDK to list firewall rules and find insecure ones.
// Authentication is handled via Application Default Credentials (ADC):
// run "gcloud auth application-default login" before using this.
// ---------------------------------------------------------------------------

type GcpFetcher struct {
	ProjectID string
}

func (f GcpFetcher) Fetch(ctx context.Context) ([]Rule, error) {
	fmt.Println("Scanning GCP...")

	// Create the compute service using application default credentials
	svc, err := compute.NewService(ctx, option.WithScopes(compute.ComputeReadonlyScope))
	if err != nil {
		return nil, fmt.Errorf("gcp: failed to create compute service: %w", err)
	}

	// Call the GCP API to list all firewall rules in the project
	resp, err := svc.Firewalls.List(f.ProjectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gcp: failed to list firewall rules: %w", err)
	}

	var rules []Rule

	// Loop over each firewall rule
	for _, fw := range resp.Items {
		// Check if this rule allows traffic from 0.0.0.0/0
		openToInternet := false
		for _, src := range fw.SourceRanges {
			if src == "0.0.0.0/0" {
				openToInternet = true
				break
			}
		}
		if !openToInternet {
			continue
		}

		// Loop over each allowed protocol/port combination
		for _, allowed := range fw.Allowed {
			protocol := allowed.IPProtocol
			port := "all"
			if len(allowed.Ports) > 0 {
				port = allowed.Ports[0]
			}

			rules = append(rules, Rule{
				Provider: "gcp",
				Resource: fw.Name,
				ResName:  fw.Network,
				Protocol: protocol,
				Port:     port,
				Source:   "0.0.0.0/0",
			})
		}
	}

	return rules, nil
}

// ---------------------------------------------------------------------------
// Azure Fetcher
// Uses the Azure SDK to list Network Security Groups and find insecure rules.
// Authentication uses DefaultAzureCredential which tries multiple methods:
// environment variables → managed identity → Azure CLI login
// ---------------------------------------------------------------------------

type AzureFetcher struct {
	SubscriptionID string
}

func (f AzureFetcher) Fetch(ctx context.Context) ([]Rule, error) {
	fmt.Println("Scanning Azure...")

	// DefaultAzureCredential tries env vars, managed identity, and az login automatically
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure: failed to get credentials: %w", err)
	}

	// Create the NSG client
	client, err := armnetwork.NewSecurityGroupsClient(f.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: failed to create NSG client: %w", err)
	}

	var rules []Rule

	// ListAll returns all NSGs across all resource groups in the subscription
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("azure: failed to list NSGs: %w", err)
		}

		// Loop over each NSG in this page
		for _, nsg := range page.Value {
			name := ""
			if nsg.Name != nil {
				name = *nsg.Name
			}

			if nsg.Properties == nil || nsg.Properties.SecurityRules == nil {
				continue
			}

			// Loop over each rule in this NSG
			for _, rule := range nsg.Properties.SecurityRules {
				if rule.Properties == nil {
					continue
				}

				// We only care about inbound Allow rules
				if rule.Properties.Direction != nil &&
					*rule.Properties.Direction != armnetwork.SecurityRuleDirectionInbound {
					continue
				}
				if rule.Properties.Access != nil &&
					*rule.Properties.Access != armnetwork.SecurityRuleAccessAllow {
					continue
				}

				// Azure uses "0.0.0.0/0", "*", or "Internet" to mean open to the internet
				src := ""
				if rule.Properties.SourceAddressPrefix != nil {
					src = *rule.Properties.SourceAddressPrefix
				}
				if src != "0.0.0.0/0" && src != "*" && src != "Internet" {
					continue
				}

				protocol := ""
				if rule.Properties.Protocol != nil {
					protocol = string(*rule.Properties.Protocol)
				}

				port := ""
				if rule.Properties.DestinationPortRange != nil {
					port = *rule.Properties.DestinationPortRange
				}

				rules = append(rules, Rule{
					Provider: "azure",
					Resource: name,
					Protocol: protocol,
					Port:     port,
					Source:   "0.0.0.0/0",
				})
			}
		}
	}

	return rules, nil
}

// ---------------------------------------------------------------------------
// groupResults takes the flat list of rules and groups them into the
// nested Result structure that the task requires for JSON output.
// ---------------------------------------------------------------------------

func groupResults(rules []Rule) Result {
	var result Result

	// Maps to group rules by resource name so we don't create duplicate entries
	awsGroups := make(map[string]*AWSGroup)
	gcpFirewalls := make(map[string]*GCPFirewall)
	azureNSGs := make(map[string]*AzureNSG)

	for _, r := range rules {
		insecure := InsecureRule{
			Protocol: r.Protocol,
			Port:     r.Port,
			Source:   r.Source,
		}

		switch r.Provider {
		case "aws":
			// Group by security group ID
			if _, exists := awsGroups[r.Resource]; !exists {
				awsGroups[r.Resource] = &AWSGroup{
					ID:   r.Resource,
					Name: r.ResName,
				}
			}
			awsGroups[r.Resource].InsecureRules = append(awsGroups[r.Resource].InsecureRules, insecure)

		case "gcp":
			// Group by firewall rule name
			if _, exists := gcpFirewalls[r.Resource]; !exists {
				gcpFirewalls[r.Resource] = &GCPFirewall{
					Name:    r.Resource,
					Network: r.ResName,
				}
			}
			gcpFirewalls[r.Resource].InsecureRules = append(gcpFirewalls[r.Resource].InsecureRules, insecure)

		case "azure":
			// Group by NSG name
			if _, exists := azureNSGs[r.Resource]; !exists {
				azureNSGs[r.Resource] = &AzureNSG{
					Name: r.Resource,
				}
			}
			azureNSGs[r.Resource].InsecureRules = append(azureNSGs[r.Resource].InsecureRules, insecure)
		}
	}

	// Convert maps to slices for the final output
	for _, g := range awsGroups {
		result.AWS.SecurityGroups = append(result.AWS.SecurityGroups, *g)
	}
	for _, f := range gcpFirewalls {
		result.GCP.FirewallRules = append(result.GCP.FirewallRules, *f)
	}
	for _, n := range azureNSGs {
		result.Azure.NSGs = append(result.Azure.NSGs, *n)
	}

	// Make sure we output empty arrays instead of null
	if result.AWS.SecurityGroups == nil {
		result.AWS.SecurityGroups = []AWSGroup{}
	}
	if result.GCP.FirewallRules == nil {
		result.GCP.FirewallRules = []GCPFirewall{}
	}
	if result.Azure.NSGs == nil {
		result.Azure.NSGs = []AzureNSG{}
	}

	return result
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	fmt.Println("==========================================")
	fmt.Println("       Cloud Security Scanner            ")
	fmt.Println("==========================================")
	fmt.Println()
	fmt.Println("Scans AWS, GCP and Azure for firewall rules open to the internet.")
	fmt.Println()
	fmt.Println("Make sure you're authenticated before running:")
	fmt.Println("  AWS   -> aws configure")
	fmt.Println("  GCP   -> gcloud auth application-default login")
	fmt.Println("  Azure -> az login")
	fmt.Println()
	fmt.Println("Press Enter to start, Ctrl+C to exit...")
	fmt.Scanln()

	ctx := context.Background()

	// All three fetchers in one slice.
	// To add a new provider, just add its fetcher here.
	fetchers := []Fetcher{
		AwsFetcher{},
		GcpFetcher{
			ProjectID: os.Getenv("GCP_PROJECT_ID"), // set this env var before running
		},
		AzureFetcher{
			SubscriptionID: os.Getenv("AZURE_SUBSCRIPTION_ID"), // set this env var before running
		},
	}

	// Loop over each provider and collect all insecure rules into one flat list
	var allRules []Rule
	for _, fetcher := range fetchers {
		rules, err := fetcher.Fetch(ctx)
		if err != nil {
			// Print a warning but keep going — don't stop because one provider failed
			fmt.Println("warning:", err)
			continue
		}
		allRules = append(allRules, rules...)
	}

	// Group the flat list into the nested output structure the task requires
	result := groupResults(allRules)

	// Write the results to a file with permission 0600 (only current user can read it)
	// This is safer than printing to stdout which can end up in logs
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Println("error building output:", err)
		return
	}

	err = os.WriteFile("results.json", output, 0600)
	if err != nil {
		fmt.Println("error writing results.json:", err)
		return
	}

	fmt.Println("Done. Results written to results.json")
}
