// Terratest suite for the lab's modules.
//
//	TestUnit*         plan a fixture OFFLINE (faked credentials, no AWS calls) and
//	                  assert on the planned resources. Runs on every push.
//	TestIntegration*  apply a fixture in the sandbox account, assert against the
//	                  real resources with the AWS SDK, destroy. Skipped unless
//	                  TERRATEST_LIVE=1 (set only by .github/workflows/live.yml).
//
// Integration state goes to TERRATEST_STATE_BUCKET under
// terratest/<fixture>/<prefix>/ so the sandbox janitor can destroy stacks left
// by a crashed run (Go does not run deferred cleanup when `go test -timeout`
// fires).
package test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	teststructure "github.com/gruntwork-io/terratest/modules/test-structure"
	"github.com/stretchr/testify/require"
)

const unitPrefix = "tt-unit"

// Terraform's plugin cache (TF_PLUGIN_CACHE_DIR, set in CI) is not safe for
// concurrent writers, and parallel tests would each run `terraform init`.
// Serialize only init: the first one per provider fills the cache, later ones
// just read it, and plans and applies stay parallel.
var initMu sync.Mutex

func initSerially(t *testing.T, opts *terraform.Options) {
	t.Helper()
	initMu.Lock()
	defer initMu.Unlock()
	terraform.Init(t, opts)
}

func region() string {
	if r := os.Getenv("AWS_REGION"); r != "" {
		return r
	}
	return "eu-west-1"
}

// copyFixture copies the repository to a temp dir (fixtures use ../../../modules
// and ../../../sigma) and returns the fixture's path inside it.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	return teststructure.CopyTerraformFolderToTemp(t, "..", filepath.Join("test", "fixtures", name))
}

// unitPlan plans a fixture offline and returns the parsed plan.
func unitPlan(t *testing.T, fixture string, vars map[string]interface{}) *terraform.PlanStruct {
	t.Helper()
	v := map[string]interface{}{"offline": true, "name_prefix": unitPrefix}
	for k, val := range vars {
		v[k] = val
	}
	opts := &terraform.Options{TerraformDir: copyFixture(t, fixture), Vars: v, NoColor: true}
	initSerially(t, opts) // providers installed: the init inside the next call only reads the cache
	return terraform.InitAndPlanAndShowWithStructNoLogTempPlanFile(t, opts)
}

func planned(t *testing.T, plan *terraform.PlanStruct, address string) map[string]interface{} {
	t.Helper()
	r, ok := plan.ResourcePlannedValuesMap[address]
	require.Truef(t, ok, "%s is not planned; planned: %v", address, addresses(plan, ""))
	return r.AttributeValues
}

func absent(t *testing.T, plan *terraform.PlanStruct, address string) {
	t.Helper()
	_, ok := plan.ResourcePlannedValuesMap[address]
	require.Falsef(t, ok, "%s should not be planned", address)
}

// block returns the first element of a nested block.
func block(t *testing.T, attrs map[string]interface{}, name string) map[string]interface{} {
	t.Helper()
	list, ok := attrs[name].([]interface{})
	require.Truef(t, ok && len(list) > 0, "block %s missing in %v", name, attrs)
	return list[0].(map[string]interface{})
}

func addresses(plan *terraform.PlanStruct, prefix string) []string {
	var out []string
	for a := range plan.ResourcePlannedValuesMap {
		if strings.HasPrefix(a, prefix) {
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

func jsonKeys(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- integration ------------------------------------------------------------------

func requireLive(t *testing.T) {
	t.Helper()
	if os.Getenv("TERRATEST_LIVE") != "1" {
		t.Skip("integration test: set TERRATEST_LIVE=1 to run against AWS (sandbox account only)")
	}
}

// livePrefix is unique per CI run and fixture: tt-<run>-<attempt>-<short>.
func livePrefix(short string) string {
	run := os.Getenv("GITHUB_RUN_ID")
	if run == "" {
		run = strings.ToLower(random.UniqueId())
	}
	attempt := os.Getenv("GITHUB_RUN_ATTEMPT")
	if attempt == "" {
		attempt = "1"
	}
	return fmt.Sprintf("tt-%s-%s-%s", run, attempt, short)
}

func awsConfig(t *testing.T) awssdk.Config {
	t.Helper()
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region()))
	require.NoError(t, err)
	return cfg
}

// applyFixture initializes (serially) and applies (in parallel).
func applyFixture(t *testing.T, opts *terraform.Options) {
	t.Helper()
	initSerially(t, opts)
	terraform.Apply(t, opts)
}

// liveOptions returns options for applying a fixture, and a cleanup that destroys
// it and then removes its remote state (kept if destroy fails, for the janitor).
func liveOptions(t *testing.T, fixture, short string, vars map[string]interface{}) (*terraform.Options, func()) {
	t.Helper()
	dir := copyFixture(t, fixture)
	prefix := livePrefix(short)
	v := map[string]interface{}{"name_prefix": prefix, "region": region()}
	for k, val := range vars {
		v[k] = val
	}
	opts := &terraform.Options{TerraformDir: dir, Vars: v, NoColor: true}
	bucket := os.Getenv("TERRATEST_STATE_BUCKET")
	key := fmt.Sprintf("terratest/%s/%s/terraform.tfstate", fixture, prefix)
	if bucket != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "backend_override.tf"),
			[]byte("terraform {\n  backend \"s3\" {}\n}\n"), 0o644))
		opts.BackendConfig = map[string]interface{}{
			"bucket": bucket, "key": key, "region": region(), "encrypt": true, "use_lockfile": true,
		}
	}
	opts = terraform.WithDefaultRetryableErrors(t, opts)
	cleanup := func() {
		terraform.Destroy(t, opts) // fails the test (and stops here) if destroy fails
		if bucket != "" {
			_, err := s3.NewFromConfig(awsConfig(t)).DeleteObject(context.Background(),
				&s3.DeleteObjectInput{Bucket: awssdk.String(bucket), Key: awssdk.String(key)})
			require.NoError(t, err)
		}
	}
	return opts, cleanup
}
