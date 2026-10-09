package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/gruntwork-io/terratest/modules/retry"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration only: the awscc provider (log alarms) validates credentials with
// STS whenever it is configured, so this module cannot be planned offline.
//
// Applied for real: the saved query exists on the log group, and a matching
// event drives the Logs Insights log alarm (an AWS-managed scheduled query)
// to ALARM, while an AWS-invoked SendCommand (excluded by the rule) does not
// count.
func TestIntegrationSigmaLogAlarmFires(t *testing.T) {
	requireLive(t)
	t.Parallel()
	opts, cleanup := liveOptions(t, "sigma-insights", "sig", nil)
	defer cleanup()
	applyFixture(t, opts)

	ctx, cfg := context.Background(), awsConfig(t)
	prefix := opts.Vars["name_prefix"].(string)
	lg := terraform.Output(t, opts, "log_group")

	defs, err := cloudwatchlogs.NewFromConfig(cfg).DescribeQueryDefinitions(ctx,
		&cloudwatchlogs.DescribeQueryDefinitionsInput{QueryDefinitionNamePrefix: awssdk.String(prefix + "/sigma/")})
	require.NoError(t, err)
	require.Len(t, defs.QueryDefinitions, 1)
	assert.Equal(t, []string{lg}, defs.QueryDefinitions[0].LogGroupNames)

	putEvents(t, lg,
		cloudTrailEvent("ssm.amazonaws.com", "SendCommand", map[string]interface{}{
			"userIdentity": map[string]interface{}{"type": "AWSService", "invokedBy": "ssm.amazonaws.com"}}),
		cloudTrailEvent("ssm.amazonaws.com", "SendCommand", nil))

	name := prefix + "-insights-sigma_ssm_command_by_human"
	cw := cloudwatch.NewFromConfig(cfg)
	retry.DoWithRetry(t, "log alarm reaches ALARM", 50, 30*time.Second, func() (string, error) {
		out, err := cw.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{
			AlarmNames: []string{name}, AlarmTypes: []cwtypes.AlarmType{cwtypes.AlarmTypeLogAlarm}})
		if err != nil {
			return "", err
		}
		if len(out.LogAlarms) != 1 {
			return "", fmt.Errorf("log alarm %s not found (%d)", name, len(out.LogAlarms))
		}
		if s := out.LogAlarms[0].StateValue; s != cwtypes.StateValueAlarm {
			return "", fmt.Errorf("state %s", s)
		}
		return "ok", nil
	})
}
