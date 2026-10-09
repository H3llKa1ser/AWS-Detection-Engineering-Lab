package test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/gruntwork-io/terratest/modules/retry"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cisCloudTrailDetections = 15 // CIS AWS Foundations v1.4.0 section 4 (4.1-4.15)

// One filter and one alarm per detection, every Sigma metric filter included,
// all on the given log group, with the alarm semantics the runbook assumes.
func TestUnitDetections(t *testing.T) {
	t.Parallel()
	plan := unitPlan(t, "detections", nil)
	filters := addresses(plan, "module.detections.aws_cloudwatch_log_metric_filter.detection[")
	alarms := addresses(plan, "module.detections.aws_cloudwatch_metric_alarm.detection[")
	sigma := jsonKeys(t, "../sigma/generated/metric_filters.json")

	require.Len(t, filters, cisCloudTrailDetections+len(sigma))
	require.Len(t, alarms, len(filters))
	for _, name := range sigma {
		planned(t, plan, fmt.Sprintf("module.detections.aws_cloudwatch_log_metric_filter.detection[%q]", name))
	}
	for _, a := range filters {
		f := planned(t, plan, a)
		assert.Equal(t, "/tt-unit/terratest/cloudtrail", f["log_group_name"], a)
		p, _ := f["pattern"].(string)
		assert.True(t, p != "" && len(p) <= 1024, "%s pattern length %d", a, len(p))
	}
	for _, a := range alarms {
		al := planned(t, plan, a)
		assert.True(t, strings.HasPrefix(al["alarm_name"].(string), unitPrefix+"-"), a)
		assert.EqualValues(t, 300, al["period"], a)
		assert.EqualValues(t, 1, al["evaluation_periods"], a)
		assert.Equal(t, "Sum", al["statistic"], a)
		assert.Equal(t, "GreaterThanOrEqualToThreshold", al["comparison_operator"], a)
		assert.Equal(t, "notBreaching", al["treat_missing_data"], a)
	}
}

// Applied for real: an event written to the log group drives its alarm to ALARM,
// for a CIS detection and a Sigma one; an unrelated alarm stays out of ALARM.
func TestIntegrationDetectionAlarmsFire(t *testing.T) {
	requireLive(t)
	t.Parallel()
	opts, cleanup := liveOptions(t, "detections", "det", nil)
	defer cleanup()
	applyFixture(t, opts)

	prefix := opts.Vars["name_prefix"].(string)
	putEvents(t, terraform.Output(t, opts, "log_group"),
		cloudTrailEvent("cloudtrail.amazonaws.com", "StopLogging", nil),
		cloudTrailEvent("ssm.amazonaws.com", "SendCommand", nil))

	want := []string{prefix + "-cloudtrail_config_changes", prefix + "-sigma_ssm_command_by_human"}
	control := prefix + "-root_account_usage"
	cw := cloudwatch.NewFromConfig(awsConfig(t))
	states := map[string]string{}
	retry.DoWithRetry(t, "metric alarms reach ALARM", 40, 30*time.Second, func() (string, error) {
		out, err := cw.DescribeAlarms(context.Background(), &cloudwatch.DescribeAlarmsInput{AlarmNames: append(want, control)})
		if err != nil {
			return "", err
		}
		for _, a := range out.MetricAlarms {
			states[awssdk.ToString(a.AlarmName)] = string(a.StateValue)
		}
		for _, n := range want {
			if states[n] != "ALARM" {
				return "", fmt.Errorf("states so far: %v", states)
			}
		}
		return "ok", nil
	})
	assert.NotEqual(t, "ALARM", states[control], "negative control: no root activity was written")
}
