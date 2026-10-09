package test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func eventPattern(t *testing.T, rule map[string]interface{}) map[string]interface{} {
	t.Helper()
	var p map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(rule["event_pattern"].(string)), &p))
	return p
}

// GuardDuty at or above the configured severity, Security Hub HIGH/CRITICAL new
// active findings, both to SNS; no email subscription when no address is given.
func TestUnitAlerting(t *testing.T) {
	t.Parallel()
	plan := unitPlan(t, "alerting", nil)

	gd := eventPattern(t, planned(t, plan, "module.alerting.aws_cloudwatch_event_rule.guardduty[0]"))
	assert.Equal(t, []interface{}{"aws.guardduty"}, gd["source"])
	sev := gd["detail"].(map[string]interface{})["severity"].([]interface{})[0].(map[string]interface{})["numeric"]
	assert.Equal(t, []interface{}{">=", float64(7)}, sev)

	sh := eventPattern(t, planned(t, plan, "module.alerting.aws_cloudwatch_event_rule.securityhub[0]"))
	f := sh["detail"].(map[string]interface{})["findings"].(map[string]interface{})
	assert.Equal(t, []interface{}{"HIGH", "CRITICAL"}, f["Severity"].(map[string]interface{})["Label"])
	assert.Equal(t, []interface{}{"ACTIVE"}, f["RecordState"])
	assert.Equal(t, []interface{}{"NEW"}, f["Workflow"].(map[string]interface{})["Status"])

	planned(t, plan, "module.alerting.aws_cloudwatch_event_target.guardduty[0]")
	planned(t, plan, "module.alerting.aws_cloudwatch_event_target.securityhub[0]")
	absent(t, plan, "module.alerting.aws_sns_topic_subscription.email[0]")
}
