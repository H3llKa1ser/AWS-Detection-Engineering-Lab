package test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/stretchr/testify/require"
)

// cloudTrailEvent builds a CloudTrail-shaped record (as CloudTrail writes to CloudWatch Logs).
func cloudTrailEvent(source, name string, extra map[string]interface{}) map[string]interface{} {
	ev := map[string]interface{}{
		"eventVersion": "1.09", "eventTime": time.Now().UTC().Format(time.RFC3339),
		"eventSource": source, "eventName": name, "awsRegion": region(),
		"sourceIPAddress": "198.51.100.7", "userAgent": "terratest", "eventType": "AwsApiCall",
		"userIdentity": map[string]interface{}{"type": "AssumedRole",
			"arn": "arn:aws:sts::111122223333:assumed-role/terratest/session"},
	}
	for k, v := range extra {
		ev[k] = v
	}
	return ev
}

// putEvents writes events into a log group (new stream, current timestamps).
func putEvents(t *testing.T, logGroup string, events ...map[string]interface{}) {
	t.Helper()
	ctx, client := context.Background(), cloudwatchlogs.NewFromConfig(awsConfig(t))
	stream := "terratest"
	_, err := client.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName: awssdk.String(logGroup), LogStreamName: awssdk.String(stream)})
	require.NoError(t, err)
	now := time.Now().UnixMilli()
	batch := make([]types.InputLogEvent, 0, len(events))
	for i, ev := range events {
		raw, err := json.Marshal(ev)
		require.NoError(t, err)
		batch = append(batch, types.InputLogEvent{Message: awssdk.String(string(raw)), Timestamp: awssdk.Int64(now + int64(i))})
	}
	_, err = client.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
		LogGroupName: awssdk.String(logGroup), LogStreamName: awssdk.String(stream), LogEvents: batch})
	require.NoError(t, err)
}
