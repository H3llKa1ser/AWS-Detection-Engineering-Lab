package test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	ttaws "github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The CloudTrail evidence store: versioned, KMS-encrypted, private, validated.
func TestUnitLogging(t *testing.T) {
	t.Parallel()
	plan := unitPlan(t, "logging", nil)

	v := planned(t, plan, "module.logging.aws_s3_bucket_versioning.cloudtrail")
	assert.Equal(t, "Enabled", block(t, v, "versioning_configuration")["status"])

	pab := planned(t, plan, "module.logging.aws_s3_bucket_public_access_block.cloudtrail")
	for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
		assert.Equal(t, true, pab[k], k)
	}

	sse := planned(t, plan, "module.logging.aws_s3_bucket_server_side_encryption_configuration.cloudtrail")
	assert.Equal(t, "aws:kms", block(t, block(t, sse, "rule"), "apply_server_side_encryption_by_default")["sse_algorithm"])

	trail := planned(t, plan, "module.logging.aws_cloudtrail.main")
	assert.Equal(t, true, trail["is_multi_region_trail"])
	assert.Equal(t, true, trail["include_global_service_events"])
	assert.Equal(t, true, trail["enable_log_file_validation"])

	lg := planned(t, plan, "module.logging.aws_cloudwatch_log_group.trail")
	assert.EqualValues(t, 1, lg["retention_in_days"])

	key := planned(t, plan, "module.logging.aws_kms_key.logs[0]")
	assert.Equal(t, true, key["enable_key_rotation"])
}

// Applied for real: the controls hold on the actual resources, and the trail logs.
func TestIntegrationLogging(t *testing.T) {
	requireLive(t)
	t.Parallel()
	opts, cleanup := liveOptions(t, "logging", "log", nil)
	defer cleanup()
	applyFixture(t, opts)

	ctx, cfg := context.Background(), awsConfig(t)
	bucket := terraform.Output(t, opts, "bucket")
	assert.Equal(t, "Enabled", ttaws.GetS3BucketVersioning(t, region(), bucket))
	assert.Contains(t, ttaws.GetS3BucketPolicy(t, region(), bucket), "aws:SecureTransport", "TLS-only bucket policy")

	pab, err := s3.NewFromConfig(cfg).GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: awssdk.String(bucket)})
	require.NoError(t, err)
	c := pab.PublicAccessBlockConfiguration
	assert.True(t, *c.BlockPublicAcls && *c.BlockPublicPolicy && *c.IgnorePublicAcls && *c.RestrictPublicBuckets)

	status, err := cloudtrail.NewFromConfig(cfg).GetTrailStatus(ctx,
		&cloudtrail.GetTrailStatusInput{Name: awssdk.String(terraform.Output(t, opts, "trail"))})
	require.NoError(t, err)
	assert.True(t, *status.IsLogging, "trail is logging")

	lgName := terraform.Output(t, opts, "log_group")
	groups, err := cloudwatchlogs.NewFromConfig(cfg).DescribeLogGroups(ctx,
		&cloudwatchlogs.DescribeLogGroupsInput{LogGroupNamePrefix: awssdk.String(lgName)})
	require.NoError(t, err)
	require.Len(t, groups.LogGroups, 1)
	assert.Equal(t, terraform.Output(t, opts, "kms_key_arn"), awssdk.ToString(groups.LogGroups[0].KmsKeyId))
	assert.EqualValues(t, 1, awssdk.ToInt32(groups.LogGroups[0].RetentionInDays))
}
