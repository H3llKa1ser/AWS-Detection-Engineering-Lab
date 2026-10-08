#!/usr/bin/env bash
# Generate one sample of every GuardDuty finding type to exercise the
# GuardDuty -> EventBridge -> SNS alert path. Safe: these are samples, not
# real detections, and are prefixed [SAMPLE] in the console.
set -euo pipefail

REGION="${AWS_REGION:-$(aws configure get region)}"
DETECTOR_ID="$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text)"

if [[ "$DETECTOR_ID" == "None" || -z "$DETECTOR_ID" ]]; then
  echo "No GuardDuty detector found in $REGION. Is enable_guardduty = true and applied?" >&2
  exit 1
fi

echo "Creating sample findings on detector $DETECTOR_ID in $REGION ..."
aws guardduty create-sample-findings \
  --region "$REGION" \
  --detector-id "$DETECTOR_ID"

echo "Done. Check your SNS subscription and the GuardDuty console (findings prefixed [SAMPLE])."
