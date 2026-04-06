# sample_logs/README.md
# 7-day synthetic log dataset for Chronos demonstration.
#
# Scenario: APT actor "GHOST" compromises developer "alice"
# Day 1-3: Slow-scan from 198.51.100.42 (missed by simple rules)
# Day 4:   Successful login from 198.51.100.42 (new IP for alice)
#          → Immediate IAM policy enumeration and S3 recon
# Day 5:   Silent-hacker activity using alice's aws-cli UA from 203.0.113.9
#          → CreateAccessKey, PutBucketPolicy
# Day 6:   Lateral movement via AssumeRole
# Day 7:   Large S3 GetObject activity (exfiltration)
