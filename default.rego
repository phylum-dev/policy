package policy

import data.phylum.domain
import data.phylum.level

# METADATA
# scope: rule
# schemas:
#   - input.issue: schema.issue
issue[reason] {
	# If an issue severity is greater than or equal to this threshold, block it.
	# To completely ignore a domain, remove it from this object.
	thresholds := {
		domain.AUTHOR: level.LOW,
		domain.ENGINEERING: level.HIGH,
		domain.MALICIOUS: level.HIGH,
		domain.VULNERABILITY: level.HIGH,
		domain.LICENSE: level.HIGH,
	}

	input.issue.severity >= thresholds[input.issue.domain]

	reason := sprintf("issue %v exceeds %v risk threshold", [input.issue.tag, input.issue.domain])
}
