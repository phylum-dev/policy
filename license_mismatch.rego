package policy

import rego.v1

# Returns a violation if there is a license mismatch between metadata and files
# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue
issue contains "License mismatch" if {
	data.issue.tag == "IL0022"
}
