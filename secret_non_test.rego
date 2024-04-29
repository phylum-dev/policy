package policy

import rego.v1

# Returns a violation if the package contains secrets/tokens excluding test/example files
# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue
issue contains "Secrets in non-test file" if {
	data.issue.tag == "ME0016"
}
