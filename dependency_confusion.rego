package policy

import rego.v1

# Returns a violation if the package appears to be a dependency confusion
# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue
issue contains "Package appears to be a dependency confusion" if {
	data.issue.tag == "HM0018"
}
