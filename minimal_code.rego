package policy

import rego.v1

# Returns a violation if the package contains minimal code and is unlikley worth the security risk
# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue
issue contains "Package contains minimal code" if {
	data.issue.tag == "IE0027"
}
