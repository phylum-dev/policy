package policy

import rego.v1

# Returns a violation if there is suspicious code execution on package install
# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue
issue contains "Package contains suspicious code execution on install" if {
	data.issue.tag == "CM0007"
}

issue contains "Package contains suspicious code execution on install" if {
	endswith(data.issue.tag, "M0031")
}
