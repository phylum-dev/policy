package policy

import rego.v1

# Returns a violation if there is code execution on package install
# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue
issue contains "Package contains code execution on install" if {
	data.issue.tag in {"IM0042", "IM0043", "IM0044"}
}
