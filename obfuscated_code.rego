package policy

import rego.v1

# Returns a violation if the package contains obfuscated code
# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue
issue contains "Package contains obfuscated code" if {
	data.issue.tag in {"HM0029", "HM0099", "HM0023", "IM0040", "IM0041"}
}
