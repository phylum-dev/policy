package policy

import rego.v1

# Returns a violation if the package contains common data exfiltration techniques
# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue
issue contains "Package contains environment variable enumeration" if {
	data.issue.tag == "HM0025"
}

issue contains "Package contains webhook exfiltration" if {
	data.issue.tag == "HM0036"
}
