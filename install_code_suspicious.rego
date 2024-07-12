# METADATA
# title: Install Code Execution (Suspicious)
# description: |
#    Blocks suspicious code execution on pacakge install
package policy.v1

import rego.v1

# METADATA
# title: Suspicious code execution on install
deny contains issue if {
	some issue in data.issues
	issue.tag == "CM0007"
}

# title: Suspicious code execution on install
deny contains issue if {
	some issue in data.issues
	endswith(issue.tag, "M0031")
}
