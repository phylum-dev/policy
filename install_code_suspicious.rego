# METADATA
# title: Install Code Execution (Suspicious)
# description: |
#    Returns a violation if there is suspicious code execution on pacakge install
package policy.v1

import rego.v1

# Package contains suspicious code execution on install
deny contains issue if {
	some issue in data.issues
	issue.tag == "CM0007"
}

# Package contains suspicious code execution on install
deny contains issue if {
	some issue in data.issues
	endswith(issue.tag, "M0031")
}
