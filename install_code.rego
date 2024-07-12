# METADATA
# title: Install Code Execution
# description: |
#    Blocks code execution on package install
package policy.v1

import rego.v1

# METADATA
# title: Code execution on install
deny contains issue if {
	some issue in data.issues
	issue.tag in {"IM0042", "IM0043", "IM0044"}
}
