# METADATA
# title: Block All Issues
# description: |
#    Blocks all identified issues
package policy.v1

import rego.v1

# METADATA
# title: Policy Violation
deny contains issue if {
	some issue in data.issues
}
