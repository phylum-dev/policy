# METADATA
# title: Show All
# description: |
#    Returns a violation for all identified issues
package policy.v1

import rego.v1

# Policy Violation
deny contains issue if {
	some issue in data.issues
}
