# METADATA
# title: Suspicious IP References
# description: |
#    Block packages containing suspicious IP addresses
package policy.v1

import rego.v1

# METADATA
# title: Suspicious IP reference
deny contains issue if {
	some issue in data.issues
	issue.tag == "CM0001"
}
