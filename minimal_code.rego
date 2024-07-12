# METADATA
# title: Minimal Code
# description: |
#    Blocks packages containing minimal code
package policy.v1

import rego.v1

# METADATA
# title: Minimal code
deny contains issue if {
	some issue in data.issues
	issue.tag == "IE0027"
}
