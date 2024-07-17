# METADATA
# title: Copyleft license
# description: |
#    Block packages that have a copyleft license
package policy.v1

import rego.v1

# METADATA
# title: Copyleft license
deny contains issue if {
	some issue in data.issues
	issue.tag == "IL0050"
}
