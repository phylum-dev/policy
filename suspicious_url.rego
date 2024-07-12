# METADATA
# title: Suspicious URL References
# description: |
#    Block packages referencing sites uncommon to legitimate software
package policy.v1

import rego.v1

# METADATA
# title: Suspicious URL reference
deny contains issue if {
	some issue in data.issues
	issue.tag == "MM0028"
}
