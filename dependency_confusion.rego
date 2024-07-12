# METADATA
# title: Dependency Confusion
# description: |
#    Blocks dependency confusion
package policy.v1

import rego.v1

# METADATA
# title: Dependency confusion
deny contains issue if {
	some issue in data.issues
	issue.tag == "HM0018"
}
