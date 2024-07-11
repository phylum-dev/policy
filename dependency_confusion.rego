# METADATA
# title: Dependency Confusion
# description: |
#    Returns a violation if the package appears to be a dependency confusion

package policy.v1

import rego.v1

# Package contains environment variable enumeration
deny contains issue if {
	some issue in data.issues
	issue.tag == "HM0018"
}
