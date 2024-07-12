# METADATA
# title: License Mismatch
# description: |
#    Blocks a license mismatch between metadata and files
package policy.v1

import rego.v1

# METADATA
# title: License mismatch
deny contains issue if {
	some issue in data.issues
	issue.tag == "IL0022"
}
