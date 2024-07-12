# METADATA
# title: Secrets in non-test files
# description: |
#    Blocks packages containing secrets/tokens in non-test files
package policy.v1

import rego.v1

# METADATA
# title: Secrets in non-test file
deny contains issue if {
	some issue in data.issues
	issue.tag == "ME0016"
}
