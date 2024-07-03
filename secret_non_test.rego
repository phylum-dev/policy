# METADATA
# title: Minimal Code
# description: |
#    Returns a violation if the package contains secrets/tokens excluding test/example files

package policy.v1

import rego.v1

# Secrets in non-test file
deny contains issue if {
   some issue in data.issues
   issue.tag == "ME0016"
}
