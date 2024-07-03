# METADATA
# title: Minimal Code
# description: |
#    Returns a violation if the package contains minimal code and is unlikley worth the security risk

package policy.v1

import rego.v1

# Package contains minimal code
deny contains issue if {
   some issue in data.issues
   issue.tag == "IE0027"
}
