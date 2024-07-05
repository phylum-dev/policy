# METADATA
# title: Suspicious URL References
# description: |
#    Returns a violation if the package references sites uncommon to legitimate software

package policy.v1

import rego.v1

# Suspicious URL reference
deny contains issue if {
   some issue in data.issues
   issue.tag == "MM0028"
}
