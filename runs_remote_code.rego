# METADATA
# title: Runs Remote Code
# description: |
#    Returns a violation if the package runs remote code

package policy.v1

import rego.v1

# Runs remote code
deny contains issue if {
	some issue in data.issues
	issue.tag in {"CM0024", "MM0024", "HM0032"}
}
