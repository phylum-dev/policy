# METADATA
# title: Runs Remote Code
# description: |
#    Blocks packages that run remote code
package policy.v1

import rego.v1

# METADATA
# title: Runs remote code
deny contains issue if {
	some issue in data.issues
	issue.tag in {"CM0024", "MM0024", "HM0032"}
}
