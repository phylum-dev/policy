# METADATA
# title: Data Exfiltration
# description: |
#    Blocks common data exfiltration techniques
package policy.v1

import rego.v1

# METADATA
# title: Environment variable enumeration
deny contains issue if {
	some issue in data.issues
	issue.tag == "HM0025"
}

# METADATA
# title: Webhook exfiltration
deny contains issue if {
	some issue in data.issues
	issue.tag == "HM0036"
}
