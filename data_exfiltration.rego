# METADATA
# title: Data Exfiltration
# description: |
#    Returns a violation if the package contains common data exfiltration techniques
package policy.v1

import rego.v1

# Package contains environment variable enumeration
deny contains issue if {
	some issue in data.issues
	issue.tag == "HM0025"
}

# Package contains webhook exfiltration
deny contains issue if {
	some issue in data.issues
	issue.tag == "HM0036"
}
