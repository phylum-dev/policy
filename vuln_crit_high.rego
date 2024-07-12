# METADATA
# title: Software Vulnerability - Critical/High
# description: |
#    Blocks Critical and High software vulnerabilities
package policy.v1

import data.phylum.domain
import data.phylum.level
import rego.v1

# METADATA
# title: Critical or High software vulnerability
deny contains issue if {
	some issue in data.issues
	issue.domain == domain.VULNERABILITY
	issue.severity > level.MEDIUM
}
