# METADATA
# title: Software Vulnerability - Critical
# description: |
#    Blocks Critical software vulnerabilities
package policy.v1

import data.phylum.domain
import data.phylum.level
import rego.v1

# METADATA
# title: Critical software vulnerability
deny contains issue if {
	some issue in data.issues
	issue.domain == domain.VULNERABILITY
	issue.severity == level.CRITICAL
}
