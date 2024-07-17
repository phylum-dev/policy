# METADATA
# title: All Critical (except Software Vulnerability)
# description: |
#    Blocks Critical issues (except software vulnerabilities)
package policy.v1

import data.phylum.domain
import data.phylum.level
import rego.v1

# METADATA
# title: Critical issue
deny contains issue if {
	some issue in data.issues
	issue.domain != domain.VULNERABILITY
	issue.severity == level.CRITICAL
}
