# METADATA
# title: Critical Software Vulnerability
# description: |
#    Returns a violation if the package has a Critical software vulnerability

package policy.v1

import rego.v1
import data.phylum.domain
import data.phylum.level

# Critical software vulnerability
deny contains issue if {
   some issue in data.issues
   issue.domain == domain.VULNERABILITY
   issue.severity == level.CRITICAL
}
