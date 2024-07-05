# METADATA
# title: Critical/High Software Vulnerability
# description: |
#    Returns a violation if the package has a Critical or High software vulnerability

package policy.v1

import rego.v1
import data.phylum.domain
import data.phylum.level

# Critical or High software vulnerability
deny contains issue if {
   some issue in data.issues
   issue.domain == domain.VULNERABILITY
   issue.severity > level.MEDIUM
}
