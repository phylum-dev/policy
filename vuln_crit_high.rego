package policy

import data.phylum.domain
import data.phylum.level
import future.keywords.contains
import future.keywords.if
import future.keywords.in


# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue

# Returns a violation if the package has a Critical or High software vulnerability
issue contains "Critical or High software vulnerability" if {
   data.issue.domain == domain.VULNERABILITY
   data.issue.severity > level.MEDIUM
}