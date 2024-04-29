package policy

import data.phylum.domain
import data.phylum.level
import rego.v1

# Returns a violation if the package has a Critical or High software vulnerability
# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue
issue contains "Critical or High software vulnerability" if {
	data.issue.domain == domain.VULNERABILITY
	data.issue.severity > level.MEDIUM
}
