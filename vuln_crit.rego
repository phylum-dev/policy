package policy

import data.phylum.domain
import data.phylum.level
import rego.v1

# Returns a violation if the package has a Critical software vulnerability
# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue
issue contains "Critical software vulnerability" if {
	data.issue.domain == domain.VULNERABILITY
	data.issue.severity > level.HIGH
}
