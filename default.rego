package policy

import data.phylum.level
import rego.v1

issue contains "risk level cannot exceed medium" if {
	data.issue.severity > level.MEDIUM
}
