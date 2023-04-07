package policy

import data.phylum.level
import future.keywords.contains
import future.keywords.if

issue contains "risk level cannot exceed medium" if {
	data.issue.severity > level.MEDIUM
}
