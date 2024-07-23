# METADATA
# title: All High, Critical Issues 
# description: |
#    Blocks all issues that exceed the medium threshold 

package policy

import data.phylum.level
import rego.v1

issue contains "risk level cannot exceed medium" if {
	data.issue.severity > level.MEDIUM
}
