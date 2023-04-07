package policy

import data.phylum.level

issue["risk level cannot exceed medium"] {
    data.issue.severity > level.MEDIUM
}
