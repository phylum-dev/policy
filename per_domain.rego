package policy

import future.keywords.in
import data.phylum.domain
import data.phylum.level

issue["risk level cannot exceed medium"] {
    data.issue.domain in {domain.AUTHOR, domain.ENGINEERING, domain.VULNERABILITY}
    data.issue.severity > level.MEDIUM
}

issue["malicious risk level cannot exceed low"] {
    data.issue.domain == domain.MALICIOUS
    data.issue.severity > level.LOW
}

issue["license risk level cannot exceed high"] {
    data.issue.domain == domain.LICENSE
    data.issue.severity > level.HIGH
}

