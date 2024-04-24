package policy

import data.phylum.ecosystem
import data.phylum.domain
import data.phylum.level

import future.keywords.contains
import future.keywords.if

# Returns `true` if the given dependency has a typosquat issue
has_typosquat {
    some i
    data.dependency.issues[i].tag == "HM0008"
}

# Returns `true` if the dependency has more than one malware issue
has_more_than_one_malware_issue {
    issues := data.dependency.issues
    count([dom | issues[i].domain == domain.MALICIOUS; dom := issues[i].domain]) > 1
}

# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue

issue contains "Potential typosquat with malicious characteristics" if {
    has_typosquat
    has_more_than_one_malware_issue
}