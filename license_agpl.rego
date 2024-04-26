package policy

import data.phylum.domain
import data.phylum.level
import future.keywords.contains
import future.keywords.if
import future.keywords.in

is_agpl {
regex.match("(?i)\\bAffero\\b", data.dependency.license)
}

is_agpl {
regex.match("(?i)\\bAGPL\\b", data.dependency.license)
}

# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue

# Returns a violation if the package license metadata indicates "Affero" or "AGPL"
dependency contains "AGPL licensed software is not allowed" if {
        is_agpl
}