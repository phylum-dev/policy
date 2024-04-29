package policy

import rego.v1

is_agpl if {
	regex.match(`(?i)\bAffero\b`, data.dependency.license)
}

is_agpl if {
	regex.match(`(?i)\bAGPL\b`, data.dependency.license)
}

# Returns a violation if the package license metadata indicates "Affero" or "AGPL"
# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue
dependency contains "AGPL licensed software is not allowed" if {
	is_agpl
}
