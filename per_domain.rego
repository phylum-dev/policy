# METADATA
# title: Per Domain 
# description: |
#    Block medium/high/critical author/engineering/vulnerability issues, any medium/high/critical malware issues and any high/critical license issues
package policy

import data.phylum.domain
import data.phylum.level
import rego.v1

issue contains "risk level cannot exceed medium" if {
	data.issue.domain in {domain.AUTHOR, domain.ENGINEERING, domain.VULNERABILITY}
	data.issue.severity > level.MEDIUM
}

issue contains "malicious risk level cannot exceed low" if {
	data.issue.domain == domain.MALICIOUS
	data.issue.severity > level.LOW
}

issue contains "license risk level cannot exceed high" if {
	data.issue.domain == domain.LICENSE
	data.issue.severity > level.HIGH
}
