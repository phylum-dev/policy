package policy

import data.phylum.domain
import data.phylum.level
import future.keywords.contains
import future.keywords.if
import future.keywords.in

default obfuscated_code := false

obfuscated_code if {
	data.issue.tag =="HM0029"
}

obfuscated_code if {
	data.issue.tag =="HM0099"
}

obfuscated_code if {
	data.issue.tag =="HM0023"
}

obfuscated_code if {
	data.issue.tag =="IM0040"
}

obfuscated_code if {
	data.issue.tag =="IM0041"
}

# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue

# Returns a violation if the package contains obfuscated code
issue contains "Package contains obfuscated code" if {
   obfuscated_code
}