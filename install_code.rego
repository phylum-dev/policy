# METADATA
# title: Install Code Execution
# description: |
#    Returns a violation if there is code execution on package install

package policy.v1

import rego.v1

# Package contains code execution on install
deny contains issue if {
   some issue in data.issues
   issue.tag in {"IM0042", "IM0043", "IM0044"}
}
