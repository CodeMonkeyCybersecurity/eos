/**
 * @name Hard-coded credentials
 * @description Detects hard-coded passwords, tokens, or other credentials
 * @kind problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id go/hardcoded-credentials
 * @tags security
 *       external/cwe/cwe-798
 */

import go

/**
 * A string literal that looks like a credential
 */
predicate isCredentialString(StringLit s) {
  exists(string val | val = s.getValue() |
    // Vault tokens
    val.regexpMatch("hvs\\.[A-Za-z0-9_-]{90,}")
    or
    val.regexpMatch("hvb\\.[A-Za-z0-9_-]{90,}")
    or
    // JWT tokens (3 base64 segments separated by dots)
    val.regexpMatch("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")
    or
    // API keys (common patterns)
    val.regexpMatch("(?i)(ak_|sk_|pk_)[a-z0-9]{20,}")
    or
    val.regexpMatch("[A-Za-z0-9]{32,}") and val.length() >= 32
    or
    // Passwords that look real (not examples)
    val.regexpMatch("(?i).*password.*") and
    not val.regexpMatch("(?i).*(example|test|demo|placeholder|your.?password|change.?me).*") and
    val.length() >= 8
    or
    // Database connection strings with credentials
    val.regexpMatch("(?i).*(postgres|mysql|mongodb)://[^:]+:[^@]+@.*")
    or
    // AWS/Cloud credentials
    val.regexpMatch("AKIA[0-9A-Z]{16}")
    or
    val.regexpMatch("(?i)(aws|gcp|azure).*(key|secret|token).*")
    or
    // Private keys
    val.regexpMatch("-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----.*")
  )
}

/**
 * A variable or field that suggests it holds credentials
 */
predicate isCredentialIdentifier(string name) {
  exists(string n | n = name |
    n.regexpMatch("(?i).*(password|passwd|pwd|secret|token|key|credential|auth|api.?key).*") and
    not n.regexpMatch("(?i).*(test|example|demo|mock|fake|dummy).*")
  )
}

/**
 * An assignment that might expose credentials
 */
predicate isCredentialAssignment(AssignStmt assign, StringLit s) {
  exists(Variable v |
    assign.getLhs().(Ident).refersTo(v) and
    isCredentialIdentifier(v.getName()) and
    s = assign.getRhs()
  )
  or
  exists(SelectorExpr se |
    assign.getLhs() = se and
    isCredentialIdentifier(se.getSelector().getName()) and
    s = assign.getRhs()
  )
}

/**
 * A variable declaration that might hold credentials
 */
predicate isCredentialVarAssignment(AssignStmt assign, StringLit s) {
  exists(Variable v |
    assign.getLhs().getAChild*() = v.getAReference() and
    isCredentialIdentifier(v.getName()) and
    s = assign.getRhs()
  )
}

/**
 * Exclude test files and examples
 */
predicate isInTestFile(AstNode node) {
  node.getFile().getBaseName().regexpMatch(".*_test\\.go") or
  node.getFile().getAbsolutePath().regexpMatch(".*/test.*") or
  node.getFile().getAbsolutePath().regexpMatch(".*/example.*")
}

from AstNode node, string message
where
  not isInTestFile(node) and
  (
    // Hard-coded credential strings in non-test files
    isCredentialString(node) and
    message = "Hard-coded credential found in string literal"
    or
    // Assignment of credential strings to credential variables
    exists(AssignStmt assign, StringLit s |
      (isCredentialAssignment(assign, s) or isCredentialVarAssignment(assign, s)) and
      node = assign and
      (
        isCredentialString(s)
        or
        s.getValue().length() >= 8 and
        not s.getValue().regexpMatch("(?i).*(example|test|demo|placeholder).*")
      ) and
      message = "Hard-coded credential assigned to variable"
    )
  )
select node, message
