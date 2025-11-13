/**
 * @name Vault token exposure in logs or error messages
 * @description Detects potential exposure of Vault tokens in log statements or error messages
 * @kind problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id go/vault-token-exposure
 * @tags security
 *       external/cwe/cwe-532
 *       external/cwe/cwe-200
 */

import go

/**
 * A call to a logging function that might expose sensitive data
 */
class LoggingCall extends CallExpr {
  LoggingCall() {
    this.getTarget().hasQualifiedName("go.uber.org/zap", ["Info", "Debug", "Warn", "Error", "Fatal"]) or
    this.getTarget().hasQualifiedName("log", ["Print", "Printf", "Println"]) or
    this.getTarget().hasQualifiedName("fmt", ["Print", "Printf", "Println", "Errorf"]) or
    this.getTarget().hasQualifiedName("github.com/uptrace/opentelemetry-go-extra/otelzap", ["Info", "Debug", "Warn", "Error", "Fatal"])
  }
}

/**
 * An expression that might contain a Vault token
 */
predicate isVaultTokenExpression(Expr e) {
  // String literals that look like vault tokens
  e.(StringLit).getValue().regexpMatch("(?i).*(hvs\\.|hvb\\.|root_token|vault.?token).*") or
  
  // Variables with token-related names
  exists(Variable v | 
    v.getAReference() = e and
    v.getName().regexpMatch("(?i).*(token|secret|credential|auth).*")
  ) or
  
  // Field access that might be token-related
  exists(SelectorExpr se |
    e = se and
    se.getSelector().getName().regexpMatch("(?i).*(token|secret|credential|password).*")
  ) or
  
  // Method calls that return tokens
  exists(CallExpr tokenCall |
    e = tokenCall and
    (
      tokenCall.getTarget().getName().regexpMatch("(?i).*(token|secret|credential|auth).*") or
      tokenCall.getTarget().hasQualifiedName("github.com/hashicorp/vault/api", ["Token", "Auth"])
    )
  )
}

/**
 * A function call that might format or interpolate vault tokens
 */
predicate mightExposeToken(Expr e) {
  // Direct token references
  isVaultTokenExpression(e) or
  
  // Formatted strings with potential tokens
  exists(CallExpr formatCall |
    formatCall.getTarget().hasQualifiedName("fmt", ["Sprintf", "Errorf"]) and
    formatCall.getAnArgument() = e and
    isVaultTokenExpression(formatCall.getAnArgument())
  ) or
  
  // String concatenation with tokens
  exists(AddExpr addExpr |
    e = addExpr and
    (isVaultTokenExpression(addExpr.getLeftOperand()) or isVaultTokenExpression(addExpr.getRightOperand()))
  )
}

from LoggingCall call, Expr arg
where
  arg = call.getAnArgument() and
  mightExposeToken(arg)
select call, "Potential Vault token exposure in logging statement: $@", arg, "sensitive data"