/**
 * @name Command injection vulnerability
 * @description Detects potential command injection vulnerabilities in exec calls
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id go/command-injection
 * @tags security
 *       external/cwe/cwe-78
 */

import go

/**
 * A call to os/exec.Command or similar that executes commands
 */
class CommandExecutionCall extends CallExpr {
  CommandExecutionCall() {
    this.getTarget().hasQualifiedName("os/exec", ["Command", "CommandContext"]) or
    this.getTarget().hasQualifiedName("syscall", ["Exec", "ForkExec"]) or
    this.getTarget().hasQualifiedName("os", "StartProcess")
  }
  
  /**
   * Gets the command name argument (usually the first argument)
   */
  Expr getCommandArg() {
    result = this.getArgument(0)
  }
  
  /**
   * Gets command arguments (excluding the first command name)
   */
  Expr getCommandArgument(int i) {
    result = this.getArgument(i) and i >= 1
  }
}

/**
 * An expression that represents user-controllable input
 */
predicate isUserInput(Expr e) {
  // CLI arguments
  exists(IndexExpr ie |
    e = ie and
    ie.getBase().(CallExpr).getTarget().hasQualifiedName("os", "Args")
  ) or
  
  // Environment variables
  exists(CallExpr call |
    e = call and
    call.getTarget().hasQualifiedName("os", ["Getenv", "LookupEnv"])
  ) or
  
  // File reads
  exists(CallExpr call |
    e = call and
    (
      call.getTarget().hasQualifiedName("io/ioutil", "ReadFile") or
      call.getTarget().hasQualifiedName("os", "ReadFile")
    )
  ) or
  
  // User input variables
  exists(Variable v |
    e = v.getAReference() and
    v.getName().regexpMatch("(?i).*(user|input|arg|param|request).*")
  )
}

/**
 * An expression that might contain dangerous command injection
 */
predicate isDangerousCommandArg(Expr e) {
  // Direct user input
  isUserInput(e) or
  
  // String concatenation with user input
  exists(AddExpr addExpr |
    e = addExpr and
    (isUserInput(addExpr.getLeftOperand()) or isUserInput(addExpr.getRightOperand()))
  ) or
  
  // Formatted strings with user input
  exists(CallExpr formatCall |
    e = formatCall and
    formatCall.getTarget().hasQualifiedName("fmt", ["Sprintf", "Fprintf"]) and
    isUserInput(formatCall.getAnArgument())
  ) or
  
  // Shell metacharacters in strings
  exists(StringLit stringLit |
    e = stringLit and
    stringLit.getValue().regexpMatch(".*[;&|`$(){}\\[\\]<>].*")
  )
}

/**
 * A command that executes through shell
 */
predicate isShellCommand(CommandExecutionCall call) {
  exists(StringLit cmd |
    cmd = call.getCommandArg() and
    cmd.getValue().regexpMatch(".*(sh|bash|cmd|powershell).*")
  )
}

from CommandExecutionCall call, Expr arg
where
  (
    // Dangerous command argument
    arg = call.getCommandArg() and isDangerousCommandArg(arg)
  ) or
  (
    // Dangerous arguments to any command
    arg = call.getCommandArgument(_) and isDangerousCommandArg(arg)
  ) or
  (
    // Special case for shell commands
    isShellCommand(call) and
    arg = call.getCommandArgument(_) and
    isUserInput(arg)
  )
select call, "Potential command injection through unsanitized argument: $@", arg, "user input"