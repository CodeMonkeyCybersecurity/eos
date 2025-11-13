/**
 * @name Insecure file permissions for sensitive files
 * @description Detects file operations that might create files with insecure permissions
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id go/insecure-file-permissions
 * @tags security
 *       external/cwe/cwe-732
 */

import go

/**
 * A call to os.OpenFile, os.Create, or os.WriteFile
 */
class FileCreationCall extends CallExpr {
  FileCreationCall() {
    this.getTarget().hasQualifiedName("os", ["OpenFile", "Create", "WriteFile", "Chmod"]) or
    this.getTarget().hasQualifiedName("io/ioutil", "WriteFile")
  }
  
  /**
   * Gets the permission argument if present
   */
  Expr getPermissionArg() {
    (this.getTarget().getName() = "OpenFile" and result = this.getArgument(2)) or
    (this.getTarget().getName() = "WriteFile" and result = this.getArgument(2)) or
    (this.getTarget().getName() = "Chmod" and result = this.getArgument(1))
  }
  
  /**
   * Gets the filename argument
   */
  Expr getFilenameArg() {
    result = this.getArgument(0)
  }
}

/**
 * Predicate to check if a file path suggests it contains sensitive data
 */
predicate isSensitiveFilePath(Expr pathExpr) {
  exists(string path |
    path = pathExpr.(StringLit).getValue() and
    (
      path.regexpMatch("(?i).*(token|secret|credential|key|password|vault|auth).*") or
      path.regexpMatch(".*/etc/.*") or
      path.regexpMatch(".*/var/lib/.*") or
      path.regexpMatch(".*/run/.*") or
      path.regexpMatch(".*\\.pem") or
      path.regexpMatch(".*\\.key")
    )
  ) or
  // Variable names that suggest sensitive paths
  exists(Variable v |
    pathExpr = v.getAReference() and
    v.getName().regexpMatch("(?i).*(secret|token|credential|vault|auth).*path.*")
  )
}

/**
 * Predicate to check if permissions are too permissive for sensitive files
 */
predicate isInsecurePermission(Expr permExpr) {
  // Check octal permission values
  exists(string literal |
    literal = permExpr.(BasicLit).getValue() and
    (
      // World writable (others can write) - 002, 003, 006, 007, 022, 023, 026, 027, etc.
      literal.regexpMatch("0[0-7]*[2367][0-7]*") or
      // World readable for secrets (others can read) - 004, 005, 006, 007, 044, 045, 046, 047, etc.
      literal.regexpMatch("0[0-7]*[4567][0-7]*") or
      // Group writable for secrets - 020, 021, 022, 023, 024, 025, 026, 027, 060, 061, etc.
      literal.regexpMatch("0[0-7]*[2367][0-7]") or
      // Overly permissive patterns
      literal.regexpMatch("0[67][0-9][0-9]") or    // 0600+ with group/other access
      literal.regexpMatch("0[0-9][67][0-9]") or    // Group has write+read
      literal.regexpMatch("07[0-9][0-9]")          // Full group access
    )
  ) or
  // Check integer permission values (for named constants)
  exists(int perm |
    perm = permExpr.(BasicLit).getIntValue() and
    (
      // Octal 0644 = decimal 420, 0755 = decimal 493, etc.
      perm >= 292 or // 0444 - world readable
      (perm % 8) >= 4 or // others can read
      ((perm / 8) % 8) >= 2 // group can write
    )
  )
}

/**
 * Exclude test files
 */
predicate isInTestFile(CallExpr call) {
  call.getFile().getBaseName().regexpMatch(".*_test\\.go") or
  call.getFile().getAbsolutePath().regexpMatch(".*/test.*")
}

from FileCreationCall call, Expr filename, Expr perm
where
  not isInTestFile(call) and
  filename = call.getFilenameArg() and
  perm = call.getPermissionArg() and
  isSensitiveFilePath(filename) and
  isInsecurePermission(perm)
select call, "Insecure file permissions $@ for sensitive file $@", perm, "permission", filename, "filename"