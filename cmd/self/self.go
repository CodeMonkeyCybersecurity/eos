diff --git a/cmd/self/self.go b/cmd/self/self.go
@@
-    "strings"
-    "syscall"
-    "time"
+    "strings"
+    "syscall"
@@
-        lockFd, lockErr := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR, 0600)
+        lockFd, lockErr := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR, 0600)
         if lockErr != nil {
             l.Warn("Could not open lock file", zap.String("path", lockPath), zap.Error(lockErr))
         } else {
             if err := syscall.Flock(lockFd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
-                return eos_err.NewUserError("another eos self update is currently running (lock held); try again in a minute")
+                // close before returning to avoid fd leak
+                _ = syscall.Close(lockFd)
+                return eos_err.NewExpectedError(rc.Ctx, errors.New("another eos self update is currently running (lock held); try again in a minute"))
             }
             defer func() {
                 _ = syscall.Flock(lockFd, syscall.LOCK_UN)
                 _ = syscall.Close(lockFd)
                 _ = os.Remove(lockPath)
             }()
         }
@@
-        // If a stash exists, tell the user but keep it.
-        if err := run(rc.Ctx, l, "bash", "-lc", "git stash list | sed -n '1p'"); err == nil {
-            l.Warn("Stash entries detected; not applying them during update. You can manually apply with: git stash pop (may conflict).")
-        }
+        // If a stash exists, tell the user but keep it.
+        // This returns 0 only when the stash list is non-empty.
+        if err := run(rc.Ctx, l, "bash", "-lc", "[[ -n \"$(git stash list)\" ]]"); err == nil {
+            l.Warn("Stash entries detected; not applying them during update. You can manually apply with: git stash pop (may conflict).")
+        }
@@
-    // Harden PATH for safety (drop current dir)
-    c.Env = security.PrunedEnv(os.Environ())
+    // Harden PATH for safety (drop current dir). If security.PrunedEnv doesn’t exist, use the fallback.
+    if pruned := pruneEnvSafe(os.Environ()); pruned != nil {
+        c.Env = pruned
+    } else {
+        c.Env = os.Environ()
+    }
     return c.Run()
 }
+
+// pruneEnvSafe removes an empty/current-dir PATH entry and returns a safe env slice.
+// If your repo has security.PrunedEnv, you can delete this and call that directly.
+func pruneEnvSafe(env []string) []string {
+    var out []string
+    for _, kv := range env {
+        if strings.HasPrefix(kv, "PATH=") {
+            // Strip leading/trailing ':' which imply current dir, and remove ':.:' patterns.
+            path := strings.Trim(kv[5:], ":")
+            path = strings.ReplaceAll(path, "::", ":")
+            out = append(out, "PATH="+path)
+            continue
+        }
+        out = append(out, kv)
+    }
+    return out
+}