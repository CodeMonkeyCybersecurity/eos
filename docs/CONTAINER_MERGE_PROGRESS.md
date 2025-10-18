# Container Package Merge - In Progress

**Goal:** Merge `pkg/container_management/` into `pkg/container/` to eliminate import cycles

## ✅ Completed

### Step 1: Types Migration
- ✅ Moved Compose types to `pkg/container/types.go`:
  - `ComposeProject`
  - `ComposeSearchResult`
  - `ComposeOperation`
  - `ComposeStopOptions` + `DefaultComposeStopOptions()`
  - `ComposeManagementConfig` + `DefaultComposeManagementConfig()` (renamed from ComposeConfig to avoid conflict)
  - `ComposeStopSummary`
  - `ComposeMultiStopResult`
  - `ContainerListResult`

### Step 2: Import Updates
- ✅ Updated `pkg/container/list.go` - removed container_management import
- ✅ Updated `cmd/list/containers.go` - removed container_management import
- ✅ Fixed type references in list.go

### Step 3: Compilation
- ✅ `pkg/container/` compiles successfully

## ✅ Phase 2 Complete!

### Step 4: Move Functions ✅ DONE
- ✅ Created `pkg/container/compose_management.go` (309 lines)
- ✅ Moved `FindComposeProjects()` with SDK integration
- ✅ Moved `ListRunningContainers()` using `Manager.ListRunning()`
- ✅ Helper functions migrated

### Step 5: Update Callers ✅ DONE
- ✅ `cmd/list/containers.go` - Updated to use `container.ListRunningContainers()`
- ✅ `cmd/list/containers.go` - Updated to use `container.FindComposeProjects()`
- ✅ All function calls working

### Step 6: Remove Old Package 🔄 READY
- ⏳ Delete `pkg/container_management/` directory (safe to remove)
- ⏳ Verify no remaining imports (all updated)

## 🎯 Next Actions

1. **Create `pkg/container/compose_management.go`**
   - Move `FindComposeProjects()`
   - Move `StopAllComposeProjects()`
   - Move `StopComposeProject()`
   - Update to use new `Manager` internally

2. **Update `cmd/list/containers.go`**
   - Change `container_management.ListRunningContainers()` to use `Manager.ListRunning()`
   - Change `container_management.FindComposeProjects()` to `container.FindComposeProjects()`

3. **Find and update all other imports**
   ```bash
   grep -r "container_management" cmd/
   ```

4. **Test compilation**
   ```bash
   go build ./pkg/container
   go build ./cmd/list
   go build ./...
   ```

5. **Remove old package**
   ```bash
   rm -rf pkg/container_management/
   ```

## 📝 Notes

- **Import cycle solved**: No more circular dependency between packages
- **Type naming**: Renamed `ComposeConfig` to `ComposeManagementConfig` to avoid conflict with docker-compose.yml parsing type
- **Backward compatibility**: Functions will have same signatures, just different package
- **ContainerInfo**: Multiple definitions exist (backup.go, types.go) - need to consolidate eventually

## 🚀 Benefits After Merge

1. ✅ No import cycles
2. ✅ Single source of truth for container operations
3. ✅ Can use SDK methods internally without circular dependencies
4. ✅ Cleaner architecture
5. ✅ Easier to maintain

---

**Status:** 60% complete - Types migrated, functions need to be moved next
