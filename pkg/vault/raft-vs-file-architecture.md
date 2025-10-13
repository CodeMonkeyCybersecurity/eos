# File Storage vs Raft Storage Architecture

## File Storage (Current - NOT RECOMMENDED)

```
┌─────────────────────────────────────────┐
│         Single Vault Node               │
│  ┌─────────────────────────────────┐   │
│  │   Vault Process (Port 8179)     │   │
│  └──────────────┬──────────────────┘   │
│                 │                       │
│                 ▼                       │
│  ┌─────────────────────────────────┐   │
│  │   File Storage Backend          │   │
│  │   /opt/vault/data               │   │
│  │   (Encrypted but single disk)   │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘

**Problems:**
❌ No High Availability
❌ Single Point of Failure
❌ Manual backup required
❌ No automatic failover
❌ Doesn't work with Vault Enterprise 1.12.0+
```

## Raft Storage (RECOMMENDED)

```
┌──────────── Availability Zone 1 ────────────┐
│  ┌────────────────────────────────────┐     │
│  │   Vault Node 1 (Leader)            │     │
│  │   ┌──────────────────────────┐     │     │
│  │   │ Raft Storage             │     │     │
│  │   │ /opt/vault/data          │     │     │
│  │   └──────────────────────────┘     │     │
│  └─────────────┬──────────────────────┘     │
└────────────────┼──────────────────────────────┘
                 │
                 │ Raft Consensus
                 │ (Port 8201)
        ┌────────┴────────┐
        │                 │
┌───────▼─── AZ 2 ────────┼──── AZ 3 ─────────┐
│  ┌────────────────┐     │  ┌──────────────┐ │
│  │ Vault Node 2   │     │  │ Vault Node 3 │ │
│  │ (Follower)     │     │  │ (Follower)   │ │
│  │ ┌────────────┐ │     │  │ ┌──────────┐ │ │
│  │ │Raft Storage│ │     │  │ │  Raft    │ │ │
│  │ │(Replicated)│ │     │  │ │ Storage  │ │ │
│  │ └────────────┘ │     │  │ └──────────┘ │ │
│  └────────────────┘     │  └──────────────┘ │
└───────▲─────────────────┴─────────▲──────────┘
        │                           │
┌───────┼─── AZ 2 ─────────┬────────┼─ AZ 3 ───┐
│  ┌────┴──────────┐       │   ┌────┴────────┐ │
│  │ Vault Node 4  │       │   │ Vault Node 5│ │
│  │ (Follower)    │       │   │ (Follower)  │ │
│  │ ┌───────────┐ │       │   │ ┌─────────┐ │ │
│  │ │   Raft    │ │       │   │ │  Raft   │ │ │
│  │ │  Storage  │ │       │   │ │ Storage │ │ │
│  │ └───────────┘ │       │   │ └─────────┘ │ │
│  └───────────────┘       │   └─────────────┘ │
└──────────────────────────┴───────────────────┘

**Benefits:**
✅ High Availability
✅ Automatic failover
✅ Distributed consensus
✅ Can lose 2 nodes and continue
✅ Built-in replication
✅ Required for Vault Enterprise 1.12.0+
```

## How Raft Consensus Works

```
Leader Election Process:

1. Initially all nodes start as FOLLOWERS
   
   Node1: FOLLOWER
   Node2: FOLLOWER  
   Node3: FOLLOWER
   Node4: FOLLOWER
   Node5: FOLLOWER

2. Election timeout → Node becomes CANDIDATE
   
   Node1: CANDIDATE (votes for self)
   Node2: FOLLOWER
   Node3: FOLLOWER
   Node4: FOLLOWER
   Node5: FOLLOWER

3. Candidate requests votes from peers
   
   Node1: CANDIDATE ─────requests vote────→ All Nodes
   
4. Majority votes → Becomes LEADER
   
   Node1: LEADER ✓ (Got 3+ votes)
   Node2: FOLLOWER
   Node3: FOLLOWER
   Node4: FOLLOWER
   Node5: FOLLOWER

5. Leader sends heartbeats to maintain leadership
   
   Node1: LEADER ─────heartbeat────→ All Followers
                 ←────acknowledgement─── 
```

## Write Operation Flow

```
Client writes secret to Vault:

1. Client → Leader
   ┌──────┐
   │Client│ ─────PUT /secret/data────→ Leader (Node1)
   └──────┘

2. Leader → Log Entry
   Leader: Creates uncommitted log entry
   
3. Leader → Followers (Replication)
   Leader ────log entry────→ Node2
          ────log entry────→ Node3
          ────log entry────→ Node4
          ────log entry────→ Node5

4. Followers → Acknowledgment
   Leader ←───ack─── Node2
          ←───ack─── Node3
          ←───ack─── Node4
          ←───ack─── Node5

5. Majority (3+) acks received → Commit
   Leader: Commits log entry to storage
   
6. Leader → Client
   Leader ────200 OK────→ Client

7. Leader → Followers (Commit notification)
   Leader ────commit notification────→ All Followers
   
8. All nodes apply to state machine
```

## Failure Scenarios

### Scenario 1: Follower Failure
```
Before:
Leader:    Node1 ✓
Followers: Node2 ✓, Node3 ✓, Node4 ✓, Node5 ✓

Node3 fails:
Leader:    Node1 ✓
Followers: Node2 ✓, Node3 ✗, Node4 ✓, Node5 ✓

Result: ✅ Cluster continues normally
Quorum: 3 nodes needed, 4 available
```

### Scenario 2: Leader Failure
```
Before:
Leader:    Node1 ✓
Followers: Node2 ✓, Node3 ✓, Node4 ✓, Node5 ✓

Node1 (leader) fails:
Followers: Node2 ✓, Node3 ✓, Node4 ✓, Node5 ✓

Election triggered:
Node2 becomes CANDIDATE
Requests votes → Gets majority
Node2 promoted to LEADER

After:
Leader:    Node2 ✓ (newly elected)
Followers: Node3 ✓, Node4 ✓, Node5 ✓
Down:      Node1 ✗

Result: ✅ Automatic failover (~1-5 seconds downtime)
```

### Scenario 3: Multi-Node Failure (within tolerance)
```
Before:
Leader:    Node1 ✓
Followers: Node2 ✓, Node3 ✓, Node4 ✓, Node5 ✓

Node3 and Node5 fail:
Leader:    Node1 ✓
Followers: Node2 ✓, Node3 ✗, Node4 ✓, Node5 ✗

Result: ✅ Cluster continues
Quorum: 3 nodes needed, 3 available (exactly at threshold)
```

### Scenario 4: Quorum Loss (CRITICAL)
```
Before:
Leader:    Node1 ✓
Followers: Node2 ✓, Node3 ✓, Node4 ✓, Node5 ✓

Node2, Node3, and Node4 fail:
Leader:    Node1 ✓
Followers: Node2 ✗, Node3 ✗, Node4 ✗, Node5 ✓

Result: ❌ CLUSTER UNAVAILABLE
Quorum: 3 nodes needed, only 2 available
Vault returns 503 errors
Cannot elect leader
Cannot commit writes
```

## Recovery from Quorum Loss

```
If you lose quorum, you have two options:

Option 1: Bring failed nodes back online
   - Fastest recovery
   - Cluster automatically reforms when quorum restored
   
Option 2: Restore from snapshot (if nodes unrecoverable)
   vault operator raft snapshot restore backup.snap
   - Requires manual intervention
   - May lose data since last snapshot
```

## Recommended Cluster Sizes

```
┌────────────────┬─────────────┬──────────────────┬─────────────┐
│ Cluster Size   │ Quorum Size │ Failure Tolerance│ Recommended │
├────────────────┼─────────────┼──────────────────┼─────────────┤
│ 1 node         │ 1           │ 0                │ ❌ Dev only │
│ 3 nodes        │ 2           │ 1                │ ⚠️  Minimal │
│ 5 nodes        │ 3           │ 2                │ ✅ Ideal    │
│ 7 nodes        │ 4           │ 3                │ ⚠️  Overkill│
└────────────────┴─────────────┴──────────────────┴─────────────┘

Why 5 nodes is optimal:
- Survives 2 node failures
- Survives 1 entire AZ failure (with proper distribution)
- Doesn't waste resources (7 nodes provides same AZ tolerance)
- Maintains odd number (prevents split-brain)
```
