# Improved Wazuh Architecture

## Message Queue Migration

Replace PostgreSQL NOTIFY/LISTEN with Redis Streams for true event-driven architecture:

```go
// pkg/wazuh/queue/redis_stream.go
type StreamProcessor struct {
    client redis.Client
    logger *otelzap.Logger
}

func (s *StreamProcessor) PublishAlert(alert *Alert) error {
    return s.client.XAdd(ctx, &redis.XAddArgs{
        Stream: "wazuh:alerts",
        Values: map[string]interface{}{
            "alert_id": alert.ID,
            "level": alert.Level,
            "timestamp": time.Now().Unix(),
        },
    }).Err()
}

func (s *StreamProcessor) ConsumeAlerts(consumerGroup string, handler AlertHandler) {
    for {
        streams, err := s.client.XReadGroup(ctx, &redis.XReadGroupArgs{
            Group:    consumerGroup,
            Consumer: "worker-" + os.Getenv("HOSTNAME"),
            Streams:  []string{"wazuh:alerts", ">"},
            Count:    10,
            Block:    time.Second * 5,
        }).Result()
        
        if err != nil {
            s.logger.Error("Failed to read from stream", zap.Error(err))
            continue
        }
        
        for _, stream := range streams {
            for _, message := range stream.Messages {
                if err := handler.Process(message); err != nil {
                    s.logger.Error("Failed to process message", 
                        zap.String("message_id", message.ID),
                        zap.Error(err))
                    continue
                }
                
                // Acknowledge successful processing
                s.client.XAck(ctx, "wazuh:alerts", consumerGroup, message.ID)
            }
        }
    }
}
```

## State Machine Implementation

```go
// pkg/wazuh/state/machine.go
type AlertState string

const (
    StateNew           AlertState = "new"
    StateEnriching     AlertState = "enriching"
    StateEnriched      AlertState = "enriched"
    StateAnalyzing     AlertState = "analyzing"
    StateAnalyzed      AlertState = "analyzed"
    StateFormatting    AlertState = "formatting"
    StateFormatted     AlertState = "formatted"
    StateSending       AlertState = "sending"
    StateSent          AlertState = "sent"
    StateError         AlertState = "error"
)

type StateMachine struct {
    transitions map[AlertState][]AlertState
    db         *gorm.DB
    logger     *otelzap.Logger
}

func NewStateMachine() *StateMachine {
    return &StateMachine{
        transitions: map[AlertState][]AlertState{
            StateNew:        {StateEnriching, StateError},
            StateEnriching:  {StateEnriched, StateError},
            StateEnriched:   {StateAnalyzing, StateError},
            StateAnalyzing:  {StateAnalyzed, StateError},
            StateAnalyzed:   {StateFormatting, StateError},
            StateFormatting: {StateFormatted, StateError},
            StateFormatted:  {StateSending, StateError},
            StateSending:    {StateSent, StateError},
            StateError:      {StateNew}, // Allow retry
        },
    }
}

func (sm *StateMachine) Transition(alertID string, newState AlertState) error {
    var alert Alert
    if err := sm.db.First(&alert, "id = ?", alertID).Error; err != nil {
        return fmt.Errorf("alert not found: %w", err)
    }
    
    currentState := AlertState(alert.State)
    validTransitions := sm.transitions[currentState]
    
    valid := false
    for _, validState := range validTransitions {
        if validState == newState {
            valid = true
            break
        }
    }
    
    if !valid {
        return fmt.Errorf("invalid state transition from %s to %s", currentState, newState)
    }
    
    alert.State = string(newState)
    alert.StateTransitionedAt = time.Now()
    
    return sm.db.Save(&alert).Error
}
```

## Circuit Breaker Implementation

```go
// pkg/wazuh/circuit/breaker.go
type CircuitBreaker struct {
    name           string
    maxFailures    int
    resetTimeout   time.Duration
    failures       int
    lastFailTime   time.Time
    state          CircuitState
    mutex          sync.RWMutex
    logger         *otelzap.Logger
}

type CircuitState int

const (
    StateClosed CircuitState = iota
    StateOpen
    StateHalfOpen
)

func (cb *CircuitBreaker) Call(fn func() error) error {
    cb.mutex.RLock()
    state := cb.state
    cb.mutex.RUnlock()
    
    if state == StateOpen {
        if time.Since(cb.lastFailTime) > cb.resetTimeout {
            cb.mutex.Lock()
            cb.state = StateHalfOpen
            cb.mutex.Unlock()
            cb.logger.Info("Circuit breaker transitioning to half-open",
                zap.String("circuit", cb.name))
        } else {
            return fmt.Errorf("circuit breaker is open for %s", cb.name)
        }
    }
    
    err := fn()
    
    cb.mutex.Lock()
    defer cb.mutex.Unlock()
    
    if err != nil {
        cb.failures++
        cb.lastFailTime = time.Now()
        
        if cb.failures >= cb.maxFailures {
            cb.state = StateOpen
            cb.logger.Error("Circuit breaker opened",
                zap.String("circuit", cb.name),
                zap.Int("failures", cb.failures))
        }
        return err
    }
    
    // Success
    cb.failures = 0
    cb.state = StateClosed
    return nil
}
```