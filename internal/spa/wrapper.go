package spa

// PhantomObjectsWrapper wraps PhantomObjects to implement SPAStatsProvider
// This is a workaround since PhantomObjects is generated in cmd/agent
type PhantomObjectsWrapper struct {
	SpaAuthSuccessMap interface{ Lookup(key uint32, value *uint64) error }
	SpaAuthFailedMap  interface{ Lookup(key uint32, value *uint64) error }
}

// GetSpaAuthSuccess returns the SPA auth success map
func (w *PhantomObjectsWrapper) GetSpaAuthSuccess() interface{ Lookup(key uint32, value *uint64) error } {
	return w.SpaAuthSuccessMap
}

// GetSpaAuthFailed returns the SPA auth failed map
func (w *PhantomObjectsWrapper) GetSpaAuthFailed() interface{ Lookup(key uint32, value *uint64) error } {
	return w.SpaAuthFailedMap
}

// NewWrapper creates a wrapper for PhantomObjects
func NewWrapper(successMap, failedMap interface{ Lookup(key uint32, value *uint64) error }) SPAStatsProvider {
	return &PhantomObjectsWrapper{
		SpaAuthSuccessMap: successMap,
		SpaAuthFailedMap:  failedMap,
	}
}

