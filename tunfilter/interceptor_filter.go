package tunfilter

// InterceptorFilter is a PacketFilter that uses an InterceptorManager
// This allows the filtered device to work with the new interceptor system
type InterceptorFilter struct {
	manager *InterceptorManager
}

// NewInterceptorFilter creates a new filter that uses an interceptor manager
func NewInterceptorFilter(manager *InterceptorManager) *InterceptorFilter {
	return &InterceptorFilter{
		manager: manager,
	}
}

// FilterOutbound checks all interceptors for outbound packets
func (f *InterceptorFilter) FilterOutbound(packet []byte, size int) FilterAction {
	if f.manager == nil {
		return FilterActionPass
	}
	return f.manager.HandlePacket(packet, DirectionOutbound)
}

// FilterInbound checks all interceptors for inbound packets
func (f *InterceptorFilter) FilterInbound(packet []byte, size int) FilterAction {
	if f.manager == nil {
		return FilterActionPass
	}
	return f.manager.HandlePacket(packet, DirectionInbound)
}
