package impl

import (
	"fmt"
	"math/rand"
)

// PickRandomRelay picks a random relay node from the routing table
func (n *node) PickRandomRelay(exclude map[string]struct{}) (string, bool) {
	n.routingMu.RLock()
	defer n.routingMu.RUnlock()

	candidates := make([]string, 0)

	for origin, relay := range n.routing {
		// exclude indirect neighbors
		if origin != relay {
			continue
		}

		if exclude != nil {
			_, found := exclude[origin]
			if found {
				continue
			}
		}

		candidates = append(candidates, origin)
	}

	if len(candidates) == 0 {
		return "", false
	}

	return candidates[rand.Intn(len(candidates))], true
}

// BuildRandomPath builds a random path of hops, useful to choose the middle nodes for a circuit
func (n *node) BuildRandomPath(hops int, destination string) ([]string, error) {
	exclude := make(map[string]struct{})
	path := make([]string, 0, hops)

	// exclude self
	if n.conf.Socket != nil {
		exclude[n.conf.Socket.GetAddress()] = struct{}{}
	}

	// exclude destination
	exclude[destination] = struct{}{}

	for i := 0; i < hops; i++ {
		r, ok := n.PickRandomRelay(exclude)
		if !ok {
			return nil, fmt.Errorf("no relay available")
		}
		path = append(path, r)
		exclude[r] = struct{}{}
	}

	return path, nil
}
