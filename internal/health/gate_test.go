package health

import "testing"

func TestGateFailsClosedAndTransitions(t *testing.T) {
	t.Parallel()

	gate := &Gate{}
	if gate.Ready() {
		t.Fatal("new Gate is ready, want not ready")
	}

	gate.MarkReady()
	if !gate.Ready() {
		t.Fatal("Gate is not ready after MarkReady")
	}

	gate.MarkNotReady()
	if gate.Ready() {
		t.Fatal("Gate is ready after MarkNotReady")
	}
}
