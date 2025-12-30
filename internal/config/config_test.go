package config

import "testing"

func TestSPASecretTokenLengthMatches(t *testing.T) {
	if got := len(SPASecretToken); got != SPATokenLen {
		t.Fatalf("SPASecretToken length = %d, want %d", got, SPATokenLen)
	}
}

func TestFakePortsNotEmpty(t *testing.T) {
	if len(FakePorts) == 0 {
		t.Fatalf("FakePorts should not be empty")
	}
}


