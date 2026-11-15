package hide

import "testing"

func TestTheLinkedCoreIsTheVersionThisBindingWasWrittenFor(t *testing.T) {
	if Version() != BindingVersion {
		t.Fatalf("the linked core is %q, this binding is %q", Version(), BindingVersion)
	}

	for _, same := range [][2]string{
		{"0.9.1", "0.9.1"},
		{"1.2.3", "1.2.3"},
		{"0.10.0", "0.10.0-rc.1"},
		{"0.10.0", "0.10.0+build.5"},
	} {
		if err := checkCoreVersion(same[0], same[1]); err != nil {
			t.Errorf("binding %q with core %q was refused: %v", same[0], same[1], err)
		}
	}
	for _, different := range [][2]string{
		{"0.9.1", "0.9.0"},
		{"0.9.1", "0.10.1"},
		{"0.9.1", "1.9.1"},
		{"0.9.1", "0.9.10"},
		{"0.9.1", "0.9"},
		{"0.9.1", "0.9.1.0"},
		{"0.9.1", ""},
		{"0.9.1", "v0.9.1"},
		{"0.9.1", "0.+9.1"},
		{"0.9.1", "garbage"},
	} {
		if err := checkCoreVersion(different[0], different[1]); err == nil {
			t.Errorf("binding %q accepted core %q", different[0], different[1])
		}
	}
}
