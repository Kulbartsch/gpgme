package gpgme_test

import (
	"testing"

	"github.com/kulbartsch/gpgme"
)

func TestContext_RandomBytes(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		length  int
		wantErr bool
	}{
		{name: "valid length", length: 16, wantErr: false},
		{name: "zero length", length: 0, wantErr: true},
		{name: "just over maximum length", length: 1025, wantErr: true},
		{name: "excessive length", length: 2048, wantErr: true},
		{name: "minimum valid length", length: 1, wantErr: false},
		{name: "maximum valid length", length: 1024, wantErr: false},
		{name: "negative length", length: -10, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := gpgme.New()
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}
			got, gotErr := c.RandomBytes(tt.length)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("RandomBytes() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("RandomBytes() succeeded unexpectedly")
			}
			if len(got) != tt.length {
				t.Errorf("RandomBytes() returned %d bytes, want %d", len(got), tt.length)
			}
		})
	}
}
