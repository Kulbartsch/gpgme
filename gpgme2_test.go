//go:build gpgme2

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

func TestContext_RandomZBase32(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		wantErr bool
	}{
		{name: "Test 1", wantErr: false},
		{name: "Test 2", wantErr: false},
		{name: "Test 3", wantErr: false},
	}
	lastResult := "ABC"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := gpgme.New()
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}
			got, gotErr := c.RandomZBase32()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("RandomZBase32() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("RandomZBase32() succeeded unexpectedly")
			}
			// Verbose output the current result and length for easier debugging.
			t.Logf("RandomZBase32() returned: %q (length %d)", got, len(got))
			if got == lastResult {
				t.Errorf("RandomZBase32() returned same result as last time: %q", got)
			}
			lastResult = got
			const wantLen = 30
			if len(got) != wantLen {
				t.Errorf("RandomZBase32() returned %d characters, want %d", len(got), wantLen)
			}
		})
	}
}

func TestContext_RandomValue(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		maxValue int
		wantErr  bool
	}{
		{name: "valid max value", maxValue: 16, wantErr: false},
		{name: "zero max value", maxValue: 0, wantErr: true},
		{name: "just over maximum max value", maxValue: 4294967296, wantErr: true},
		// {name: "excessive max value", maxValue: 5294967295, wantErr: true}, // does not work because of uint32 casting
		{name: "sense less max value 1", maxValue: 1, wantErr: false},
		{name: "minimum valid max value", maxValue: 2, wantErr: false},
		{name: "maximum valid max value", maxValue: 4294967295, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := gpgme.New()
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}
			got, gotErr := c.RandomValue(uint32(tt.maxValue))
			t.Logf("Test %s with maxValue %d returned %d\n", tt.name, tt.maxValue, got)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("RandomValue() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("RandomValue() succeeded unexpectedly")
			}
			if int(got) > (tt.maxValue - 1) {
				t.Errorf("RandomValue() returned %d bytes, want %d", int(got), tt.maxValue)
			}
		})
	}
}
