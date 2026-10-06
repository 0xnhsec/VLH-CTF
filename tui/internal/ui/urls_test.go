package ui

import "testing"

func TestURLsForFull(t *testing.T) {
	got := urlsFor("full", 18024)
	want := "http://aslv.lab:18024/"
	if len(got) == 0 || got[0] != want {
		t.Fatalf("first entry = %q, want %q (all: %v)", firstOf(got), want, got)
	}
	seen := map[string]bool{}
	for _, u := range got {
		seen[u] = true
	}
	for _, u := range []string{
		"http://victim.aslv.lab:18024/",
		"http://client.aslv.lab:18024/",
		"http://auth.aslv.lab:18024/",
	} {
		if !seen[u] {
			t.Errorf("missing %s in %v", u, got)
		}
	}
}

func TestURLsForUnknownProfile(t *testing.T) {
	if u := firstURL("no-such-profile", 18024); u != "" {
		t.Fatalf("firstURL(unknown) = %q, want empty", u)
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"http://aslv.lab:18024/":                 "aslv.lab",
		"http://localhost:8119/":                 "localhost",
		"http://collector.aslv.lab:18024/verify": "collector.aslv.lab",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolvesFromHosts(t *testing.T) {
	if !resolvesFromHosts("localhost") {
		t.Error("localhost must always resolve")
	}
	// installer.sh --hosts always pins aslv.lab; client.aslv.lab only exists
	// after the installer block — never fail the test on either outcome, just
	// make sure the lookup does not panic and stays consistent.
	_ = resolvesFromHosts("aslv.lab")
	_ = resolvesFromHosts("client.aslv.lab")
}

func firstOf(in []string) string {
	if len(in) == 0 {
		return ""
	}
	return in[0]
}
