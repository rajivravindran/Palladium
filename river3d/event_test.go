package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestEveryEmittedClassIsInEngineVocabulary(t *testing.T) {
	allowed := map[string]bool{}
	for _, c := range EngineClasses {
		allowed[c] = true
	}
	for name := range binaryDetails {
		class, detail := classifyBinary("/usr/bin/" + name)
		if !allowed[class] {
			t.Errorf("%s (%s) -> %q is not an engine class", name, detail, class)
		}
	}
	for detail := range detailToClass {
		if !allowed[detailToClass[detail]] {
			t.Errorf("detail %s maps outside the engine vocabulary", detail)
		}
	}
	if c, d := classifyBinary("/opt/custom/tool"); c != "OTHER" || d != "OTHER" {
		t.Errorf("unknown binary -> %s/%s", c, d)
	}
}

func TestClassExamples(t *testing.T) {
	cases := map[string][2]string{
		"/usr/bin/cat":        {"DIAGNOSTIC", "FILE_UTIL"},
		"/bin/sh":             {"INTERPRETER", "SHELL"},
		"/usr/bin/curl":       {"NET_CLIENT", "NET_CLIENT"},
		"/usr/bin/sudo":       {"PRIVILEGED_TOOL", "PRIV_ESC"},
		"/usr/sbin/capsh":     {"PRIVILEGED_TOOL", "RECON"},
		"/usr/bin/ss":         {"DIAGNOSTIC", "RECON"},
		"/usr/bin/openssl":    {"NET_CLIENT", "ENCODER"},
		"/usr/bin/pip3":       {"NET_CLIENT", "PKG"},
		"/usr/bin/python3.12": {"INTERPRETER", "INTERPRETER"},
	}
	for exe, want := range cases {
		c, d := classifyBinary(exe)
		if c != want[0] || d != want[1] {
			t.Errorf("%s -> %s/%s, want %s/%s", exe, c, d, want[0], want[1])
		}
	}
}

// Guards against the two vocabularies drifting apart in the monorepo.
func TestEngineClassesMatchPolicyEngine(t *testing.T) {
	src, err := os.ReadFile("../policy/profile.go")
	if err != nil {
		t.Skip("policy engine source not alongside river3d")
	}
	m := regexp.MustCompile(`var classes = map\[string\]bool\{([^}]*)\}`).FindSubmatch(src)
	if m == nil {
		t.Fatal("could not find `classes` in policy/profile.go")
	}
	found := regexp.MustCompile(`"([A-Z_]+)":\s*true`).FindAllSubmatch(m[1], -1)
	engine := []string{}
	for _, f := range found {
		engine = append(engine, string(f[1]))
	}
	sort.Strings(engine)
	ours := append([]string{}, EngineClasses...)
	sort.Strings(ours)
	if strings.Join(engine, ",") != strings.Join(ours, ",") {
		t.Fatalf("policy engine classes %v != river3d EngineClasses %v", engine, ours)
	}
}
