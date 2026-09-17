package deliver

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Citing a test by name claims something is guaranteed, and a citation to a
// test that does not exist hides the absence of the guard behind a
// description of it. That has happened downstream: a documented marker named
// the test pinning it, no such test existed, and the format changed three
// times that evening.
func TestEveryCitedTestExists(t *testing.T) {
	cited, defined := scanCitations(t, "..")
	if len(defined) == 0 {
		t.Fatal("found no test declarations at all; the walk is not seeing the module")
	}
	for name, files := range cited {
		if defined[name] {
			continue
		}
		t.Errorf("%s is cited in %s but defined nowhere: either write it, or delete the "+
			"sentence claiming it guards something", name, strings.Join(files, ", "))
	}
}

// scanCitations returns every Test name mentioned under root and every one
// declared there.
func scanCitations(t *testing.T, root string) (cited map[string][]string, defined map[string]bool) {
	t.Helper()
	cited, defined = map[string][]string{}, map[string]bool{}

	mention := regexp.MustCompile(`\bTest[A-Z][A-Za-z0-9_]*`)
	declare := regexp.MustCompile(`(?m)^func (Test[A-Z][A-Za-z0-9_]*)`)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(b)
		for _, m := range declare.FindAllStringSubmatch(src, -1) {
			defined[m[1]] = true
		}
		// Strip declarations before looking for mentions, so a function's
		// own signature does not count as a citation of itself.
		for _, name := range mention.FindAllString(declare.ReplaceAllString(src, ""), -1) {
			cited[name] = append(cited[name], path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return cited, defined
}

// The check has to be able to fail, or it is a citation of itself.
func TestEveryCitedTestExistsCatchesADanglingName(t *testing.T) {
	// The fixture's names are assembled at runtime rather than written
	// literally: a literal here is itself a citation, and the scan would
	// flag this file for mentioning tests that exist only inside its own
	// test data. Caught by running the check — it reported exactly that.
	gone := "Test" + "ThisWasRenamedAwayLastYear"
	real := "Test" + "SomethingElse"

	dir := t.TempDir()
	src := "package x\n\n// " + gone + " guards the thing.\nfunc " + real + "(t *testing.T) {}\n"
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cited, defined := scanCitations(t, dir)
	if !defined[real] {
		t.Error("the declared test was not seen")
	}
	if _, ok := cited[gone]; !ok {
		t.Error("the dangling citation in the comment was not seen")
	}
	if defined[gone] {
		t.Error("a name that appears only in a comment must not count as defined")
	}
}
