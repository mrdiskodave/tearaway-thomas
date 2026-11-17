#!/bin/sh
# Compiles everything (tests and sandbox too) and runs the JUnit 3 tests.
# Needs only a JDK (21 or later).
#   ./test.sh               all the tests
#   ./test.sh Coroutine Map only test classes whose name contains one of these
set -e
cd "$(dirname "$0")"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) SEP=';' ;; # Git Bash: Windows' java wants ';'
  *) SEP=':' ;;
esac
rm -rf build/test && mkdir -p build/test
find src -name '*.java' > build/test-sources.txt
javac --release 21 -nowarn -encoding UTF-8 -cp "lib/*" -d build/test @build/test-sources.txt

# the test classes: src/a/b/CTest.java -> a.b.CTest
tests=$(grep -rl --include='*Test.java' 'extends TestCase' src | sed -e 's#^src/##' -e 's#\.java$##' -e 's#/#.#g' | sort)
if [ $# -gt 0 ]; then
  pattern=$(printf '%s\n' "$@" | paste -sd '|' -)
  tests=$(printf '%s\n' "$tests" | grep -E "$pattern" || true)
fi
if [ -z "$tests" ]; then
  echo "No test classes match: $*"
  exit 1
fi

# one JVM for the lot: a suite of all the classes
cat > build/AllTests.java <<'EOF'
import junit.framework.TestCase;
import junit.framework.TestResult;
import junit.framework.TestSuite;

public class AllTests {
	@SuppressWarnings("unchecked")
	public static void main(String[] args) throws Exception {
		TestSuite suite = new TestSuite("tearaway");
		for (String name : args) {
			suite.addTestSuite((Class<? extends TestCase>) Class.forName(name));
		}
		TestResult result = junit.textui.TestRunner.run(suite);
		System.exit(result.wasSuccessful() ? 0 : 1);
	}
}
EOF
# (src: tests load resources such as maps from beside the code)
java -ea -Djava.awt.headless=true -cp "build/test${SEP}src${SEP}lib/*" build/AllTests.java $tests
