"""Break the handler on purpose, and see whether the suite notices.

A passing test suite proves the code does what the tests say. It does not prove
the tests would notice if the code stopped doing it. This introduces one
deliberate defect at a time and reruns the whole suite against it. A mutation
the suite still passes is a hole: that line could be wrong in production and
nothing here would tell you.

    python tools/mutation_test.py                 the safety critical functions
    python tools/mutation_test.py --all           every function in the handler
    python tools/mutation_test.py --functions a,b  a named set
    python tools/mutation_test.py --limit 40      stop after N mutations

Each run copies the module to a temporary directory, mutates the copy, and runs
`unittest discover` there. Nothing in the working tree is touched.

Mutations applied, one at a time:

    comparison     ==  !=  <  <=  >  >=  in  is        swapped for their opposite
    boolean        and <-> or
    negation       `not X` reduced to `X`
    constant       True <-> False, and n -> n + 1
    refusal        a `raise` statement replaced by `pass`

The last one matters most here. This module's central claim is that it refuses:
on drift, on an unsettled set, on an unknown outcome. A `raise` that can be
deleted without a test failing is a refusal nobody is checking.
"""

import argparse
import ast
import copy
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
HANDLER = ROOT / "handlers" / "handler.py"
# tools/ and docs/ are staged too: two tests import check_workflow, and the
# parity checks read the docs. A missing one looks like a handler failure.
COPY = ("handlers", "tests", "tools", "docs", "module.json", "workflow", "README.md")

# Where a wrong answer is a safety failure rather than a cosmetic one.
CRITICAL = [
    "verify_plan", "_fingerprint", "_describe_drift", "_structured",
    "_settle", "_apply_result", "_as_runtime", "_guard",
    "_redact", "_assert_allowed", "_org_host",
    "_paged", "_next_link", "_settled_members", "_paged_optional",
    "_scan_untrusted", "_needle_matches", "_flag_untrusted",
    "_header", "_clock_complaint", "_server_skew", "_wants_new_nonce",
    "_classify_actor", "_int", "_as_int",
]

OPPOSITE = {
    ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
    ast.Lt: ast.GtE, ast.GtE: ast.Lt,
    ast.Gt: ast.LtE, ast.LtE: ast.Gt,
    ast.In: ast.NotIn, ast.NotIn: ast.In,
    ast.Is: ast.IsNot, ast.IsNot: ast.Is,
}


class Sites(ast.NodeVisitor):
    """Collect every mutable position, tagged with the function it sits in."""

    def __init__(self, wanted):
        self.wanted = wanted
        self.stack = []
        self.found = []

    def _where(self):
        return self.stack[-1] if self.stack else "<module>"

    def _keep(self):
        return self.wanted is None or self._where() in self.wanted

    def visit_FunctionDef(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_Compare(self, node):
        if self._keep():
            for i, op in enumerate(node.ops):
                if type(op) in OPPOSITE:
                    self.found.append((self._where(), "comparison", node, i,
                                       type(op).__name__))
        self.generic_visit(node)

    def visit_BoolOp(self, node):
        if self._keep():
            self.found.append((self._where(), "boolean", node, None,
                               type(node.op).__name__))
        self.generic_visit(node)

    def visit_UnaryOp(self, node):
        if self._keep() and isinstance(node.op, ast.Not):
            self.found.append((self._where(), "negation", node, None, "Not"))
        self.generic_visit(node)

    def visit_Constant(self, node):
        if self._keep():
            if isinstance(node.value, bool):
                self.found.append((self._where(), "constant", node, None,
                                   repr(node.value)))
            elif isinstance(node.value, int) and not isinstance(node.value, bool):
                self.found.append((self._where(), "constant", node, None,
                                   repr(node.value)))
        self.generic_visit(node)

    def visit_Raise(self, node):
        if self._keep():
            self.found.append((self._where(), "refusal", node, None, "raise"))
        self.generic_visit(node)


def mutate(tree, index, wanted):
    """Return a copy of the tree with exactly the site at `index` mutated."""
    clone = copy.deepcopy(tree)
    sites = Sites(wanted)
    sites.visit(clone)
    where, kind, node, slot, detail = sites.found[index]

    if kind == "comparison":
        node.ops[slot] = OPPOSITE[type(node.ops[slot])]()
    elif kind == "boolean":
        node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
    elif kind == "negation":
        replace(clone, node, node.operand)
    elif kind == "constant":
        node.value = (not node.value) if isinstance(node.value, bool) else node.value + 1
    elif kind == "refusal":
        replace(clone, node, ast.Pass())
    return clone, where, kind, detail


def replace(tree, target, new):
    """Swap one node for another, in place, wherever it appears."""
    for parent in ast.walk(tree):
        for field, value in ast.iter_fields(parent):
            if value is target:
                setattr(parent, field, new)
                return
            if isinstance(value, list):
                for i, item in enumerate(value):
                    if item is target:
                        value[i] = new
                        return


def run_suite(workdir, timeout=180):
    """True when the suite passes. A mutation the suite passes is a hole."""
    try:
        done = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "tests"],
            cwd=workdir, capture_output=True, text=True, timeout=timeout,
        )
        return done.returncode == 0
    except subprocess.TimeoutExpired:
        return False          # a hang is a failure, which counts as caught


def stage():
    work = pathlib.Path(tempfile.mkdtemp(prefix="mutation-"))
    for name in COPY:
        src = ROOT / name
        if src.is_dir():
            shutil.copytree(src, work / name)
        elif src.exists():
            shutil.copy2(src, work / name)
    return work


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--functions", default="")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    if args.all:
        wanted = None
    elif args.functions:
        wanted = {f.strip() for f in args.functions.split(",") if f.strip()}
    else:
        wanted = set(CRITICAL)

    source = HANDLER.read_text(encoding="utf8")
    tree = ast.parse(source)
    sites = Sites(wanted)
    sites.visit(tree)
    total = len(sites.found)
    if args.limit:
        total = min(total, args.limit)
    print("mutation sites: %d%s" % (total, "" if wanted is None else
                                    " across %d functions" % len(wanted)))

    work = stage()
    target = work / "handlers" / "handler.py"
    try:
        # The harness must be trusted before its results are. An unmutated
        # round trip through ast has to pass, or a survivor might only mean
        # the rewrite broke something unrelated.
        target.write_text(ast.unparse(tree), encoding="utf8")
        if not run_suite(work):
            print("ABORT: the suite fails on an unmutated ast round trip; "
                  "results would be meaningless")
            return 2
        print("harness check: unmutated round trip passes\n")

        survivors, caught, started = [], 0, time.time()
        for i in range(total):
            mutant, where, kind, detail = mutate(tree, i, wanted)
            try:
                target.write_text(ast.unparse(mutant), encoding="utf8")
            except Exception:
                continue                      # unparseable mutant, skip it
            if run_suite(work):
                survivors.append((where, kind, detail))
                mark = "SURVIVED"
            else:
                caught += 1
                mark = "caught"
            print("  %4d/%d  %-9s %-26s %-10s %s"
                  % (i + 1, total, mark, where, kind, detail))

        print("\n%d mutations, %d caught, %d survived, %.0fs"
              % (total, caught, len(survivors), time.time() - started))
        if survivors:
            print("\nSURVIVORS, each one a line the suite does not defend:")
            for where, kind, detail in survivors:
                print("  %-26s %-10s %s" % (where, kind, detail))
        else:
            print("\nNo survivors: every deliberate defect was caught.")
        return 1 if survivors else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
