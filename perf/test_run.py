#!/usr/bin/env python3
"""Measurement-contract tests; fake timings never constitute performance data."""
import collections
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("ceremony_runner", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def rows():
    return [dict(
        case=case, iterations=10, concurrency=1, p50_ns=10,
        p95_ns=20, p99_ns=30, throughput_per_sec=1000,
        allocations_per_op=0, allocated_bytes_per_op=0,
    ) for case in sorted(runner.CASES)]


def encode(data):
    return "\n".join(json.dumps(row) for row in data)


class RowsTest(unittest.TestCase):
    def test_valid_complete_case_set(self):
        self.assertEqual(runner.parse_rows(encode(rows()), 10), rows())

    def test_indented_json_and_diagnostic_line(self):
        data = "diagnostic\n" + "\n".join("  " + json.dumps(row) for row in rows())
        self.assertEqual(runner.parse_rows(data, 10), rows())

    def test_duplicate_replacing_missing_case(self):
        data = rows()
        data[-1] = data[0].copy()
        self.assertEqual(len(data), 10)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            runner.parse_rows(encode(data), 10)

    def test_missing_case(self):
        with self.assertRaisesRegex(ValueError, "missing benchmark cases"):
            runner.parse_rows(encode(rows()[:-1]), 10)

    def test_unknown_case(self):
        data = rows()
        data[0]["case"] = "not-a-ceremony"
        with self.assertRaisesRegex(ValueError, "unknown"):
            runner.parse_rows(encode(data), 10)

    def test_wrong_case_type(self):
        data = rows()
        data[0]["case"] = []
        with self.assertRaises(ValueError):
            runner.parse_rows(encode(data), 10)

    def test_field_schema(self):
        for mutation in (lambda row: row.pop("p99_ns"), lambda row: row.update(extra=0)):
            with self.subTest(mutation=mutation):
                data = rows()
                mutation(data[0])
                with self.assertRaisesRegex(ValueError, "fields"):
                    runner.parse_rows(encode(data), 10)

    def test_wrong_iteration_count_or_type(self):
        for value in (9, 11, 10.0, True):
            with self.subTest(value=value):
                data = rows()
                data[0]["iterations"] = value
                with self.assertRaisesRegex(ValueError, "iterations"):
                    runner.parse_rows(encode(data), 10)

    def test_wrong_concurrency_or_type(self):
        for value in (0, 2, 1.0, True):
            with self.subTest(value=value):
                data = rows()
                data[0]["concurrency"] = value
                with self.assertRaisesRegex(ValueError, "concurrency"):
                    runner.parse_rows(encode(data), 10)

    def test_invalid_metrics(self):
        for metric in runner.METRICS:
            for value in (-1, float("nan"), float("inf"), float("-inf"), True, "10", None):
                with self.subTest(metric=metric, value=value):
                    data = rows()
                    data[0][metric] = value
                    with self.assertRaises(ValueError):
                        runner.parse_rows(encode(data), 10)

    def test_zero_throughput(self):
        data = rows()
        data[0]["throughput_per_sec"] = 0
        with self.assertRaisesRegex(ValueError, "positive"):
            runner.parse_rows(encode(data), 10)

    def test_reversed_quantiles(self):
        for metric, value in (("p50_ns", 21), ("p95_ns", 31)):
            data = rows()
            data[0][metric] = value
            with self.assertRaisesRegex(ValueError, "quantiles"):
                runner.parse_rows(encode(data), 10)

    def test_malformed_json(self):
        with self.assertRaises(json.JSONDecodeError):
            runner.parse_rows("{broken}", 10)


class ScheduleTest(unittest.TestCase):
    def test_two_way_alternates(self):
        labels = ["baseline", "candidate"]
        self.assertEqual([runner.round_order(labels, i) for i in range(4)],
                         [labels, labels[::-1], labels, labels[::-1]])

    def test_three_way_six_rounds_balance_positions(self):
        labels = ["baseline", "checkpoint", "candidate"]
        orders = [runner.round_order(labels, i) for i in range(6)]
        self.assertEqual(len({tuple(order) for order in orders}), 6)
        for position in range(3):
            self.assertEqual(collections.Counter(order[position] for order in orders),
                             dict.fromkeys(labels, 2))
        self.assertEqual(labels, ["baseline", "checkpoint", "candidate"])


class EnvironmentTest(unittest.TestCase):
    def test_iteration_override_without_mutating_parent(self):
        env = {"PERF_ITERATIONS": "999", "PATH": "/usr/bin"}
        actual = runner.benchmark_environment(env, 10)
        self.assertEqual(actual["PERF_ITERATIONS"], "10")
        self.assertEqual(env["PERF_ITERATIONS"], "999")
        self.assertEqual(actual["PATH"], env["PATH"])

    def test_reject_profiler_and_selector_inheritance(self):
        for name in ("PERF_CASE", "PERF_MTRACE", "MALLOC_TRACE", "LD_PRELOAD", "LD_AUDIT"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, name):
                runner.benchmark_environment({name: "enabled"}, 10)
        for name in ("PERF_CASE", "PERF_MTRACE"):
            with self.subTest(empty=name), self.assertRaisesRegex(ValueError, name):
                runner.benchmark_environment({name: ""}, 10)


class CliTest(unittest.TestCase):
    def test_reject_nonpositive_rounds_and_clamped_iterations(self):
        common = ["--baseline", "missing", "--candidate", "missing", "--output", "unused"]
        for extra in (["--rounds", "0"], ["--rounds", "-1"], ["--iterations", "9"]):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    runner.main(common + extra)
                self.assertEqual(error.exception.code, 2)

    def invoke(self, directory, code, checkpoint=False):
        program = directory / "fake-benchmark"
        program.write_text(f"#!{sys.executable}\n" + code)
        program.chmod(0o700)
        output = directory / "result.json"
        command = [sys.executable, str(Path(runner.__file__)),
                   "--baseline", str(program), "--candidate", str(program),
                   "--output", str(output), "--iterations", "10", "--rounds", "2"]
        if checkpoint:
            command.extend(["--checkpoint", str(program)])
        env = {key: value for key, value in os.environ.items()
               if key not in ("PERF_CASE", "PERF_MTRACE", "MALLOC_TRACE", "LD_PRELOAD", "LD_AUDIT")}
        return subprocess.run(command, text=True, capture_output=True, env=env), output

    def test_end_to_end_two_way_report(self):
        with tempfile.TemporaryDirectory() as temp:
            process, output = self.invoke(Path(temp), f"print({encode(rows())!r})\n")
            self.assertEqual(process.returncode, 0, process.stderr)
            report = json.loads(output.read_text())
            self.assertEqual([run["label"] for run in report["runs"]],
                             ["baseline", "candidate", "candidate", "baseline"])
            self.assertEqual(set(report["median_by_case"]), {"baseline", "candidate"})
            self.assertEqual(set(report["environment"]["artifacts"]), {"baseline", "candidate"})

    def test_end_to_end_three_way_report(self):
        with tempfile.TemporaryDirectory() as temp:
            code = "import os, sys\nassert os.environ['PERF_ITERATIONS'] == '10'\n"
            code += f"print({encode(rows())!r})\nprint('diagnostic retained', file=sys.stderr)\n"
            process, output = self.invoke(Path(temp), code, checkpoint=True)
            self.assertEqual(process.returncode, 0, process.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(len(report["runs"]), 6)
            self.assertEqual(len(report["environment"]["process_order"]), 2)
            self.assertEqual(len(report["environment"]["driver_sha256"]), 64)
            for label in ("baseline", "checkpoint", "candidate"):
                self.assertEqual(set(report["median_by_case"][label]), runner.CASES)
                for row in report["median_by_case"][label].values():
                    self.assertEqual(row["p99_ns"], 30)
            self.assertTrue(all("diagnostic retained" in run["stderr"] for run in report["runs"]))

    def test_invalid_child_output_never_publishes_report(self):
        with tempfile.TemporaryDirectory() as temp:
            data = rows()
            data[-1] = data[0].copy()
            process, output = self.invoke(Path(temp), f"print({encode(data)!r})\n")
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("duplicate", process.stderr)
            self.assertFalse(output.exists())

    def test_child_failure_preserves_stderr_and_no_report(self):
        with tempfile.TemporaryDirectory() as temp:
            process, output = self.invoke(Path(temp), "import sys\nprint('actual failure', file=sys.stderr)\nsys.exit(7)\n")
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("exited 7", process.stderr)
            self.assertIn("actual failure", process.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
