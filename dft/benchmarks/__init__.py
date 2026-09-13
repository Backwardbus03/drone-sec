"""
Benchmark Subsystem for Drone Forensic Toolkit (DFT).
Provides reference dataset registries, academic citations, ground truth specifications,
and automated evaluation suites for forensic verification.
"""

from dft.benchmarks.registry import (
    BENCHMARK_REGISTRY,
    BenchmarkDataset,
    BenchmarkMetric,
    BenchmarkCategory,
    get_benchmark_by_id,
    list_benchmarks,
)
from dft.benchmarks.evaluator import BenchmarkEvaluator, BenchmarkSuiteResult

__all__ = [
    "BENCHMARK_REGISTRY",
    "BenchmarkDataset",
    "BenchmarkMetric",
    "BenchmarkCategory",
    "get_benchmark_by_id",
    "list_benchmarks",
    "BenchmarkEvaluator",
    "BenchmarkSuiteResult",
]
