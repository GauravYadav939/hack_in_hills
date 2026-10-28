"""
Timing Normalization Benchmark for Glasshouse Broker.

This script measures the effectiveness of response-time normalization
by comparing response time distributions with and without padding.

It demonstrates:
1. Response times without normalization (raw variance)
2. Response times with normalization (fixed target)
3. Statistical comparison of the distributions

Usage:
    python scripts/timing_benchmark.py
"""

import asyncio
import time
import statistics
from typing import List, Dict
import json


async def simulate_processing(min_ms: float = 100, max_ms: float = 1000) -> float:
    """
    Simulate variable processing time.

    Returns:
        Processing time in seconds
    """
    import random
    delay = random.uniform(min_ms / 1000, max_ms / 1000)
    await asyncio.sleep(delay)
    return delay


async def with_normalization(actual_time: float, target: float) -> float:
    """
    Apply timing normalization.

    Args:
        actual_time: Actual processing time in seconds
        target: Target response time in seconds

    Returns:
        Total time including padding
    """
    if actual_time < target:
        padding = target - actual_time
        await asyncio.sleep(padding)
        return target
    return actual_time


async def run_benchmark(
    num_requests: int = 50,
    target_time: float = 2.0
) -> Dict[str, List[float]]:
    """
    Run timing benchmark.

    Args:
        num_requests: Number of requests to simulate
        target_time: Target response time for normalization (seconds)

    Returns:
        Dictionary with raw and normalized response times
    """
    raw_times = []
    normalized_times = []

    print(f"Running benchmark with {num_requests} requests...")
    print(f"Target normalization time: {target_time}s")
    print()

    for i in range(num_requests):
        # Measure raw processing time
        start = time.time()
        processing_time = await simulate_processing()
        raw_elapsed = time.time() - start
        raw_times.append(raw_elapsed * 1000)  # Convert to ms

        # Measure with normalization
        start = time.time()
        processing_time = await simulate_processing()
        await with_normalization(processing_time, target_time)
        normalized_elapsed = time.time() - start
        normalized_times.append(normalized_elapsed * 1000)  # Convert to ms

        if (i + 1) % 10 == 0:
            print(f"  Progress: {i + 1}/{num_requests}")

    return {
        "raw": raw_times,
        "normalized": normalized_times
    }


def analyze_results(results: Dict[str, List[float]]) -> None:
    """
    Analyze and print benchmark results.

    Args:
        results: Dictionary with raw and normalized response times
    """
    raw = results["raw"]
    normalized = results["normalized"]

    print("\n" + "=" * 70)
    print("TIMING NORMALIZATION BENCHMARK RESULTS")
    print("=" * 70)
    print()

    print("RAW (No Normalization):")
    print(f"  Mean:   {statistics.mean(raw):.2f} ms")
    print(f"  Median: {statistics.median(raw):.2f} ms")
    print(f"  StdDev: {statistics.stdev(raw):.2f} ms")
    print(f"  Min:    {min(raw):.2f} ms")
    print(f"  Max:    {max(raw):.2f} ms")
    print()

    print("NORMALIZED (With Padding):")
    print(f"  Mean:   {statistics.mean(normalized):.2f} ms")
    print(f"  Median: {statistics.median(normalized):.2f} ms")
    print(f"  StdDev: {statistics.stdev(normalized):.2f} ms")
    print(f"  Min:    {min(normalized):.2f} ms")
    print(f"  Max:    {max(normalized):.2f} ms")
    print()

    # Calculate variance reduction
    raw_variance = statistics.variance(raw)
    normalized_variance = statistics.variance(normalized)
    variance_reduction = ((raw_variance - normalized_variance) / raw_variance) * 100

    print("EFFECTIVENESS:")
    print(f"  Raw variance:        {raw_variance:.2f}")
    print(f"  Normalized variance: {normalized_variance:.2f}")
    print(f"  Variance reduction:  {variance_reduction:.1f}%")
    print()

    print("INTERPRETATION:")
    if variance_reduction > 80:
        print("  ✓ Excellent - Timing normalization significantly reduces variance")
    elif variance_reduction > 50:
        print("  ✓ Good - Timing normalization reduces variance")
    else:
        print("  ⚠ Limited - Timing normalization has limited effect")
    print()

    print("LIMITATIONS:")
    print("  • This only tests timing padding, not actual side-channel resistance")
    print("  • Real attackers may use additional signals (cache, power, etc.)")
    print("  • Timing normalization is one layer; defense-in-depth is required")
    print("  • Network jitter may affect real-world effectiveness")
    print()


def save_results(results: Dict[str, List[float]], filename: str = "timing_results.json"):
    """Save results to JSON file for further analysis."""
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to: {filename}")


async def main():
    print("=" * 70)
    print("Glasshouse Timing Normalization Benchmark")
    print("=" * 70)
    print()
    print("This benchmark demonstrates the effectiveness of response-time")
    print("padding in reducing timing variance between requests.")
    print()

    # Run benchmark
    results = await run_benchmark(num_requests=50, target_time=2.0)

    # Analyze results
    analyze_results(results)

    # Save results
    save_results(results)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nBenchmark cancelled.")
