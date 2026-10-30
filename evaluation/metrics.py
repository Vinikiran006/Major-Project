# ============================================================
# Adaptive IoT Security Framework
# Stage 3 - Metrics
# ============================================================

import os
import time
import psutil


def measure_time(function, *args):
    """
    Measure execution time of a function.

    Returns:
        result, elapsed_time_ms
    """

    start = time.perf_counter()

    result = function(*args)

    end = time.perf_counter()

    elapsed_time_ms = (end - start) * 1000

    return result, elapsed_time_ms


def get_process_memory_mb():
    """
    Get current Python process memory usage in MB.
    """

    process = psutil.Process(os.getpid())

    memory_bytes = process.memory_info().rss

    return memory_bytes / (1024 * 1024)


def calculate_throughput(data_size_bytes, time_ms):
    """
    Calculate throughput in MB/s.
    """

    if time_ms <= 0:
        return 0

    data_size_mb = data_size_bytes / (1024 * 1024)

    time_seconds = time_ms / 1000

    return data_size_mb / time_seconds