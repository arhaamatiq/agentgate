These three load runs are **invalid** and excluded from RESULTS.md: the host
disk filled up mid-run (121 MB free) and Docker's VM storage returned I/O
errors (Redis went unhealthy). Kept for transparency only. The one useful
signal: inside-gateway decision p99 at 1,000 req/s was 0.87 ms even then.
