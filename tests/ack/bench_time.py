import sys, time
t0 = None
for line in sys.stdin:
    now = time.time()
    if t0 is None:
        t0 = now
    print("%8.1f ms  %s" % ((now - t0) * 1000.0, line.rstrip()))
    sys.stdout.flush()
