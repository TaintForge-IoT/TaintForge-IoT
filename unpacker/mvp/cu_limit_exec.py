"""Apply limits to one child without changing the parent."""
import os
import resource
import sys

for kind, ceiling in ((resource.RLIMIT_AS, int(sys.argv[1])),
                      (resource.RLIMIT_FSIZE, int(sys.argv[2])),
                      (resource.RLIMIT_CORE, 0)):
    _, hard = resource.getrlimit(kind)
    if hard != resource.RLIM_INFINITY:
        ceiling = min(ceiling, hard)
    resource.setrlimit(kind, (ceiling, ceiling))
os.execv(sys.argv[3], sys.argv[3:])
