# P2.1 external-lab admission

Admission is intentionally split into two gates:

1. `admitted=true` means the pinned source, license, reset model and requested
   runtime policy passed static review.
2. `runtime_ready=true` is produced only during acquisition after the exact
   archive hash and the locally available image digest have both been checked.

An admitted source-build record whose image is marked `BUILD_REQUIRED` is not
allowed to enter the isolated runtime until its local image has been built and
materialized to an immutable `sha256:` digest. This prevents an admission record
from becoming an implicit floating-image exception.

The admission records contain no challenge names, solutions, flags or per-case
ground truth. Individual oracle data remains outside agent input and outside CI
artifacts.
