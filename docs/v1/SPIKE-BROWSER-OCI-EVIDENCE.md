# SPIKE-BROWSER OCI evidence

Status: native-arm64 decision evidence is being finalized for an exact source
commit. Canonical package status remains `IN_PROGRESS`.

## Evidence contract

The final record must name the exact Git commit, image ID/config, host/runtime,
static and mutation tests, effective Docker inspect values, exact renderer JSON,
negative outer-boundary probes, and invocation-owned cleanup. A pre-commit native
arm64 smoke proved that this boundary can launch without `SYS_ADMIN`, host IPC,
root, an added capability, or a sandbox-disabling launch flag; that provisional
run is not the commit-bound artifact record.

Required commands:

```console
python scripts/verify_browser_containment.py
python scripts/ci/guarded_pytest.py -q tests/architecture/test_browser_containment.py
python scripts/verify_browser_containment_runtime.py --image sha256:<exact-local-id> --revision <40-hex-commit>
```

## Current fail-closed boundary

Only native arm64 Docker Desktop may be recorded by this slice. amd64, native
Linux, rootless/userns-remapped Docker, ECI, gVisor, Kata, a published OCI index,
bit reproducibility, signatures, SBOM/provenance, live navigation, gateway and
connector behavior are untested or out of scope. Shared renderer mount namespace
is an explicit P1 residual before an enabled browser profile.
