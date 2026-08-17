# BUG_REPRO

The following failures were observed while validating the initial project state.
Each section records what failed, how to reproduce it, and the complete command output.
They are preserved intentionally; only failing build gates are omitted from the generated Dockerfile.

## Failure 1: Go test (.)

- Observed problem: `Go test (.)` failed in the initial project state.
- Working directory: `.`
- Command: `cd /app && GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -count=1 ./...`
- Exit status: `1`

```text
?   	scanvault/cmd/scanvault	[no test files]
ok  	scanvault/internal/audit	0.013s
--- FAIL: TestBatchImportAuditTrail (0.02s)
    batch_test.go:40: batch import failed: import line 2: record resource limit reached results=[{Line:1 Serial:SC-400 Status:accepted Message:secret recovered Envelope:envelope-0002} {Line:2 Serial:SC-400 Status:failed Message:record resource limit reached Envelope:}] batch={ID:/tmp/TestBatchImportAuditTrail3905984615/001/batch.db|devices.csv Source:devices.csv Operator:alice State:processing Total:3 Succeeded:1 Failed:1 CreatedAt:fixed-time}
FAIL
FAIL	scanvault/internal/batch	0.026s
ok  	scanvault/internal/crypto	0.002s
ok  	scanvault/internal/model	0.001s
ok  	scanvault/internal/report	0.002s
ok  	scanvault/internal/service	0.032s
ok  	scanvault/internal/store	0.018s
FAIL
```

## Architecture reproduction

### linux/amd64
- Go toolchain version: exit `0`
- Node.js version: exit `0`
- Go build (.): exit `0`
- Go test (.): exit `1`
- Go run smoke (cmd/scanvault): exit `0`
- Frontend build (web): exit `0`
### linux/arm64
- Go toolchain version: exit `0`
- Node.js version: exit `0`
- Go build (.): exit `0`
- Go test (.): exit `1`
- Go run smoke (cmd/scanvault): exit `0`
- Frontend build (web): exit `0`
