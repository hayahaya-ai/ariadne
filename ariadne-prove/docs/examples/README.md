# Examples

Run from the repository root:

```bash
ariadne inventory --path testdata/realpath/messy-ai-surfaces
ariadne prove --path testdata/realpath/combined-risk
ariadne scan --targets testdata/realpath/targets.txt
```

Expected high-level scan result:

- `combined-risk`: exposed paths for secret boundary access, mutable tool launch, and data egress chain
- `safe-controls`: protected paths where controls break the modeled paths
- `repo-only-risk`: inconclusive because runtime authority is missing
