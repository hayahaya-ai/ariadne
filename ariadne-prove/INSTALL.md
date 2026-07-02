# Install Ariadne

## From Source

Prerequisites:

- Go 1.26 or newer
- Git
- Make

Build:

```bash
git clone https://github.com/hayahaya-ai/ariadne.git
cd ariadne/ariadne-prove
make build
./bin/ariadne help
```

Install into your path:

```bash
GOBIN="$HOME/.local/bin" go install github.com/hayahaya-ai/ariadne/ariadne-prove/cmd/ariadne@latest
ariadne help
```

## First Run

Assess the current developer machine:

```bash
ariadne self
ariadne self --bundle-dir ariadne-self
ariadne self --format html --out ariadne-self.html
```

Assess a repository or mounted path:

```bash
ariadne assess --path .
ariadne dashboard --path . --out ariadne-dashboard.html
```

Export lower-level deterministic evidence when you need automation inputs:

```bash
ariadne inventory --path . --format json --out inventory.json
ariadne prove --path . --format json --out exposure.json
```

## Endpoint Mode

Endpoint mode inspects known user-level agent configuration locations for the current home directory:

```bash
ariadne self
ariadne self --bundle-dir ariadne-self
ariadne assess --path "$HOME" --mode endpoint
ariadne dashboard --path "$HOME" --mode endpoint --out ariadne-self.html
```

## Multi-Target Scan

Create `targets.txt`:

```text
laptop-a,/mnt/snapshots/laptop-a
laptop-b,/mnt/snapshots/laptop-b
```

Run:

```bash
ariadne scan --targets targets.txt --format json --out scan.json
```

## Exit Codes

- `0`: command completed successfully
- `1`: validation story ran but did not match its oracle
- `2`: CLI usage, input, output, or runtime error
