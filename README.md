# cra-gate

A release gate for CI/CD pipelines. It asks [CVD Portal](https://cvdportal.com) whether a product release passes six checks, prints the reason for each check, and fails the job on a block. Each verdict is stored in the workspace as a record of the release.

A pass means that the listed checks passed for this release. It is not a statement that the product conforms to the Cyber Resilience Act.

Porta Regulus B.V. publishes this tool and sells CVD Portal, the service it calls. The tool is free and MIT licensed. The service needs a paid plan.

## What it checks

| Check | Passes when |
|---|---|
| SBOM scan | The current SBOM has components and a complete vulnerability scan |
| Critical and high vulnerabilities | The scan has no open critical or high finding without a VEX statement |
| Component support | No component loses supplier support before the product support period ends |
| Technical file approval | The approval is current, when the workspace requires one |
| Pipeline findings | No SARIF or FOSSA finding is open at critical or high severity |
| Known exploited vulnerabilities | No open finding is on the list of known exploited vulnerabilities |

The workspace decides which checks block. The pipeline file cannot switch a check off, so a pull request cannot weaken the gate. A check that the workspace switched off prints as `OFF`.

The tool is not a scanner. Run your own scanner and SBOM generator, and give their output to the gate.

## What you need

- A CVD Portal workspace on the Compliance plan or higher, for the verdict.
- The Enterprise plan to push an SBOM, SARIF or JUnit file from the pipeline. On Compliance, upload the SBOM in the dashboard.
- An API key from Settings, then API Keys, with the scope `gate:write`. Add `sbom:write` and `sarif:write` ("Push pipeline results", for SARIF and JUnit) if the pipeline pushes files. An administrator must create a key that pushes an SBOM.
- The product id, from the product page.
- Node 20 or later.

## GitHub Actions

```yaml
- uses: porta-regulus/cra-gate@<commit sha>
  with:
    api-key: ${{ secrets.CVD_API_KEY }}
    product-id: ${{ vars.CVD_PRODUCT_ID }}
    release: ${{ github.ref_name }}
    sbom: sbom.cdx.json
    sarif: |
      results/semgrep.sarif
      results/trivy.sarif
    junit: |
      reports/junit.xml
    files: |
      dist/firmware.bin
```

`files` records the SHA-256 of each shipped file and the commit of the run on the release, with the SBOM push. Both are write-once: a later run with another hash for the same file name, or from another commit, is refused. So give `files` only for a real release label, for example a tag.

Pin the action by commit SHA. The step writes the checks to the job summary.

## Any other runner

The CLI is one file with no dependencies. Download it at a fixed commit and run it with Node 20 or later.

```bash
curl -fsSLO https://raw.githubusercontent.com/porta-regulus/cra-gate/<commit sha>/cra-gate.mjs
node cra-gate.mjs run --sbom sbom.cdx.json --release 2.4.1
```

This works in Jenkins, Azure DevOps, GitLab CI and any runner with Node. A Docker image and a GitLab CI/CD component are not released yet. The `Dockerfile` and `templates/` in this repository are for those future releases.

## Commands

| Command | What it does |
|---|---|
| `run` | Pushes the files given with `--sbom`, `--sarif` and `--junit`, then asks for a verdict |
| `verdict` | Asks for a verdict and stores it |
| `push-sbom <file>` | Pushes a CycloneDX or SPDX JSON SBOM |
| `push-sarif <file>` | Pushes a SARIF 2.1.0 file |
| `push-junit <file>` | Pushes a JUnit XML test report |

| Option | Meaning |
|---|---|
| `--product <id>` | The product id. Also `CVD_PRODUCT_ID` |
| `--release <version>` | The release label |
| `--released-at <date>` | The release date, `YYYY-MM-DD`, for an SBOM push |
| `--part <name>` | The SBOM part, for example `firmware`, for an SBOM push |
| `--junit <file>` | With `run`, a JUnit XML report to push. Repeat for more files |
| `--file <path>` | A shipped file. Its SHA-256 and the commit go with the SBOM push, so it needs `--sbom` and `--release`. Repeat for more files |
| `--mode <block\|warn>` | `warn` never fails the job. The default is `block` |
| `--on-error <fail\|pass>` | What to do when the service does not answer. The default is `fail` |
| `--json <path>` | Writes the verdict to a file |
| `--api-url <url>` | The base URL. Also `CVD_API_URL` |

The API key comes from the environment variable `CVD_API_KEY` only. No option takes it, so it cannot appear in a process list or a shell history.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Pass, or a block in `warn` mode |
| 1 | Block |
| 2 | Bad input, or the service refused the key, the scope or the plan |
| 3 | The service did not answer. No verdict exists for this run |

With `--on-error pass`, code 3 becomes 0, and the log says that no verdict exists.

## What it sends

- To the API URL only, over https. It follows no redirect.
- The SBOM, SARIF and JUnit files that you name.
- For each `--file`, the file name and its SHA-256, never the file itself.
- The product id, the release label, the commit SHA, the URL of the pipeline run, and the name of the CI system.

It prints no approver name or email. The file from `--json` leaves the approval block out.

## The release label

The checks read the current SBOM of the product at the time of the run. Push the SBOM of the release first, which `run` does when you give `--sbom`. The label does not select the archived SBOM of an older release.

## Development

```bash
node --test test/cra-gate.test.mjs
```

The tests run the CLI against a local stub server. The tool has no dependencies.
