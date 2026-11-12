// Run with: node --test integrations/cra-gate/test
import { test, describe, before, after, beforeEach } from "node:test"
import assert from "node:assert/strict"
import { createServer } from "node:http"
import { mkdtemp, writeFile, readFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  DISCLAIMER,
  EXIT,
  UsageError,
  detectCi,
  exitCodeFor,
  main,
  parseArgs,
  publicVerdict,
  renderMarkdown,
  renderText,
  resolveApiUrl,
  resolveConfig,
  sbomLine,
} from "../cra-gate.mjs"

const KEY = "test-key-not-a-secret" // gitleaks:allow

const check = (id, passed, extra = {}) => ({ id, label: `Label ${id}`, passed, detail: `Detail ${id}`, enforced: true, ...extra })
const verdict = (status, checks) => ({
  runId: "run_1",
  createdAt: "2026-11-12T10:00:00.000Z",
  status,
  passedChecks: checks.filter((c) => c.passed).length,
  totalChecks: checks.length,
  checks,
  blockingReasons: checks.filter((c) => !c.passed && c.enforced).map((c) => c.detail),
  disabledChecks: [],
  policyVersion: 2,
  contentHash: "a".repeat(64),
  signature: { decidedByEmail: "approver@example.com", decidedAt: "2026-11-01T00:00:00.000Z", meaning: null, meaningLabel: null, verifiedMethod: null },
})
const PASS = verdict("PASS", [check("sbomScanned", true), check("noKnownExploitedVulnerabilities", true)])
const BLOCK = verdict("BLOCK", [check("sbomScanned", true), check("noOpenCriticalHighVulnerabilities", false)])

let server
let base
let requests
let reply

before(async () => {
  server = createServer((req, res) => {
    let body = ""
    req.on("data", (c) => (body += c))
    req.on("end", () => {
      requests.push({ method: req.method, url: req.url, headers: req.headers, body })
      const r = reply(req, body)
      if (r === "hang") return
      res.writeHead(r.status, { "Content-Type": "application/json" })
      res.end(typeof r.body === "string" ? r.body : JSON.stringify(r.body))
    })
  })
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve))
  base = `http://127.0.0.1:${server.address().port}`
})
after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve) }))
beforeEach(() => {
  requests = []
  reply = () => ({ status: 201, body: PASS })
})

function io(env = {}) {
  const out = []
  const err = []
  return {
    env: { CVD_API_KEY: KEY, CVD_PRODUCT_ID: "prod_1", CVD_API_URL: base, ...env },
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    text: () => out.join("\n"),
    errors: () => err.join("\n"),
  }
}

describe("parseArgs", () => {
  test("reads a command, positionals and options", () => {
    const a = parseArgs(["push-sbom", "sbom.json", "--product", "p1", "--release=2.4.1"])
    assert.equal(a.command, "push-sbom")
    assert.deepEqual(a.positionals, ["sbom.json"])
    assert.equal(a.options.product, "p1")
    assert.equal(a.options.release, "2.4.1")
  })
  test("collects a repeated --sarif", () => {
    assert.deepEqual(parseArgs(["run", "--sarif", "a.sarif", "--sarif", "b.sarif"]).options.sarif, ["a.sarif", "b.sarif"])
  })
  test("refuses an unknown option and a missing value", () => {
    assert.throws(() => parseArgs(["run", "--api-key", "x"]), UsageError)
    assert.throws(() => parseArgs(["run", "--product"]), UsageError)
  })
})

describe("resolveApiUrl", () => {
  test("accepts https and loopback http only", () => {
    assert.equal(resolveApiUrl("https://cvdportal.com/"), "https://cvdportal.com")
    assert.equal(resolveApiUrl("http://127.0.0.1:8080"), "http://127.0.0.1:8080")
    assert.throws(() => resolveApiUrl("http://example.com"), UsageError)
    assert.throws(() => resolveApiUrl("https://user:pw@example.com"), UsageError)
    assert.throws(() => resolveApiUrl("not a url"), UsageError)
  })
})

describe("resolveConfig", () => {
  test("needs a key and a product", () => {
    assert.throws(() => resolveConfig({}, { CVD_PRODUCT_ID: "p" }), /CVD_API_KEY/)
    assert.throws(() => resolveConfig({}, { CVD_API_KEY: KEY }), /product id/)
  })
  test("reads GitHub Action inputs, and an option wins over an input", () => {
    const c = resolveConfig(
      { release: "9.9.9" },
      { "INPUT_API-KEY": KEY, "INPUT_PRODUCT-ID": "p_in", INPUT_RELEASE: "1.0.0", INPUT_MODE: "warn", INPUT_SARIF: "a.sarif\n b.sarif \n", INPUT_SBOM: "" },
    )
    assert.equal(c.productId, "p_in")
    assert.equal(c.release, "9.9.9")
    assert.equal(c.mode, "warn")
    assert.deepEqual(c.sarif, ["a.sarif", "b.sarif"])
    assert.equal(c.sbom, undefined)
    assert.equal(c.apiUrl, "https://cvdportal.com")
  })
  test("refuses an unknown mode", () => {
    assert.throws(() => resolveConfig({ mode: "off" }, { CVD_API_KEY: KEY, CVD_PRODUCT_ID: "p" }), UsageError)
  })
})

describe("detectCi", () => {
  test("GitHub Actions", () => {
    const ci = detectCi({ GITHUB_ACTIONS: "true", GITHUB_SHA: "abc1234", GITHUB_SERVER_URL: "https://github.com", GITHUB_REPOSITORY: "acme/app", GITHUB_RUN_ID: "7" })
    assert.deepEqual(ci, { source: "github-actions", commitSha: "abc1234", pipelineUrl: "https://github.com/acme/app/actions/runs/7", repo: "acme/app" })
  })
  test("GitLab, Jenkins, Azure DevOps and none", () => {
    assert.equal(detectCi({ GITLAB_CI: "true" }).source, "gitlab-ci")
    assert.equal(detectCi({ JENKINS_URL: "https://ci" }).source, "jenkins")
    assert.equal(detectCi({ TF_BUILD: "True" }).source, "azure-devops")
    assert.equal(detectCi({}).source, "other")
  })
})

describe("render", () => {
  const config = { release: "2.4.1", mode: "block", apiUrl: "https://cvdportal.com", productId: "prod_1" }
  test("text names each check and ends with the disclaimer", () => {
    const text = renderText(BLOCK, config)
    assert.match(text, /Release gate for release 2\.4\.1: BLOCK/)
    assert.match(text, /\[FAIL\] Label noOpenCriticalHighVulnerabilities/)
    assert.match(text, /\[PASS\] Label sbomScanned/)
    assert.ok(text.endsWith(DISCLAIMER))
  })
  test("a check that the workspace switched off reads OFF", () => {
    const v = verdict("PASS", [check("sbomScanned", false, { enforced: false })])
    assert.match(renderText(v, config), /\[OFF \]/)
    assert.match(renderMarkdown(v, config), /\| OFF \|/)
  })
  test("never prints the approver email", () => {
    assert.doesNotMatch(renderText(PASS, config), /approver@example\.com/)
    assert.doesNotMatch(renderMarkdown(PASS, config), /approver@example\.com/)
    assert.equal("signature" in publicVerdict(PASS), false)
  })
  test("markdown escapes a pipe in a detail", () => {
    const v = verdict("PASS", [check("sbomScanned", true, { detail: "a | b" })])
    assert.match(renderMarkdown(v, config), /a \\\| b/)
  })
  test("exit code", () => {
    assert.equal(exitCodeFor(PASS, "block"), EXIT.PASS)
    assert.equal(exitCodeFor(BLOCK, "block"), EXIT.BLOCK)
    assert.equal(exitCodeFor(BLOCK, "warn"), EXIT.PASS)
  })
  test("SBOM line says when the vulnerability check did not run", () => {
    assert.equal(sbomLine({ count: 12, refresh: { ok: true } }), "SBOM pushed: 12 components.")
    assert.match(sbomLine({ count: 12, refresh: null }), /did not run/)
    assert.match(sbomLine({ count: 12, refreshError: "OSV down" }), /failed: OSV down/)
  })
})

describe("main against a stub portal", () => {
  test("verdict PASS exits 0 and sends the key in the header only", async () => {
    const i = io({ GITHUB_ACTIONS: "true", GITHUB_SHA: "ABCDEF1234", GITHUB_SERVER_URL: "https://github.com", GITHUB_REPOSITORY: "acme/app", GITHUB_RUN_ID: "5" })
    const code = await main(["verdict", "--release", "2.4.1"], i)
    assert.equal(code, EXIT.PASS)
    assert.equal(requests.length, 1)
    const r = requests[0]
    assert.equal(r.method, "POST")
    assert.equal(r.url, "/api/v1/compliance/release-gate/runs")
    assert.equal(r.headers.authorization, `Bearer ${KEY}`)
    assert.doesNotMatch(r.url + r.body, new RegExp(KEY))
    assert.deepEqual(JSON.parse(r.body), {
      productId: "prod_1",
      mode: "block",
      source: "github-actions",
      strict: true,
      releaseVersion: "2.4.1",
      commitSha: "ABCDEF1234",
      pipelineUrl: "https://github.com/acme/app/actions/runs/5",
    })
    assert.match(i.text(), /Stored as run run_1/)
    assert.doesNotMatch(i.text() + i.errors(), new RegExp(KEY))
  })

  test("verdict BLOCK (422) exits 1, and 0 in warn mode", async () => {
    reply = () => ({ status: 422, body: BLOCK })
    assert.equal(await main(["verdict"], io()), EXIT.BLOCK)
    const warn = io()
    assert.equal(await main(["verdict", "--mode", "warn"], warn), EXIT.PASS)
    assert.match(warn.text(), /warn mode/)
    assert.equal(JSON.parse(requests[1].body).mode, "warn")
  })

  test("a refused credential exits 2 with the reason", async () => {
    reply = () => ({ status: 403, body: { error: "The release gate requires a Compliance subscription or above." } })
    const i = io()
    assert.equal(await main(["verdict"], i), EXIT.USAGE)
    assert.match(i.errors(), /refused \(403\): The release gate requires a Compliance subscription/)
  })

  test("a 5xx exits 3, or 0 with --on-error pass, and says that no verdict exists", async () => {
    reply = () => ({ status: 503, body: {} })
    const fail = io()
    assert.equal(await main(["verdict"], fail), EXIT.UNREACHABLE)
    assert.match(fail.errors(), /No verdict exists/)
    const pass = io()
    assert.equal(await main(["verdict", "--on-error", "pass"], pass), EXIT.PASS)
    assert.match(pass.errors(), /No verdict exists/)
  })

  test("a 201 that is not a verdict exits 3", async () => {
    reply = () => ({ status: 201, body: { ok: true } })
    assert.equal(await main(["verdict"], io()), EXIT.UNREACHABLE)
  })

  test("an unreachable host exits 3", async () => {
    const i = io({ CVD_API_URL: "http://127.0.0.1:1" })
    assert.equal(await main(["verdict"], i), EXIT.UNREACHABLE)
  })

  test("run pushes the SBOM and SARIF first, then asks for the verdict, and writes --json", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cra-gate-"))
    const sbom = join(dir, "sbom.cdx.json")
    const sarif = join(dir, "scan.sarif")
    const json = join(dir, "verdict.json")
    const summary = join(dir, "summary.md")
    await writeFile(sbom, JSON.stringify({ bomFormat: "CycloneDX", components: [] }))
    await writeFile(sarif, JSON.stringify({ version: "2.1.0", runs: [] }))
    await writeFile(summary, "")
    reply = (req) => {
      if (req.url.startsWith("/api/v1/sbom")) return { status: 200, body: { success: true, count: 3, refresh: {} } }
      if (req.url.startsWith("/api/v1/scan/sarif")) return { status: 200, body: { ingested: 2, created: 1 } }
      return { status: 201, body: PASS }
    }
    const i = io({ GITLAB_CI: "true", CI_PROJECT_PATH: "acme/app", GITHUB_STEP_SUMMARY: summary })
    const code = await main(["run", "--sbom", sbom, "--sarif", sarif, "--release", "1.0.0", "--part", "firmware", "--json", json], i)
    assert.equal(code, EXIT.PASS)
    assert.deepEqual(requests.map((r) => r.url.split("?")[0]), ["/api/v1/sbom", "/api/v1/scan/sarif", "/api/v1/compliance/release-gate/runs"])
    const pushed = JSON.parse(requests[0].body)
    assert.equal(pushed.filename, "sbom.cdx.json")
    assert.equal(pushed.productId, "prod_1")
    assert.equal(pushed.part, "firmware")
    assert.equal(pushed.releaseVersion, "1.0.0")
    const q = new URL(requests[1].url, base).searchParams
    assert.equal(q.get("source"), "gitlab-ci")
    assert.equal(q.get("repo"), "acme/app")
    assert.equal(q.get("productId"), "prod_1")
    const written = JSON.parse(await readFile(json, "utf8"))
    assert.equal(written.status, "PASS")
    assert.equal("signature" in written, false)
    assert.match(await readFile(summary, "utf8"), /### Release gate for release 1\.0\.0: PASS/)
  })

  test("run stops with exit 2 when a push is refused, and asks for no verdict", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cra-gate-"))
    const sbom = join(dir, "sbom.json")
    await writeFile(sbom, "{}")
    reply = () => ({ status: 403, body: { error: "SBOM connectivity is an Enterprise feature" } })
    const i = io()
    assert.equal(await main(["run", "--sbom", sbom], i), EXIT.USAGE)
    assert.equal(requests.length, 1)
    assert.match(i.errors(), /The SBOM push was refused \(403\)/)
  })

  test("a missing file, a missing key and an unknown command exit 2 with no request", async () => {
    assert.equal(await main(["push-sbom", "/nonexistent/sbom.json"], io()), EXIT.USAGE)
    assert.equal(await main(["verdict"], io({ CVD_API_KEY: "" })), EXIT.USAGE)
    assert.equal(await main(["frobnicate"], io()), EXIT.USAGE)
    assert.equal(requests.length, 0)
  })

  test("a GitHub Action step with no arguments means run", async () => {
    const i = io({ GITHUB_ACTIONS: "true", "INPUT_API-KEY": KEY, "INPUT_PRODUCT-ID": "prod_9", "INPUT_API-URL": base, CVD_API_KEY: "", CVD_PRODUCT_ID: "" })
    assert.equal(await main([], i), EXIT.PASS)
    assert.equal(JSON.parse(requests[0].body).productId, "prod_9")
  })

  test("--help exits 0 and no arguments exit 2", async () => {
    assert.equal(await main(["--help"], io()), EXIT.PASS)
    assert.equal(await main([], io()), EXIT.USAGE)
  })
})
