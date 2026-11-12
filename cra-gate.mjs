#!/usr/bin/env node
// cra-gate: a release gate for CI/CD pipelines, backed by the CVD Portal API.
//
// One file, no dependencies, Node 20 or later. It pushes the SBOM and the scan
// findings of a release, asks for a verdict, prints the reason for each check
// and sets the exit code. See README.md.
//
// Exit codes: 0 pass (or a block in warn mode), 1 block, 2 bad input or a
// refused credential, 3 the portal did not answer.

import { readFile, writeFile, appendFile } from "node:fs/promises"
import { basename } from "node:path"
import { pathToFileURL } from "node:url"

export const VERSION = "0.1.0"
export const DEFAULT_API_URL = "https://cvdportal.com"

export const EXIT = { PASS: 0, BLOCK: 1, USAGE: 2, UNREACHABLE: 3 }

/** Printed at the end of every verdict. A pass is not a statement of conformity. */
export const DISCLAIMER =
  "A pass means that the listed checks passed for this release. It is not a statement that the product conforms to the Cyber Resilience Act."

const USAGE = `cra-gate ${VERSION}

Usage
  cra-gate run [options]            push the files that are given, then ask for a verdict
  cra-gate verdict [options]        ask for a verdict and store it
  cra-gate push-sbom <file> [options]
  cra-gate push-sarif <file> [options]

Options
  --product <id>        product id (or CVD_PRODUCT_ID)
  --release <version>   release label, for example 2.4.1
  --released-at <date>  release date, YYYY-MM-DD (SBOM push only)
  --part <name>         SBOM part name, for example firmware (SBOM push only)
  --sbom <file>         with run: a CycloneDX or SPDX JSON SBOM to push first
  --sarif <file>        with run: a SARIF 2.1.0 file to push first. Repeat for more files
  --mode <block|warn>   warn never fails the job. Default block
  --on-error <fail|pass> what to do when the portal does not answer. Default fail
  --json <path>         write the raw verdict to a file
  --api-url <url>       default ${DEFAULT_API_URL} (or CVD_API_URL)
  --version, --help

Environment
  CVD_API_KEY           required. The API key. Never pass it as an option

${DISCLAIMER}
`

export class UsageError extends Error {}
export class UnreachableError extends Error {}

const VALUE_FLAGS = new Set([
  "product", "release", "released-at", "part", "sbom", "sarif", "mode", "on-error", "json", "api-url",
])
const REPEATABLE = new Set(["sarif"])

/** Splits argv into a command, positionals and options. Throws UsageError on an unknown flag. */
export function parseArgs(argv) {
  const out = { command: null, positionals: [], options: {} }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === "--help" || arg === "-h") { out.options.help = true; continue }
    if (arg === "--version") { out.options.version = true; continue }
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=")
      const name = eq === -1 ? arg.slice(2) : arg.slice(2, eq)
      if (!VALUE_FLAGS.has(name)) throw new UsageError(`Unknown option: --${name}`)
      const value = eq === -1 ? argv[++i] : arg.slice(eq + 1)
      if (value === undefined || value === "") throw new UsageError(`Option --${name} needs a value.`)
      if (REPEATABLE.has(name)) (out.options[name] ??= []).push(value)
      else out.options[name] = value
      continue
    }
    if (!out.command) out.command = arg
    else out.positionals.push(arg)
  }
  return out
}

/** Inputs of a GitHub Action step arrive as INPUT_<NAME> variables. An empty one counts as absent. */
function actionInput(env, name) {
  const value = env[`INPUT_${name.toUpperCase()}`]
  return value === undefined || value.trim() === "" ? undefined : value.trim()
}

/** What the CI system says about this run. Every value is optional. */
export function detectCi(env) {
  if (env.GITHUB_ACTIONS === "true") {
    const url =
      env.GITHUB_SERVER_URL && env.GITHUB_REPOSITORY && env.GITHUB_RUN_ID
        ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`
        : undefined
    return { source: "github-actions", commitSha: env.GITHUB_SHA, pipelineUrl: url, repo: env.GITHUB_REPOSITORY }
  }
  if (env.GITLAB_CI === "true") {
    return { source: "gitlab-ci", commitSha: env.CI_COMMIT_SHA, pipelineUrl: env.CI_PIPELINE_URL, repo: env.CI_PROJECT_PATH }
  }
  if (env.JENKINS_URL) {
    return { source: "jenkins", commitSha: env.GIT_COMMIT, pipelineUrl: env.BUILD_URL, repo: undefined }
  }
  if (env.TF_BUILD) {
    return { source: "azure-devops", commitSha: env.BUILD_SOURCEVERSION, pipelineUrl: undefined, repo: env.BUILD_REPOSITORY_NAME }
  }
  return { source: "other", commitSha: undefined, pipelineUrl: undefined, repo: undefined }
}

function isLoopback(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]"
}

/** The base URL of the API. https only, except a loopback address for local tests. */
export function resolveApiUrl(raw) {
  let url
  try {
    url = new URL(raw)
  } catch {
    throw new UsageError(`The API URL is not a URL: ${raw}`)
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback(url.hostname))) {
    throw new UsageError("The API URL must use https.")
  }
  if (url.username || url.password) throw new UsageError("The API URL must not hold credentials.")
  return url.origin
}

/** Merges options, Action inputs and environment variables into one config. Options win. */
export function resolveConfig(options, env) {
  const pick = (flag, input, envName) => options[flag] ?? actionInput(env, input) ?? (envName ? env[envName] : undefined)

  const apiKey = actionInput(env, "api-key") ?? env.CVD_API_KEY
  if (!apiKey) throw new UsageError("Set the API key in the environment variable CVD_API_KEY.")

  const productId = pick("product", "product-id", "CVD_PRODUCT_ID")
  if (!productId) throw new UsageError("Give the product id with --product or CVD_PRODUCT_ID.")

  const mode = pick("mode", "mode") ?? "block"
  if (mode !== "block" && mode !== "warn") throw new UsageError("--mode must be block or warn.")
  const onError = pick("on-error", "on-error") ?? "fail"
  if (onError !== "fail" && onError !== "pass") throw new UsageError("--on-error must be fail or pass.")

  const sarifInput = actionInput(env, "sarif")
  const sarif = options.sarif ?? (sarifInput ? sarifInput.split(/\r?\n/).map((s) => s.trim()).filter(Boolean) : [])

  return {
    apiKey,
    apiUrl: resolveApiUrl(pick("api-url", "api-url", "CVD_API_URL") ?? DEFAULT_API_URL),
    productId,
    release: pick("release", "release"),
    releasedAt: pick("released-at", "released-at"),
    part: pick("part", "part"),
    sbom: pick("sbom", "sbom"),
    sarif,
    mode,
    onError,
    json: pick("json", "json"),
    ci: detectCi(env),
  }
}

/**
 * One request to the API. Returns { status, body }. A network failure, a
 * timeout or a 5xx answer throws UnreachableError, so the caller can apply
 * --on-error. The key goes in the Authorization header and nowhere else.
 */
export async function request(config, method, path, { body, query, timeoutMs = 60_000, fetchImpl = fetch } = {}) {
  const url = new URL(path, config.apiUrl)
  for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined && v !== null) url.searchParams.set(k, v)
  let res
  try {
    res = await fetchImpl(url, {
      method,
      headers: {
        Authorization: `Bearer ${config.apiKey}`,
        "Content-Type": "application/json",
        "User-Agent": `cra-gate/${VERSION}`,
      },
      body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "error",
    })
  } catch (err) {
    throw new UnreachableError(`The portal did not answer: ${err?.name === "TimeoutError" ? "timeout" : err?.cause?.code ?? err?.message ?? "network error"}`)
  }
  if (res.status >= 500) throw new UnreachableError(`The portal answered ${res.status}.`)
  let parsed = null
  try {
    parsed = await res.json()
  } catch {
    parsed = null
  }
  return { status: res.status, body: parsed }
}

function refusal(what, res) {
  const reason = typeof res.body?.error === "string" ? res.body.error : `HTTP ${res.status}`
  return new UsageError(`${what} was refused (${res.status}): ${reason}`)
}

async function readText(path, what) {
  try {
    return await readFile(path, "utf8")
  } catch {
    throw new UsageError(`Cannot read the ${what} file: ${path}`)
  }
}

export async function pushSbom(config, file, deps = {}) {
  const content = await readText(file, "SBOM")
  const res = await request(config, "POST", "/api/v1/sbom", {
    body: {
      filename: basename(file),
      content,
      productId: config.productId,
      ...(config.part ? { part: config.part } : {}),
      ...(config.release ? { releaseVersion: config.release } : {}),
      ...(config.releasedAt ? { releasedAt: config.releasedAt } : {}),
    },
    // The push scans the components before it returns.
    timeoutMs: 180_000,
    ...deps,
  })
  if (res.status !== 200) throw refusal("The SBOM push", res)
  return res.body
}

export async function pushSarif(config, file, deps = {}) {
  const content = await readText(file, "SARIF")
  try {
    JSON.parse(content)
  } catch {
    throw new UsageError(`The SARIF file is not JSON: ${file}`)
  }
  // The findings API knows two pipeline sources. Every other one is "manual".
  const source = config.ci.source === "github-actions" || config.ci.source === "gitlab-ci" ? config.ci.source : "manual"
  const res = await request(config, "POST", "/api/v1/scan/sarif", {
    body: content,
    query: { source, repo: config.ci.repo, productId: config.productId },
    timeoutMs: 120_000,
    ...deps,
  })
  if (res.status !== 200) throw refusal("The SARIF push", res)
  return res.body
}

/** Asks for a verdict and stores it. Returns the verdict body for 201 and 422. */
export async function requestVerdict(config, deps = {}) {
  const res = await request(config, "POST", "/api/v1/compliance/release-gate/runs", {
    body: {
      productId: config.productId,
      mode: config.mode,
      source: config.ci.source,
      strict: true,
      ...(config.release ? { releaseVersion: config.release } : {}),
      ...(config.ci.commitSha && /^[0-9a-f]{7,64}$/i.test(config.ci.commitSha) ? { commitSha: config.ci.commitSha } : {}),
      ...(config.ci.pipelineUrl?.startsWith("https://") ? { pipelineUrl: config.ci.pipelineUrl } : {}),
    },
    ...deps,
  })
  if (res.status !== 201 && res.status !== 422) throw refusal("The verdict request", res)
  if (!res.body || (res.body.status !== "PASS" && res.body.status !== "BLOCK") || !Array.isArray(res.body.checks)) {
    throw new UnreachableError("The portal gave an answer that is not a verdict.")
  }
  return res.body
}

function checkState(check) {
  if (check.passed) return "PASS"
  return check.enforced === false ? "OFF" : "FAIL"
}

/** The exit code for a verdict. A block in warn mode does not fail the job. */
export function exitCodeFor(verdict, mode) {
  return verdict.status === "BLOCK" && mode === "block" ? EXIT.BLOCK : EXIT.PASS
}

/** Plain text for the log. The approver's email is never printed. */
export function renderText(verdict, config) {
  const lines = []
  const label = config.release ? ` for release ${config.release}` : ""
  lines.push(`Release gate${label}: ${verdict.status}${verdict.status === "BLOCK" && config.mode === "warn" ? " (warn mode, the job does not fail)" : ""}`)
  lines.push("")
  for (const c of verdict.checks) {
    lines.push(`  [${checkState(c).padEnd(4)}] ${c.label}`)
    lines.push(`         ${c.detail}`)
  }
  lines.push("")
  if (verdict.runId) lines.push(`Stored as run ${verdict.runId}.`)
  lines.push(`Product: ${config.apiUrl}/products/${encodeURIComponent(config.productId)}`)
  lines.push("")
  lines.push(DISCLAIMER)
  return lines.join("\n")
}

function cell(text) {
  return String(text).replace(/\|/g, "\\|").replace(/\r?\n/g, " ")
}

/** Markdown for the job summary of GitHub Actions. */
export function renderMarkdown(verdict, config) {
  const label = config.release ? ` for release ${cell(config.release)}` : ""
  const rows = verdict.checks.map((c) => `| ${checkState(c)} | ${cell(c.label)} | ${cell(c.detail)} |`)
  return [
    `### Release gate${label}: ${verdict.status}`,
    "",
    "| Result | Check | Detail |",
    "|---|---|---|",
    ...rows,
    "",
    verdict.runId ? `Stored as run \`${cell(verdict.runId)}\`.` : "",
    "",
    `_${DISCLAIMER}_`,
    "",
  ].join("\n")
}

/** The verdict as written to --json. The approver block is left out. */
export function publicVerdict(verdict) {
  const { signature: _signature, ...rest } = verdict
  return rest
}

/** One log line for an SBOM push. It says so when the vulnerability check did not run. */
export function sbomLine(r) {
  const base = `SBOM pushed: ${r?.count ?? "?"} components.`
  if (r?.refreshError) return `${base} The vulnerability check failed: ${r.refreshError}`
  if (r && r.refresh === null) return `${base} The vulnerability check did not run for this push.`
  return base
}

async function runVerdict(config, io, deps) {
  const verdict = await requestVerdict(config, deps)
  io.out(renderText(verdict, config))
  if (io.env.GITHUB_STEP_SUMMARY) {
    await appendFile(io.env.GITHUB_STEP_SUMMARY, renderMarkdown(verdict, config) + "\n").catch(() => undefined)
  }
  if (config.json) await writeFile(config.json, JSON.stringify(publicVerdict(verdict), null, 2) + "\n")
  return exitCodeFor(verdict, config.mode)
}

/**
 * Runs the CLI. `io` carries the environment and the two output functions, so
 * a test can run it without a process. Returns the exit code.
 */
export async function main(argv, io = { env: process.env, out: console.log, err: console.error }, deps = {}) {
  let config = null
  try {
    const args = parseArgs(argv)
    if (args.options.version) { io.out(VERSION); return EXIT.PASS }
    // A GitHub Action step passes no arguments. It means "run".
    const command = args.command ?? (io.env.GITHUB_ACTIONS === "true" ? "run" : null)
    if (args.options.help || !command) { io.out(USAGE); return args.options.help ? EXIT.PASS : EXIT.USAGE }

    config = resolveConfig(args.options, io.env)

    if (command === "push-sbom" || command === "push-sarif") {
      const file = args.positionals[0]
      if (!file) throw new UsageError(`Give the file: cra-gate ${command} <file>`)
      if (command === "push-sbom") {
        io.out(sbomLine(await pushSbom(config, file, deps)))
      } else {
        const r = await pushSarif(config, file, deps)
        io.out(`SARIF pushed: ${r?.ingested ?? 0} findings, ${r?.created ?? 0} new.`)
      }
      return EXIT.PASS
    }

    if (command === "verdict") return await runVerdict(config, io, deps)

    if (command === "run") {
      if (config.sbom) {
        io.out(sbomLine(await pushSbom(config, config.sbom, deps)))
      }
      for (const file of config.sarif) {
        const r = await pushSarif(config, file, deps)
        io.out(`SARIF pushed (${basename(file)}): ${r?.ingested ?? 0} findings, ${r?.created ?? 0} new.`)
      }
      return await runVerdict(config, io, deps)
    }

    throw new UsageError(`Unknown command: ${command}`)
  } catch (err) {
    if (err instanceof UsageError) {
      io.err(`cra-gate: ${err.message}`)
      return EXIT.USAGE
    }
    if (err instanceof UnreachableError) {
      if (config?.onError === "pass") {
        io.err(`cra-gate: ${err.message} No verdict exists for this run. The job continues because --on-error is pass.`)
        return EXIT.PASS
      }
      io.err(`cra-gate: ${err.message} No verdict exists for this run.`)
      return EXIT.UNREACHABLE
    }
    io.err(`cra-gate: ${err?.message ?? err}`)
    return EXIT.USAGE
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code })
}
