import { spawn } from "node:child_process";
import { access, cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright-core";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

const args = new Map();
for (let index = 2; index < process.argv.length; index += 1) {
  const current = process.argv[index];
  if (!current.startsWith("--")) continue;
  const next = process.argv[index + 1];
  if (!next || next.startsWith("--")) {
    args.set(current, "true");
    continue;
  }
  args.set(current, next);
  index += 1;
}

const host = args.get("--host") ?? "127.0.0.1";
const port = Number.parseInt(args.get("--port") ?? "4176", 10);
const outputDir = path.resolve(
  repoRoot,
  args.get("--output-dir") ?? "docs/screenshots"
);
const mirrorDir = args.get("--mirror-dir")
  ? path.resolve(repoRoot, args.get("--mirror-dir"))
  : null;

const screenshotPlan = [
  {
    key: "env",
    button: "ENV",
    stillFile: "pentect-env.png",
    animationFile: "pentect-env.gif",
  },
  {
    key: "nmap",
    button: "NMAP",
    stillFile: "pentect-nmap.png",
    animationFile: "pentect-nmap.gif",
  },
  {
    key: "har",
    button: "HAR",
    stillFile: "pentect-har.png",
    animationFile: "pentect-har.gif",
  },
];

const chromeCandidates = [
  process.env.CHROME_PATH,
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
].filter(Boolean);

async function fileExists(targetPath) {
  try {
    await access(targetPath);
    return true;
  } catch {
    return false;
  }
}

async function resolveChromePath() {
  for (const candidate of chromeCandidates) {
    if (await fileExists(candidate)) {
      return candidate;
    }
  }
  throw new Error(
    "Chrome executable not found. Set CHROME_PATH or install google-chrome."
  );
}

async function waitForServer(url, timeoutMs = 20000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // retry
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Timed out waiting for dev server: ${url}`);
}

async function waitForMaskingReady(page, timeoutMs = 10000) {
  await page.waitForFunction(
    () => document.documentElement.dataset.pentectReady === "true",
    { timeout: timeoutMs }
  );
}

async function waitForMaskingStart(page, timeoutMs = 1500) {
  await page
    .waitForFunction(
      () => document.documentElement.dataset.pentectReady !== "true",
      { timeout: timeoutMs }
    )
    .catch(() => undefined);
}

function runCommand(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: repoRoot,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stderr = "";

    child.stdout.on("data", (chunk) => process.stdout.write(chunk));
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
      process.stderr.write(chunk);
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code === 0) {
        resolve(undefined);
        return;
      }

      reject(new Error(`${command} exited with code ${code}\n${stderr}`));
    });
  });
}

function startDevServer() {
  const viteBin = path.join(repoRoot, "node_modules", ".bin", "vite");
  const child = spawn(viteBin, ["--host", host, "--port", String(port)], {
    cwd: repoRoot,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  child.stdout.on("data", (chunk) => process.stdout.write(chunk));
  child.stderr.on("data", (chunk) => process.stderr.write(chunk));
  return child;
}

async function stopDevServer(child) {
  if (child.exitCode !== null) return;

  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 3000)),
  ]);

  if (child.exitCode === null) {
    child.kill("SIGKILL");
    await new Promise((resolve) => child.once("exit", resolve));
  }
}

async function ensureDirs() {
  await mkdir(outputDir, { recursive: true });
  if (mirrorDir) {
    await mkdir(mirrorDir, { recursive: true });
  }
}

async function captureAnimation(page, animationPath) {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "pentect-gif-"));
  const framePattern = path.join(tempDir, "frame-%03d.png");
  const captureStart = Date.now();
  let frameIndex = 0;

  try {
    while (Date.now() - captureStart < 6000) {
      const framePath = path.join(
        tempDir,
        `frame-${String(frameIndex).padStart(3, "0")}.png`
      );
      await page.screenshot({ path: framePath, fullPage: true, type: "png" });
      frameIndex += 1;

      const ready = await page.evaluate(
        () => document.documentElement.dataset.pentectReady === "true"
      );
      if (ready && frameIndex > 6) break;

      await page.waitForTimeout(90);
    }

    await runCommand("ffmpeg", [
      "-y",
      "-framerate",
      "10",
      "-i",
      framePattern,
      "-vf",
      "fps=10,scale=1200:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse",
      animationPath,
    ]);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function captureScreenshots() {
  const chromePath = await resolveChromePath();
  const baseUrl = `http://${host}:${port}/`;
  const devServer = startDevServer();

  try {
    await waitForServer(baseUrl);

    const browser = await chromium.launch({
      executablePath: chromePath,
      headless: true,
    });

    try {
      const page = await browser.newPage({
        viewport: { width: 1500, height: 1300 },
      });
      await page.goto(baseUrl, { waitUntil: "domcontentloaded" });

      for (const [index, item] of screenshotPlan.entries()) {
        if (index === 0) {
          await waitForMaskingStart(page);
        } else {
          await page.getByRole("button", { name: item.button, exact: true }).click();
          await waitForMaskingStart(page);
        }

        const animationDestination = path.join(outputDir, item.animationFile);
        await captureAnimation(page, animationDestination);
        await waitForMaskingReady(page);
        await page.waitForTimeout(150);

        const destination = path.join(outputDir, item.stillFile);
        await page.screenshot({ path: destination, fullPage: true, type: "png" });

        if (mirrorDir) {
          await cp(destination, path.join(mirrorDir, item.stillFile));
          await cp(animationDestination, path.join(mirrorDir, item.animationFile));
        }

        process.stdout.write(`saved ${destination}\n`);
        process.stdout.write(`saved ${animationDestination}\n`);
      }
    } finally {
      await browser.close();
    }
  } finally {
    await stopDevServer(devServer);
  }
}

await ensureDirs();
await captureScreenshots();
