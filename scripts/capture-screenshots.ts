import {
  spawn,
  type ChildProcessByStdio,
} from "node:child_process";
import { access, cp, mkdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import type { Readable } from "node:stream";
import { fileURLToPath } from "node:url";

import { chromium, type Page } from "playwright-core";

type ScreenshotKey = "env" | "nmap" | "har";
type DevServerProcess = ChildProcessByStdio<
  null,
  Readable,
  Readable
>;

interface ScreenshotPlanItem {
  key: ScreenshotKey;
  button: string;
  stillFile: string;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

function parseArgs(argv: string[]): Map<string, string> {
  const parsed = new Map<string, string>();

  for (let index = 0; index < argv.length; index += 1) {
    const current = argv[index];
    if (!current.startsWith("--")) continue;

    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      parsed.set(current, "true");
      continue;
    }

    parsed.set(current, next);
    index += 1;
  }

  return parsed;
}

const args = parseArgs(process.argv.slice(2));
const host = args.get("--host") ?? "127.0.0.1";
const port = Number.parseInt(args.get("--port") ?? "4176", 10);
const outputDir = path.resolve(
  repoRoot,
  args.get("--output-dir") ?? "docs/screenshots"
);
const mirrorDir = args.get("--mirror-dir")
  ? path.resolve(repoRoot, args.get("--mirror-dir") ?? ".")
  : null;

const screenshotPlan: ScreenshotPlanItem[] = [
  {
    key: "env",
    button: "ENV",
    stillFile: "pentect-env.png",
  },
  {
    key: "nmap",
    button: "NMAP",
    stillFile: "pentect-nmap.png",
  },
  {
    key: "har",
    button: "HAR",
    stillFile: "pentect-har.png",
  },
];

const chromeCandidates = [
  process.env.CHROME_PATH,
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
].filter((candidate): candidate is string => Boolean(candidate));

async function fileExists(targetPath: string): Promise<boolean> {
  try {
    await access(targetPath);
    return true;
  } catch {
    return false;
  }
}

async function resolveChromePath(): Promise<string> {
  for (const candidate of chromeCandidates) {
    if (await fileExists(candidate)) {
      return candidate;
    }
  }

  throw new Error(
    "Chrome executable not found. Set CHROME_PATH or install google-chrome."
  );
}

async function waitForServer(url: string, timeoutMs = 20000): Promise<void> {
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // retry
    }

    await new Promise<void>((resolve) => setTimeout(resolve, 250));
  }

  throw new Error(`Timed out waiting for dev server: ${url}`);
}

async function waitForMaskingReady(page: Page, timeoutMs = 10000): Promise<void> {
  await page.waitForFunction("document.documentElement.dataset.pentectReady === 'true'", {
    timeout: timeoutMs,
  });
}

async function waitForMaskingStart(page: Page, timeoutMs = 1500): Promise<void> {
  await page
    .waitForFunction("document.documentElement.dataset.pentectReady !== 'true'", {
      timeout: timeoutMs,
    })
    .catch(() => undefined);
}

function startDevServer(): DevServerProcess {
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

async function stopDevServer(child: DevServerProcess): Promise<void> {
  if (child.exitCode !== null) return;

  child.kill("SIGTERM");
  await Promise.race([
    new Promise<void>((resolve) => child.once("exit", () => resolve())),
    new Promise<void>((resolve) => setTimeout(resolve, 3000)),
  ]);

  if (child.exitCode === null) {
    child.kill("SIGKILL");
    await new Promise<void>((resolve) => child.once("exit", () => resolve()));
  }
}

async function ensureDirs(): Promise<void> {
  await mkdir(outputDir, { recursive: true });
  if (mirrorDir) {
    await mkdir(mirrorDir, { recursive: true });
  }
}

async function captureScreenshots(): Promise<void> {
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
          await waitForMaskingStart(page, 2500);
        } else {
          await page.getByRole("button", { name: item.button, exact: true }).click();
          await waitForMaskingStart(page, 2500);
        }

        await waitForMaskingReady(page);
        await page.waitForTimeout(280);

        const destination = path.join(outputDir, item.stillFile);
        await page.screenshot({ path: destination, fullPage: true, type: "png" });

        if (mirrorDir) {
          await cp(destination, path.join(mirrorDir, item.stillFile));
        }

        process.stdout.write(`saved ${destination} (${item.key})\n`);
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
