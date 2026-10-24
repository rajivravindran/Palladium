// Browser half of demo/shoot.py: signs in to the console and takes the evidence screenshots.
// Playwright is the Node package here (no Python binding on this host), so shoot.py drives this file.
//
//   node demo/shoot.mjs <console-url> <operator-token> <out-dir> <date-prefix> [playwright-index.mjs]
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const [url, token, outDir, prefix, pwPath] = process.argv.slice(2);
if (!url || !token || !outDir || !prefix) {
  console.error("usage: shoot.mjs <console-url> <token> <out-dir> <date-prefix> [playwright-index.mjs]");
  process.exit(2);
}
const { chromium } = await import(pwPath || "playwright");
mkdirSync(outDir, { recursive: true });
const shot = async (page, name) => {
  const file = join(outDir, `${prefix}-${name}.png`);
  await page.waitForTimeout(600); // let the live stream settle
  await page.screenshot({ path: file, fullPage: false });
  console.log(file);
};

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, colorScheme: "light" });
page.setDefaultTimeout(15000);
await page.goto(url);
await page.fill("#token", token);
await page.click("button.btn.primary");
await page.waitForSelector("nav.views");

// 1. Incidents list
await page.click("nav.views >> text=Incidents");
await page.waitForSelector(".incident-list");
await shot(page, "console-incidents");

// 2. The coding agent's incident (frozen, verified)
const rows = page.locator(".incident-row");
const n = await rows.count();
let picked = -1;
for (let i = 0; i < n; i++) {
  const t = await rows.nth(i).innerText();
  if (/coding-agent/i.test(t) && /decoy/i.test(t)) { picked = i; break; }
}
if (picked < 0) for (let i = 0; i < n; i++) if (/coding-agent/i.test(await rows.nth(i).innerText())) { picked = i; break; }
if (picked >= 0) {
  await rows.nth(picked).click();
  await page.waitForSelector("section.detail-pane:not(.empty) h2");
  await shot(page, "console-incident-coding-agent");
} else {
  console.error("no coding-agent incident on screen");
}

// 3. Workloads with the DevOps agent's early-warning tier and its reasons
await page.click("nav.views >> text=Workloads");
await page.waitForSelector("tr.selectable");
await shot(page, "console-workloads");
const devops = page.locator("tr.selectable", { hasText: "devops-agent-01" });
if (await devops.count()) {
  await devops.first().click();
  await page.waitForSelector("section.drift-panel");
  await shot(page, "console-workload-devops-agent");
}

// 4. Approvals (empty unless a gate held a tool)
await page.click("nav.views >> text=Approvals");
await page.waitForTimeout(800);
await shot(page, "console-approvals");

await browser.close();
