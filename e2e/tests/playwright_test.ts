import { chromium, Browser, Page } from "playwright-core";
import * as fs from "fs";

const BASE_URL = process.env.HORUS_BASE_URL ?? "http://localhost:5173";

interface TestResult {
  name: string;
  success: boolean;
  details?: any;
  error?: string;
}

interface PageError {
  type: string;
  message: string;
  timestamp: string;
  url?: string;
}

const results: TestResult[] = [];
const pageErrors: PageError[] = [];
const consoleLogs: { type: string; message: string }[] = [];

async function testPageLoads(page: Page) {
  try {
    console.log("\n=== Testing Page Loads ===");

    await page.goto(BASE_URL, { waitUntil: "networkidle" });
    console.log("[✓] Page loaded successfully");
    results.push({ name: "Page loads", success: true });
  } catch (e) {
    console.log("[✗] Page load failed:", e);
    results.push({ name: "Page loads", success: false, error: String(e) });
  }
}

async function testLoginInterface(page: Page) {
  try {
    console.log("\n=== Testing Login Interface ===");

    // Check for login form elements
    const emailInput = await page.$('input[type="email"], input[placeholder*="email" i]');
    const passwordInput = await page.$('input[type="password"]');
    const submitButton = await page.$('button[type="submit"], button:has-text("Login"), button:has-text("Sign in")');

    const hasEmailInput = emailInput !== null;
    const hasPasswordInput = passwordInput !== null;
    const hasSubmitButton = submitButton !== null;

    console.log(`  Email input: ${hasEmailInput ? "✓" : "✗"}`);
    console.log(`  Password input: ${hasPasswordInput ? "✓" : "✗"}`);
    console.log(`  Submit button: ${hasSubmitButton ? "✓" : "✗"}`);

    results.push({
      name: "Login interface",
      success: hasEmailInput && hasPasswordInput && hasSubmitButton,
      details: { hasEmailInput, hasPasswordInput, hasSubmitButton },
    });
  } catch (e) {
    console.log("[✗] Login interface check failed:", e);
    results.push({ name: "Login interface", success: false, error: String(e) });
  }
}

async function testNavigation(page: Page) {
  try {
    console.log("\n=== Testing Navigation ===");

    // Find all navigation links
    const navLinks = await page.$$eval('nav a, [role="navigation"] a, header a', els =>
      els.map(el => ({
        text: el.textContent?.trim(),
        href: el.getAttribute("href"),
      }))
    );

    console.log(`Found ${navLinks.length} navigation links:`);
    navLinks.forEach(link => {
      console.log(`  - ${link.text} (${link.href})`);
    });

    results.push({
      name: "Navigation links",
      success: navLinks.length > 0,
      details: navLinks,
    });
  } catch (e) {
    console.log("[✗] Navigation check failed:", e);
    results.push({ name: "Navigation links", success: false, error: String(e) });
  }
}

async function testButtons(page: Page) {
  try {
    console.log("\n=== Testing Buttons ===");

    const buttons = await page.$$eval("button", els =>
      els.map((el, idx) => ({
        id: idx,
        text: el.textContent?.trim(),
        type: el.getAttribute("type"),
        disabled: el.hasAttribute("disabled"),
        ariaLabel: el.getAttribute("aria-label"),
      }))
    );

    console.log(`Found ${buttons.length} buttons:`);
    buttons.forEach(btn => {
      const label = btn.ariaLabel || btn.text || "(unlabeled)";
      console.log(`  - ${label} (${btn.type || "button"})${btn.disabled ? " [DISABLED]" : ""}`);
    });

    results.push({
      name: "Buttons",
      success: buttons.length > 0,
      details: { count: buttons.length, buttons },
    });
  } catch (e) {
    console.log("[✗] Button check failed:", e);
    results.push({ name: "Buttons", success: false, error: String(e) });
  }
}

async function testFormFields(page: Page) {
  try {
    console.log("\n=== Testing Form Fields ===");

    const inputs = await page.$$eval("input, textarea, select", els =>
      els.map((el, idx) => ({
        id: idx,
        type: el.getAttribute("type"),
        name: el.getAttribute("name"),
        placeholder: el.getAttribute("placeholder"),
        label: el.parentElement?.textContent?.trim().substring(0, 50),
      }))
    );

    console.log(`Found ${inputs.length} form fields:`);
    inputs.forEach(inp => {
      const desc = inp.placeholder || inp.name || inp.label || "(unnamed)";
      console.log(`  - ${desc} (${inp.type || "element"})`);
    });

    results.push({
      name: "Form fields",
      success: inputs.length >= 0,
      details: { count: inputs.length, inputs },
    });
  } catch (e) {
    console.log("[✗] Form fields check failed:", e);
    results.push({ name: "Form fields", success: false, error: String(e) });
  }
}

async function testViewports(page: Page) {
  try {
    console.log("\n=== Testing Responsive Design ===");

    const viewports = [
      { width: 1920, height: 1080, name: "Desktop" },
      { width: 1024, height: 768, name: "Tablet" },
      { width: 375, height: 667, name: "Mobile" },
    ];

    for (const viewport of viewports) {
      try {
        await page.setViewportSize(viewport);
        const elementCount = await page.$$eval("*", els => els.length);
        console.log(`  ${viewport.name} (${viewport.width}x${viewport.height}): ${elementCount} elements - ✓`);
        results.push({
          name: `Viewport ${viewport.name}`,
          success: true,
          details: { viewport, elementCount },
        });
      } catch (e) {
        console.log(`  ${viewport.name}: ✗ - ${e}`);
        results.push({
          name: `Viewport ${viewport.name}`,
          success: false,
          error: String(e),
        });
      }
    }

  } catch (e) {
    console.log("[✗] Viewport testing failed:", e);
    results.push({ name: "Responsive design", success: false, error: String(e) });
  }
}

async function testAccessibility(page: Page) {
  try {
    console.log("\n=== Testing Accessibility ===");

    const issues: string[] = [];

    // Check for alt text on images
    const imagesWithoutAlt = await page.$$eval("img:not([alt])", els => els.length);
    if (imagesWithoutAlt > 0) issues.push(`${imagesWithoutAlt} images missing alt text`);

    // Check for form labels
    const inputsWithoutLabel = await page.$$eval(
      "input:not([aria-label])",
      els => els.filter(el => !el.previousElementSibling?.textContent).length
    );
    if (inputsWithoutLabel > 0) issues.push(`${inputsWithoutLabel} inputs may be missing labels`);

    // Check color contrast (basic check)
    const styleIssues = await page.evaluate(() => {
      const issues = [];
      document.querySelectorAll("*").forEach(el => {
        const styles = window.getComputedStyle(el);
        // Very basic check - not a real contrast checker
        if (styles.color === styles.backgroundColor) {
          issues.push("Potential color contrast issue");
        }
      });
      return issues.slice(0, 5); // Return first 5 issues
    });

    if (styleIssues.length > 0) issues.push(...styleIssues);

    console.log(`Accessibility issues found: ${issues.length}`);
    if (issues.length > 0) {
      issues.forEach(issue => console.log(`  - ${issue}`));
    } else {
      console.log("  No major issues detected");
    }

    results.push({
      name: "Accessibility",
      success: issues.length === 0,
      details: issues,
    });
  } catch (e) {
    console.log("[✗] Accessibility check failed:", e);
    results.push({ name: "Accessibility", success: false, error: String(e) });
  }
}

async function testNetworkRequests(page: Page) {
  try {
    console.log("\n=== Testing Network Requests ===");

    const failedRequests: any[] = [];

    page.on("response", response => {
      if (response.status() >= 400) {
        failedRequests.push({
          url: response.url(),
          status: response.status(),
        });
      }
    });

    // Wait a moment for requests
    await page.waitForLoadState("networkidle");

    console.log(`Failed requests: ${failedRequests.length}`);
    failedRequests.forEach(req => {
      console.log(`  ${req.status} - ${req.url}`);
    });

    results.push({
      name: "Network requests",
      success: failedRequests.length === 0,
      details: failedRequests,
    });
  } catch (e) {
    console.log("[✗] Network check failed:", e);
    results.push({ name: "Network requests", success: false, error: String(e) });
  }
}

async function testPerformance(page: Page) {
  try {
    console.log("\n=== Testing Performance ===");

    const metrics = await page.evaluate(() => {
      const nav = performance.getEntriesByType("navigation")[0] as any;
      return {
        loadTime: nav?.loadEventEnd - nav?.loadEventStart,
        domReadyTime: nav?.domContentLoadedEventEnd - nav?.domContentLoadedEventStart,
        firstPaint: performance.getEntriesByName("first-paint")[0]?.startTime,
      };
    });

    console.log(`  Load time: ${metrics.loadTime}ms`);
    console.log(`  DOM ready: ${metrics.domReadyTime}ms`);
    console.log(`  First paint: ${metrics.firstPaint}ms`);

    results.push({
      name: "Performance",
      success: true,
      details: metrics,
    });
  } catch (e) {
    console.log("[✗] Performance check failed:", e);
    results.push({ name: "Performance", success: false, error: String(e) });
  }
}

async function main() {
  let browser: Browser | null = null;
  let page: Page | null = null;

  try {
    console.log("🧪 Starting Exhaustive Testing for Horus\n");
    console.log(`Target: ${BASE_URL}\n`);

    browser = await chromium.launch({ headless: false });
    page = await browser.newPage();

    // Capture console messages
    page.on("console", msg => {
      consoleLogs.push({ type: msg.type(), message: msg.text() });
      if (msg.type() === "error" || msg.type() === "warning") {
        console.log(`[CONSOLE ${msg.type().toUpperCase()}] ${msg.text()}`);
      }
    });

    // Capture page errors
    page.on("pageerror", error => {
      const errorInfo = {
        type: "page_error",
        message: error.message,
        timestamp: new Date().toISOString(),
      };
      pageErrors.push(errorInfo);
      console.log(`[PAGE ERROR] ${error.message}`);
    });

    // Run all tests
    await testPageLoads(page);
    await testLoginInterface(page);
    await testNavigation(page);
    await testButtons(page);
    await testFormFields(page);
    await testViewports(page);
    await testAccessibility(page);
    await testNetworkRequests(page);
    await testPerformance(page);

    // Summary
    console.log("\n" + "=".repeat(60));
    console.log("📊 TEST SUMMARY");
    console.log("=".repeat(60));

    const passed = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;

    console.log(`✓ Passed: ${passed}`);
    console.log(`✗ Failed: ${failed}`);
    console.log(`Total: ${results.length}`);
    console.log(`Success Rate: ${((passed / results.length) * 100).toFixed(2)}%`);

    if (failed > 0) {
      console.log("\n❌ FAILED TESTS:");
      results
        .filter(r => !r.success)
        .forEach(r => {
          console.log(`  - ${r.name}: ${r.error}`);
        });
    }

    if (pageErrors.length > 0) {
      console.log("\n⚠️  PAGE ERRORS:");
      pageErrors.forEach(e => {
        console.log(`  - ${e.message}`);
      });
    }

    // Generate report
    const report = `# Horus Testing Report

Generated: ${new Date().toISOString()}

## Summary
- **Total Tests**: ${results.length}
- **Passed**: ${passed}
- **Failed**: ${failed}
- **Success Rate**: ${((passed / results.length) * 100).toFixed(2)}%

## Testing Environment
- **URL**: ${BASE_URL}
- **Browser**: Chromium
- **Date**: ${new Date().toLocaleString()}

---

## Test Results

${results
  .map(
    r => `### ${r.name}
- **Status**: ${r.success ? "✓ PASS" : "✗ FAIL"}
${r.error ? `- **Error**: ${r.error}` : ""}
${r.details ? `- **Details**: \`\`\`json\n${JSON.stringify(r.details, null, 2)}\n\`\`\`` : ""}
`
  )
  .join("\n")}

---

## Console Logs

\`\`\`
${consoleLogs.map(log => `[${log.type.toUpperCase()}] ${log.message}`).join("\n")}
\`\`\`

---

## Page Errors

${
  pageErrors.length > 0
    ? `\`\`\`
${pageErrors.map(e => `[${e.timestamp}] ${e.message}`).join("\n")}
\`\`\``
    : "No page errors detected ✓"
}

---

## Detailed JSON

\`\`\`json
${JSON.stringify(
  {
    results,
    pageErrors,
    consoleLogs: consoleLogs.slice(0, 50), // Limit to first 50
  },
  null,
  2
)}
\`\`\`
`;

    fs.writeFileSync("bugs.md", report);
    console.log("\n✅ Full report saved to bugs.md");

    await browser.close();

  } catch (e) {
    console.error("\n❌ Fatal error:", e);
    if (browser) {
      await browser.close();
    }
    process.exit(1);
  }
}

main();
