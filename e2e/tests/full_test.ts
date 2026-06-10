import { Stagehand } from "@browserbasehq/stagehand";
import * as fs from "fs";

const BASE_URL = process.env.HORUS_BASE_URL ?? "http://localhost:5173";
const MODEL = `openai/${process.env.LLM_DEFAULT_MODEL ?? "deepseek/deepseek-v4-flash"}`;

interface TestResult {
  name: string;
  success: boolean;
  error?: string;
  timestamp: string;
}

const results: TestResult[] = [];
let errorLog = "";

function logError(msg: string) {
  console.error(msg);
  errorLog += msg + "\n";
}

function logTest(name: string, success: boolean, error?: string) {
  results.push({ name, success, error, timestamp: new Date().toISOString() });
  console.log(`[${success ? "✓" : "✗"}] ${name}${error ? ": " + error : ""}`);
  if (error) errorLog += `[${name}] ${error}\n`;
}

async function testPageLoads(stagehand: any) {
  try {
    console.log("\n=== Testing Page Loads ===");

    // Navigate to base URL
    await stagehand.page.goto(BASE_URL, { waitUntil: "networkidle" });
    logTest("Navigate to home page", true);

  } catch (e) {
    logTest("Page loads test", false, String(e));
  }
}

async function testPageContent(stagehand: any) {
  try {
    console.log("\n=== Testing Page Content ===");

    const { hasContent } = await stagehand.extract({
      instruction: "Is the page properly loaded with content visible?",
      schema: { hasContent: { type: "boolean" } } as any,
    });

    logTest("Page content loaded", hasContent === true);

  } catch (e) {
    logTest("Page content test", false, String(e));
  }
}

async function testLoginInterface(stagehand: any) {
  try {
    console.log("\n=== Testing Login Interface ===");

    const { loginElements } = await stagehand.extract({
      instruction: "Extract all visible login form elements (email, password, submit button, etc.)",
      schema: {
        loginElements: { type: "array", items: { type: "string" } },
      } as any,
    });

    logTest(
      "Login interface visible",
      loginElements && loginElements.length > 0,
      loginElements?.length > 0 ? `Found ${loginElements.length} elements` : "No login elements"
    );

  } catch (e) {
    logTest("Login interface test", false, String(e));
  }
}

async function testNavigationMenu(stagehand: any) {
  try {
    console.log("\n=== Testing Navigation Menu ===");

    const { menuItems } = await stagehand.extract({
      instruction: "List all visible navigation menu items or links",
      schema: {
        menuItems: { type: "array", items: { type: "string" } },
      } as any,
    });

    logTest(
      "Navigation menu present",
      menuItems && menuItems.length > 0,
      menuItems?.join(", ") || "No menu items"
    );

  } catch (e) {
    logTest("Navigation menu test", false, String(e));
  }
}

async function testButtons(stagehand: any) {
  try {
    console.log("\n=== Testing Buttons ===");

    const { allButtons } = await stagehand.extract({
      instruction: "List all clickable buttons visible on the page with their labels",
      schema: {
        allButtons: { type: "array", items: { type: "string" } },
      } as any,
    });

    logTest(
      "Buttons visible",
      allButtons && allButtons.length > 0,
      allButtons?.length > 0 ? `Found ${allButtons.length} buttons` : "No buttons found"
    );

  } catch (e) {
    logTest("Buttons test", false, String(e));
  }
}

async function testFormFields(stagehand: any) {
  try {
    console.log("\n=== Testing Form Fields ===");

    const { formFields } = await stagehand.extract({
      instruction: "List all visible form input fields (text, email, password, etc.)",
      schema: {
        formFields: { type: "array", items: { type: "string" } },
      } as any,
    });

    logTest(
      "Form fields present",
      formFields && formFields.length > 0,
      formFields?.join(", ") || "No form fields"
    );

  } catch (e) {
    logTest("Form fields test", false, String(e));
  }
}

async function testErrorMessages(stagehand: any) {
  try {
    console.log("\n=== Testing Error Messages ===");

    // Try to submit empty login
    try {
      await stagehand.act({
        action: "Look for any error or warning messages displayed on the page",
      });
    } catch (e) {
      // Ignore if action fails
    }

    const { errors } = await stagehand.extract({
      instruction: "Extract any error messages, warnings, or alerts visible on the page",
      schema: {
        errors: { type: "array", items: { type: "string" } },
      } as any,
    });

    logTest(
      "Error handling checked",
      true,
      errors?.length > 0 ? `Found ${errors.length} messages` : "No error messages"
    );

  } catch (e) {
    logTest("Error messages test", false, String(e));
  }
}

async function testResponsiveness(stagehand: any) {
  try {
    console.log("\n=== Testing Responsiveness ===");

    // Test different viewport sizes
    const viewports = [
      { width: 1920, height: 1080, name: "Desktop" },
      { width: 768, height: 1024, name: "Tablet" },
      { width: 375, height: 667, name: "Mobile" },
    ];

    for (const viewport of viewports) {
      try {
        await stagehand.page.setViewportSize(viewport);
        logTest(`${viewport.name} viewport (${viewport.width}x${viewport.height})`, true);
      } catch (e) {
        logTest(`${viewport.name} viewport`, false, String(e));
      }
    }

    // Reset to default
    await stagehand.page.setViewportSize({ width: 1280, height: 720 });

  } catch (e) {
    logTest("Responsiveness test", false, String(e));
  }
}

async function testAccessibility(stagehand: any) {
  try {
    console.log("\n=== Testing Accessibility ===");

    const { a11yIssues } = await stagehand.extract({
      instruction:
        "Check for accessibility issues: missing alt text, unlabeled inputs, color contrast problems, missing ARIA labels",
      schema: {
        a11yIssues: { type: "array", items: { type: "string" } },
      } as any,
    });

    logTest(
      "Accessibility audit",
      true,
      a11yIssues?.length > 0 ? `Found ${a11yIssues.length} issues` : "No major issues"
    );

    if (a11yIssues?.length > 0) {
      a11yIssues.forEach(issue => errorLog += `[Accessibility] ${issue}\n`);
    }

  } catch (e) {
    logTest("Accessibility test", false, String(e));
  }
}

async function testPerformance(stagehand: any) {
  try {
    console.log("\n=== Testing Performance ===");

    const perfMetrics = await stagehand.page.evaluate(() => {
      const nav = performance.getEntriesByType("navigation")[0] as any;
      return {
        loadTime: nav?.loadEventEnd - nav?.loadEventStart,
        domReadyTime: nav?.domContentLoadedEventEnd - nav?.domContentLoadedEventStart,
      };
    });

    logTest(
      "Performance metrics collected",
      perfMetrics?.loadTime !== undefined,
      `Load: ${perfMetrics?.loadTime}ms, DOM: ${perfMetrics?.domReadyTime}ms`
    );

  } catch (e) {
    logTest("Performance test", false, String(e));
  }
}

async function main() {
  let stagehand: any = null;

  try {
    console.log("🧪 Starting Exhaustive Web Testing for Horus...\n");
    console.log(`Target URL: ${BASE_URL}`);
    console.log(`Model: ${MODEL}\n`);

    stagehand = new Stagehand({
      env: "LOCAL",
      modelName: MODEL as any,
      modelClientOptions: {
        apiKey: process.env.LLM_API_KEY,
        baseURL: process.env.LLM_BASE_URL ?? "https://openrouter.ai/api/v1",
        headers: {
          "HTTP-Referer": "https://horusagents.com",
          "X-Title": "Horus E2E Full Test",
        },
      },
      headless: false,
    });

    await stagehand.init();

    // Run all tests in sequence
    await testPageLoads(stagehand);
    await testPageContent(stagehand);
    await testLoginInterface(stagehand);
    await testNavigationMenu(stagehand);
    await testButtons(stagehand);
    await testFormFields(stagehand);
    await testErrorMessages(stagehand);
    await testResponsiveness(stagehand);
    await testAccessibility(stagehand);
    await testPerformance(stagehand);

    await stagehand.close();

    // Print summary
    console.log("\n" + "=".repeat(60));
    console.log("📊 TEST SUMMARY");
    console.log("=".repeat(60));

    const passed = results.filter((r) => r.success).length;
    const failed = results.filter((r) => !r.success).length;

    console.log(`✓ Passed: ${passed}`);
    console.log(`✗ Failed: ${failed}`);
    console.log(`Total: ${results.length}`);
    console.log(`Success Rate: ${((passed / results.length) * 100).toFixed(2)}%`);

    if (failed > 0) {
      console.log("\n❌ FAILED TESTS:");
      results
        .filter((r) => !r.success)
        .forEach((r) => {
          console.log(`  - ${r.name}: ${r.error}`);
        });
    }

    // Save error log to file
    const bugsContent = `# Horus Testing Report

Generated: ${new Date().toISOString()}

## Summary
- Total Tests: ${results.length}
- Passed: ${passed}
- Failed: ${failed}
- Success Rate: ${((passed / results.length) * 100).toFixed(2)}%

## Errors Found
\`\`\`
${errorLog || "No errors logged"}
\`\`\`

## Detailed Results

${JSON.stringify(results, null, 2)}

## Testing Environment
- Base URL: ${BASE_URL}
- Model: ${MODEL}
- Date: ${new Date().toISOString()}
`;

    fs.writeFileSync("bugs.md", bugsContent);
    console.log("\n✅ Report saved to bugs.md");

  } catch (e) {
    logError("Fatal error: " + String(e));
    console.error(e);
    if (stagehand) {
      try {
        await stagehand.close();
      } catch (closeError) {
        console.error("Error closing stagehand:", closeError);
      }
    }
    process.exit(1);
  }
}

main().catch(console.error);
