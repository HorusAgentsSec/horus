import { Stagehand } from "@browserbasehq/stagehand";

const BASE_URL = process.env.HORUS_BASE_URL ?? "http://localhost:3000";

// Prefix "openai/" routes through the OpenAI-compatible client with a custom baseURL,
// which is how Stagehand talks to OpenRouter.
const MODEL = `openai/${process.env.LLM_DEFAULT_MODEL ?? "deepseek/deepseek-v4-flash"}`;

async function main() {
  const stagehand = new Stagehand({
    env: "LOCAL",
    modelName: MODEL as any,
    modelClientOptions: {
      apiKey: process.env.LLM_API_KEY,
      baseURL: process.env.LLM_BASE_URL ?? "https://openrouter.ai/api/v1",
      headers: {
        "HTTP-Referer": "https://horusagents.com",
        "X-Title": "Horus E2E",
      },
    },
    headless: false,
  });

  await stagehand.init();
  const page = stagehand.page;

  console.log("Navigating to", BASE_URL);
  await page.goto(BASE_URL);

  await stagehand.act({ action: "wait for the login form to appear" });
  const { loginFormVisible } = await stagehand.extract({
    instruction: "Check if the login form is visible",
    schema: { loginFormVisible: { type: "boolean" } } as any,
  });

  console.log("Login form visible:", loginFormVisible);

  await stagehand.close();
}

main().catch(console.error);
