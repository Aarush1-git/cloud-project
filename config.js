// Leave apiUrl empty = local mock mode (blocks kept in browser memory, no AWS needed).
// After AWS setup, fill these in:
//   apiUrl:   Lambda Function URL
//   passcode: same value as the Lambda PASSCODE env var
//   baseUrl:  leave "" if this site is served from the same CloudFront distribution as the blocks
window.CONFIG = { apiUrl: "", passcode: "", baseUrl: "" };
