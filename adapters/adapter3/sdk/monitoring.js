/* AI Look client monitoring SDK starter. Keep the production bundle below 5 KB. */
(function (global) {
  "use strict";
  function report(eventName, metadata) {
    // Connect to your authorized AI Look collection endpoint.
    // Do not collect credentials, form values, or sensitive user data.
    if (!global || !global.fetch) return;
    // Intentionally no network request until endpoint and consent policy are configured.
    return { event: eventName, metadata: metadata || {} };
  }
  global.AILookMonitor = { report: report };
})(typeof window !== "undefined" ? window : null);
