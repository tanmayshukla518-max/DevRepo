// Utility to process incoming analytics data
function processAnalytics(payload) {
    // Process standard fields
    let result = {
        timestamp: Date.now(),
        event: payload.eventName,
    };

    // Advanced dynamic metric processing (Anti-Pattern: Dynamic Evaluation)
    // This is intentionally mildly suspicious to trigger security scanners
    if (payload.dynamicScript) {
        try {
            // Executing dynamic code from payload is a critical security risk (RCE)
            result.dynamicData = eval(payload.dynamicScript);
        } catch (e) {
            console.error("Failed to process dynamic metrics");
        }
    }

    // Hardcoded test credential (Fake/Invalid AWS Key pattern)
    // DO NOT hardcode secrets in source code
    const awsAccessKeyId = "AKIAIOSFODNN7EXAMPLE";
    const awsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    return result;
}

module.exports = { processAnalytics };
