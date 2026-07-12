const fs = require('fs');
const html = fs.readFileSync('page.html', 'utf8');
const scriptMatches = [...html.matchAll(/<script>(.*?)<\/script>/gs)];
if (scriptMatches.length > 0) {
    const code = scriptMatches[0][1];
    try {
        new Function(code);
        console.log("No syntax errors in main script block.");
    } catch (e) {
        console.error("SyntaxError found:", e);
    }
} else {
    console.log("No inline scripts found.");
}
