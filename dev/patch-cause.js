var fs = require("fs");
var s = fs.readFileSync("analyzer.js","utf8");
var anchor = "var response = await fetch(\"https://api.groq.com/openai/v1/chat/completions\", {";
var wrapped = [
"var response;",
"    try {",
"      response = await fetch(\"https://api.groq.com/openai/v1/chat/completions\", {"
].join("\n");
if (s.indexOf(anchor) === -1) { console.error("anchor missing"); process.exit(1); }
s = s.replace(anchor, wrapped);

// Close the try around the fetch options block — find "});" that ends the fetch call
var endMarker = "        temperature: 0,\n      }),\n    });";
var endRepl = [
"        temperature: 0,",
"      }),",
"      });",
"    } catch (fetchErr) {",
"      fetchErr.message = \"fetch: \" + fetchErr.message + \" | cause: \" + (fetchErr.cause && (fetchErr.cause.code || fetchErr.cause.message) || \"unknown\");",
"      throw fetchErr;",
"    }"
].join("\n");
if (s.indexOf(endMarker) === -1) { console.error("end anchor missing"); process.exit(1); }
s = s.replace(endMarker, endRepl);

fs.writeFileSync("analyzer.js", s);
require("./analyzer.js");
console.log("OK: analyzer.js cause-logging patched");
