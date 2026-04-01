import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, "..");
const outDir = path.join(root, "dist-standalone");

const result = await build({
  entryPoints: [path.join(root, "src", "main.ts")],
  bundle: true,
  outdir: "out",
  format: "iife",
  platform: "browser",
  target: ["es2020"],
  minify: true,
  write: false,
  logLevel: "info"
});

const jsFile = result.outputFiles.find((f) => f.path.endsWith(".js"));
const cssFile = result.outputFiles.find((f) => f.path.endsWith(".css"));

if (!jsFile) {
  throw new Error("JavaScript bundle non generato.");
}

const css = cssFile ? cssFile.text : "";
const js = jsFile.text;

const html = `<!doctype html>
<html lang="it">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>JWE Decrypt & JWS Verify (Standalone)</title>
    <style>${css}</style>
  </head>
  <body>
    <div id="app"></div>
    <script>${js}</script>
  </body>
</html>
`;

await mkdir(outDir, { recursive: true });
await writeFile(path.join(outDir, "index.html"), html, "utf8");
console.log(`Creato: ${path.join(outDir, "index.html")}`);
