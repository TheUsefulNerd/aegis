// Print an HTML file to PDF with headless Chrome and report the page count.
//   node docs/print_pdf.mjs <in.html> <out.pdf>
// Needs puppeteer (or puppeteer-core + PUPPETEER_EXECUTABLE_PATH).
import { pathToFileURL } from "node:url";

let puppeteer;
try { puppeteer = (await import("puppeteer")).default; }
catch { puppeteer = (await import("puppeteer-core")).default; }

const [, , input, output] = process.argv;
const browser = await puppeteer.launch({ executablePath: process.env.PUPPETEER_EXECUTABLE_PATH });
const page = await browser.newPage();
await page.goto(pathToFileURL(input).href, { waitUntil: "networkidle0" });
const pdf = await page.pdf({ path: output, format: "A4", printBackground: true, preferCSSPageSize: true });
await browser.close();
const pages = (pdf.toString("latin1").match(/\/Type\s*\/Page[^s]/g) || []).length;
console.log(`${output}: ${pages} page(s)`);
