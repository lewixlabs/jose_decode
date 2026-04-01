import "./style.css";
import {
  compactDecrypt,
  compactVerify,
  importPKCS8,
  importSPKI,
  importX509,
  decodeProtectedHeader
} from "jose";

const app = document.querySelector<HTMLDivElement>("#app");

if (!app) {
  throw new Error("Container #app non trovato.");
}

app.innerHTML = `
  <div class="container">
    <h1>JWE Decrypt &amp; JWS Verify</h1>
    <p class="subtitle">RSA-OAEP-256 + A256GCM &rarr; RS256</p>

    <div class="card">
      <div class="field-group">
        <label for="privateKey">Private Key (PKCS#8 PEM)</label>
        <div class="file-input-wrapper">
          <svg class="file-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
          </svg>
          <span class="file-label-text" id="privateKeyLabel">Select file .pem / .p8 / .key...</span>
          <input type="file" id="privateKey" accept=".pem,.p8,.key" />
        </div>
      </div>

      <div class="field-group">
        <label for="publicKey">Public Key / Certificate (PEM)</label>
        <div class="file-input-wrapper">
          <svg class="file-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
          <span class="file-label-text" id="publicKeyLabel">Select file .pem / .crt / .cer...</span>
          <input type="file" id="publicKey" accept=".pem,.crt,.cer" />
        </div>
      </div>

      <div class="field-group">
        <label for="jwePayload">JWE Payload (compact, 5 segments)</label>
        <textarea id="jwePayload" placeholder="Paste the JWE token here..." spellcheck="false"></textarea>
      </div>

      <button class="btn" id="decryptBtn">
        <div class="spinner"></div>
        <span class="btn-text">Decrypt &amp; Verify</span>
      </button>
    </div>

    <div id="result">
      <div class="card">
        <div class="result-title">Result</div>
        <div class="status-row" id="statusRow"></div>
        <div id="resultBody"></div>
      </div>
    </div>
  </div>
`;

const privateInput = document.querySelector<HTMLInputElement>("#privateKey")!;
const publicInput = document.querySelector<HTMLInputElement>("#publicKey")!;
const privateLabel = document.querySelector<HTMLSpanElement>("#privateKeyLabel")!;
const publicLabel = document.querySelector<HTMLSpanElement>("#publicKeyLabel")!;
const jwePayload = document.querySelector<HTMLTextAreaElement>("#jwePayload")!;
const decryptBtn = document.querySelector<HTMLButtonElement>("#decryptBtn")!;
const result = document.querySelector<HTMLDivElement>("#result")!;
const statusRow = document.querySelector<HTMLDivElement>("#statusRow")!;
const resultBody = document.querySelector<HTMLDivElement>("#resultBody")!;

privateInput.addEventListener("change", () => updateLabel(privateInput, privateLabel));
publicInput.addEventListener("change", () => updateLabel(publicInput, publicLabel));
decryptBtn.addEventListener("click", () => decryptAndVerify());

function updateLabel(input: HTMLInputElement, target: HTMLSpanElement): void {
  const file = input.files?.[0];
  if (file) {
    target.textContent = file.name;
    target.classList.add("selected");
    return;
  }
  target.classList.remove("selected");
}

function jsonOrString(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value, null, 2);
}

function makeBadge(label: string, ok: boolean): HTMLSpanElement {
  const badge = document.createElement("span");
  badge.className = `badge ${ok ? "badge-ok" : "badge-err"}`;
  badge.textContent = `${ok ? "✓" : "✗"} ${label}`;
  return badge;
}

function makeSection(labelText: string, content: string, type: "normal" | "payload" | "error" = "normal"): HTMLDivElement {
  const section = document.createElement("div");
  section.className = "section";

  const label = document.createElement("div");
  label.className = "section-label";
  label.textContent = labelText;
  section.appendChild(label);

  const pre = document.createElement("pre");
  if (type === "payload") {
    pre.className = "payload-block";
  } else if (type === "error") {
    pre.className = "error-block";
  }
  pre.textContent = content;
  section.appendChild(pre);

  return section;
}

function clearResult(): void {
  result.style.display = "block";
  statusRow.innerHTML = "";
  resultBody.innerHTML = "";
}

function setLoading(loading: boolean): void {
  decryptBtn.disabled = loading;
  decryptBtn.classList.toggle("loading", loading);
}

async function readFileText(file: File): Promise<string> {
  return file.text();
}

async function importVerificationKey(pem: string): Promise<CryptoKey> {
  if (pem.includes("BEGIN CERTIFICATE")) {
    return importX509(pem, "RS256");
  }
  return importSPKI(pem, "RS256");
}

async function decryptAndVerify(): Promise<void> {
  const privateFile = privateInput.files?.[0];
  const publicFile = publicInput.files?.[0];
  const jweToken = jwePayload.value.trim();

  if (!privateFile || !publicFile) {
    window.alert("Carica prima private key e public key/certificate.");
    return;
  }

  if (!jweToken) {
    window.alert("Incolla prima il token JWE.");
    return;
  }

  setLoading(true);
  clearResult();

  try {
    const [privatePem, publicPem] = await Promise.all([
      readFileText(privateFile),
      readFileText(publicFile)
    ]);

    const jweParts = jweToken.split(".");
    if (jweParts.length !== 5) {
      throw new Error(`Invalid JWE: expected 5 segments, found ${jweParts.length}.`);
    }

    const decryptKey = await importPKCS8(privatePem, "RSA-OAEP-256");
    const { plaintext, protectedHeader: jweHeader } = await compactDecrypt(jweToken, decryptKey);

    const jwsToken = new TextDecoder().decode(plaintext).trim();
    const jwsParts = jwsToken.split(".");
    if (jwsParts.length !== 3) {
      statusRow.appendChild(makeBadge("JWE Decryption: OK", true));
      statusRow.appendChild(makeBadge("JWS Verification: FAIL", false));
      resultBody.appendChild(
        makeSection(
          "Error detail",
          `Il plaintext decrittato non e un JWS compact valido: attesi 3 segmenti, trovati ${jwsParts.length}.\n\nPreview:\n${jwsToken.slice(0, 200)}`,
          "error"
        )
      );
      resultBody.appendChild(makeSection("JWE Protected Header", jsonOrString(jweHeader)));
      return;
    }

    const verifyKey = await importVerificationKey(publicPem);
    const verifyOutput = await compactVerify(jwsToken, verifyKey);
    const jwsHeader = decodeProtectedHeader(jwsToken);

    let payload: unknown;
    try {
      payload = JSON.parse(new TextDecoder().decode(verifyOutput.payload));
    } catch {
      payload = new TextDecoder().decode(verifyOutput.payload);
    }

    statusRow.appendChild(makeBadge("JWE Decryption: OK", true));
    statusRow.appendChild(makeBadge("JWS Verification: OK", true));

    resultBody.appendChild(makeSection("Plaintext Payload", jsonOrString(payload), "payload"));

    const jweDetails = document.createElement("details");
    jweDetails.innerHTML = "<summary>JWE Protected Header</summary>";
    const jwePre = document.createElement("pre");
    jwePre.textContent = jsonOrString(jweHeader);
    jweDetails.appendChild(jwePre);

    const jwsDetails = document.createElement("details");
    jwsDetails.innerHTML = "<summary>JWS Header</summary>";
    const jwsPre = document.createElement("pre");
    jwsPre.textContent = jsonOrString(jwsHeader);
    jwsDetails.appendChild(jwsPre);

    const block1 = document.createElement("div");
    block1.className = "section";
    block1.style.marginTop = "1rem";
    block1.appendChild(jweDetails);

    const block2 = document.createElement("div");
    block2.className = "section";
    block2.appendChild(jwsDetails);

    resultBody.appendChild(block1);
    resultBody.appendChild(block2);
  } catch (error) {
    const detail = error instanceof Error ? `${error.message}\n\n${error.stack ?? ""}` : String(error);
    statusRow.appendChild(makeBadge("Error", false));
    resultBody.appendChild(makeSection("Error detail", detail, "error"));
  } finally {
    setLoading(false);
  }
}
