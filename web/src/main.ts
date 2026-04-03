import "./style.css";
import {
  CompactEncrypt,
  CompactSign,
  compactDecrypt,
  compactVerify,
  importPKCS8,
  importSPKI,
  importX509,
  decodeProtectedHeader
} from "jose";

const app = document.querySelector<HTMLDivElement>("#app");

if (!app) {
  throw new Error("Container #app not found.");
}

app.innerHTML = `
  <div class="container">
    <h1>JOSE Tool</h1>
    <p class="subtitle" id="modeSubtitle">Decrypt JWE then verify JWS (RSA-OAEP-256 + A256GCM &rarr; RS256)</p>

    <div class="mode-toggle" role="group" aria-label="Operation mode">
      <span class="toggle-label">Mode</span>
      <label class="switch" for="modeToggle">
        <input type="checkbox" id="modeToggle" />
        <span class="slider"></span>
      </label>
      <span class="mode-text" id="modeText">Decrypt + Verify</span>
    </div>

    <div class="card">
      <div class="field-group">
        <label for="privateKey" id="privateKeyTitle">Private Key (PKCS#8 PEM, decrypt)</label>
        <div class="file-input-wrapper">
          <svg class="file-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
          </svg>
          <span class="file-label-text" id="privateKeyLabel">Select file .pem / .p8 / .key...</span>
          <input type="file" id="privateKey" accept=".pem,.p8,.key" />
        </div>
      </div>

      <div class="field-group">
        <label for="publicKey" id="publicKeyTitle">Public Key / Certificate (PEM, verify)</label>
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
        <label for="jwePayload" id="payloadTitle">JWE Payload (compact, 5 segments)</label>
        <textarea id="jwePayload" placeholder="Paste the JWE token here..." spellcheck="false"></textarea>
      </div>

      <button class="btn" id="decryptBtn">
        <div class="spinner"></div>
        <span class="btn-text" id="actionText">Decrypt &amp; Verify</span>
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
const privateKeyTitle = document.querySelector<HTMLLabelElement>("#privateKeyTitle")!;
const publicKeyTitle = document.querySelector<HTMLLabelElement>("#publicKeyTitle")!;
const payloadTitle = document.querySelector<HTMLLabelElement>("#payloadTitle")!;
const modeSubtitle = document.querySelector<HTMLParagraphElement>("#modeSubtitle")!;
const modeToggle = document.querySelector<HTMLInputElement>("#modeToggle")!;
const modeText = document.querySelector<HTMLSpanElement>("#modeText")!;
const actionText = document.querySelector<HTMLSpanElement>("#actionText")!;
const jwePayload = document.querySelector<HTMLTextAreaElement>("#jwePayload")!;
const decryptBtn = document.querySelector<HTMLButtonElement>("#decryptBtn")!;
const result = document.querySelector<HTMLDivElement>("#result")!;
const statusRow = document.querySelector<HTMLDivElement>("#statusRow")!;
const resultBody = document.querySelector<HTMLDivElement>("#resultBody")!;
const PRIVATE_KEY_PLACEHOLDER = "Select file .pem / .p8 / .key...";
const PUBLIC_KEY_PLACEHOLDER = "Select file .pem / .crt / .cer...";

privateInput.addEventListener("change", () => updateLabel(privateInput, privateLabel));
publicInput.addEventListener("change", () => updateLabel(publicInput, publicLabel));
modeToggle.addEventListener("change", () => {
  clearLoadedKeys();
  updateModeUI();
});
decryptBtn.addEventListener("click", () => runOperation());
updateModeUI();

function updateLabel(input: HTMLInputElement, target: HTMLSpanElement): void {
  const file = input.files?.[0];
  if (file) {
    target.textContent = file.name;
    target.classList.add("selected");
    return;
  }
  target.textContent = target === privateLabel ? PRIVATE_KEY_PLACEHOLDER : PUBLIC_KEY_PLACEHOLDER;
  target.classList.remove("selected");
}

function clearLoadedKeys(): void {
  privateInput.value = "";
  publicInput.value = "";
  updateLabel(privateInput, privateLabel);
  updateLabel(publicInput, publicLabel);
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

function makeInfoBadge(label: string): HTMLSpanElement {
  const badge = document.createElement("span");
  badge.className = "badge badge-info";
  badge.textContent = `i ${label}`;
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

function isEncryptMode(): boolean {
  return modeToggle.checked;
}

function updateModeUI(): void {
  const encryptMode = isEncryptMode();

  if (encryptMode) {
    modeText.textContent = "Sign + Encrypt";
    modeSubtitle.textContent = "Sign payload as JWS then encrypt it as JWE (RS256 -> RSA-OAEP-256 + A256GCM)";
    privateKeyTitle.textContent = "Private Key (PKCS#8 PEM, sign)";
    publicKeyTitle.textContent = "Public Key / Certificate (PEM, encrypt)";
    payloadTitle.textContent = "Payload to sign and encrypt";
    jwePayload.placeholder = "Paste plaintext payload (JSON or text)...";
    actionText.textContent = "Sign & Encrypt";
  } else {
    modeText.textContent = "Decrypt + Verify";
    modeSubtitle.textContent = "Decrypt JWE then verify JWS (RSA-OAEP-256 + A256GCM -> RS256)";
    privateKeyTitle.textContent = "Private Key (PKCS#8 PEM, decrypt)";
    publicKeyTitle.textContent = "Public Key / Certificate (PEM, verify)";
    payloadTitle.textContent = "JWE Payload (compact, 5 segments)";
    jwePayload.placeholder = "Paste the JWE token here...";
    actionText.textContent = "Decrypt & Verify";
  }
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

async function importEncryptionKey(pem: string): Promise<CryptoKey> {
  if (pem.includes("BEGIN CERTIFICATE")) {
    return importX509(pem, "RSA-OAEP-256");
  }
  return importSPKI(pem, "RSA-OAEP-256");
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function certificateDerFromPem(pem: string): Uint8Array {
  const match = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
  if (!match) {
    throw new Error("missing-certificate");
  }

  const certBase64 = match[1].replace(/\s+/g, "");
  const raw = atob(certBase64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    out[i] = raw.charCodeAt(i);
  }
  return out;
}

async function certificateThumbprintS256FromPem(pem: string): Promise<string> {
  const der = certificateDerFromPem(pem);
  const derBuffer = der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer;
  const digest = await crypto.subtle.digest("SHA-256", derBuffer);
  return base64UrlEncode(new Uint8Array(digest));
}

async function optionalCertificateThumbprintS256FromPem(pem: string): Promise<string | null> {
  try {
    return await certificateThumbprintS256FromPem(pem);
  } catch (error) {
    if (error instanceof Error && error.message === "missing-certificate") {
      return null;
    }
    throw error;
  }
}

async function runOperation(): Promise<void> {
  if (isEncryptMode()) {
    await signAndEncrypt();
    return;
  }
  await decryptAndVerify();
}

async function decryptAndVerify(): Promise<void> {
  const privateFile = privateInput.files?.[0];
  const publicFile = publicInput.files?.[0];
  const jweToken = jwePayload.value.trim();

  if (!privateFile || !publicFile) {
    window.alert("Please load the private key and public key/certificate first.");
    return;
  }

  if (!jweToken) {
    window.alert("Please paste the JWE token first.");
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
          `The decrypted plaintext is not a valid compact JWS: expected 3 segments, found ${jwsParts.length}.\n\nPreview:\n${jwsToken.slice(0, 200)}`,

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

async function signAndEncrypt(): Promise<void> {
  const privateFile = privateInput.files?.[0];
  const publicFile = publicInput.files?.[0];
  const payloadInput = jwePayload.value;

  if (!privateFile || !publicFile) {
    window.alert("Please load the private key for signing and the public key/certificate for encryption first.");
    return;
  }

  if (!payloadInput.trim()) {
    window.alert("Please paste the payload to sign and encrypt first.");
    return;
  }

  setLoading(true);
  clearResult();

  try {
    const [privatePem, publicPem] = await Promise.all([
      readFileText(privateFile),
      readFileText(publicFile)
    ]);

    const signKey = await importPKCS8(privatePem, "RS256");
    const payloadBytes = new TextEncoder().encode(payloadInput);
    const jwsToken = await new CompactSign(payloadBytes)
      .setProtectedHeader({ alg: "RS256" })
      .sign(signKey);

    const encryptKey = await importEncryptionKey(publicPem);
    const x5tS256 = await optionalCertificateThumbprintS256FromPem(publicPem);

    const protectedHeader = x5tS256
      ? { alg: "RSA-OAEP-256", enc: "A256GCM", cty: "JWE", "x5t#S256": x5tS256 }
      : { alg: "RSA-OAEP-256", enc: "A256GCM", cty: "JWE" };

    const jweToken = await new CompactEncrypt(new TextEncoder().encode(jwsToken))
      .setProtectedHeader(protectedHeader)
      .encrypt(encryptKey);
    const jweHeader = decodeProtectedHeader(jweToken);

    statusRow.appendChild(makeBadge("JWS Signing: OK", true));
    statusRow.appendChild(makeBadge("JWE Encryption: OK", true));
    statusRow.appendChild(
      makeInfoBadge(
        x5tS256
          ? "JWE Header x5t#S256: included (certificate)"
          : "JWE Header x5t#S256: omitted (public key PEM)"
      )
    );

    resultBody.appendChild(makeSection("Generated JWE", jweToken, "payload"));

    const jwsDetails = document.createElement("details");
    jwsDetails.innerHTML = "<summary>Generated JWS (signed payload)</summary>";
    const jwsPre = document.createElement("pre");
    jwsPre.textContent = jwsToken;
    jwsDetails.appendChild(jwsPre);

    const jweDetails = document.createElement("details");
    jweDetails.innerHTML = "<summary>Generated JWE Protected Header</summary>";
    const jwePre = document.createElement("pre");
    jwePre.textContent = jsonOrString(jweHeader);
    jweDetails.appendChild(jwePre);

    const parsedPayload = (() => {
      try {
        return JSON.stringify(JSON.parse(payloadInput), null, 2);
      } catch {
        return payloadInput;
      }
    })();

    const payloadDetails = document.createElement("details");
    payloadDetails.innerHTML = "<summary>Input Payload</summary>";
    const payloadPre = document.createElement("pre");
    payloadPre.textContent = parsedPayload;
    payloadDetails.appendChild(payloadPre);

    const block1 = document.createElement("div");
    block1.className = "section";
    block1.style.marginTop = "1rem";
    block1.appendChild(payloadDetails);

    const block2 = document.createElement("div");
    block2.className = "section";
    block2.appendChild(jweDetails);

    const block3 = document.createElement("div");
    block3.className = "section";
    block3.appendChild(jwsDetails);

    resultBody.appendChild(block1);
    resultBody.appendChild(block2);
    resultBody.appendChild(block3);
  } catch (error) {
    const detail = error instanceof Error ? `${error.message}\n\n${error.stack ?? ""}` : String(error);
    statusRow.appendChild(makeBadge("Error", false));
    resultBody.appendChild(makeSection("Error detail", detail, "error"));
  } finally {
    setLoading(false);
  }
}
