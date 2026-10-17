const privateKeyTextarea = document.querySelector("#private-key-textarea");
const publicKeyTextarea = document.querySelector("#public-key-textarea");
const revocationCertificateTextarea = document.querySelector("#revocation-certificate-textarea");

const buttonGenerateKeys = document.querySelector("#generate-keys-button");
const optionsType = document.querySelector("#options-type");
const keySizeSelectHolder = document.querySelector("#key-size-select-holder");
const optionsKeySize = document.querySelector("#options-key-size");
const optionsName = document.querySelector("#options-name");
const optionsEmail = document.querySelector("#options-email");
const optionsPassphrase = document.querySelector("#options-passphrase");
const optionsExpirationTime = document.querySelector("#options-expiration");

const copyPrivateKeyButton = document.querySelector("#copy-private-key-button");
const copyPublicKeyButton = document.querySelector("#copy-public-key-button");
const copyRevocationCertificateButton = document.querySelector("#copy-revocation-certificate-button");

const downloadPrivateKeyButton = document.querySelector("#download-private-key-button");
const downloadPublicKeyButton = document.querySelector("#download-public-key-button");
const downloadRevocationCertificateButton = document.querySelector("#download-revocation-certificate-button");
const errorMessage = document.querySelector("#error-message");

const showError = (msg) => {
    errorMessage.textContent = msg;
    errorMessage.hidden = false;
};

const clearError = () => {
    errorMessage.hidden = true;
    errorMessage.textContent = "";
};

const getTextareaByName = (textareaName) => {
    // Whitelist the known textareas instead of building a selector from
    // untrusted data attributes (defense in depth against selector injection).
    const map = {
        "private-key-textarea": privateKeyTextarea,
        "public-key-textarea": publicKeyTextarea,
        "revocation-certificate-textarea": revocationCertificateTextarea
    };
    return map[textareaName] || null;
};

const downloadFile = (element) => {

    const textareaName = element.dataset.target;

    const link = document.createElement("a");
    const target = getTextareaByName(textareaName);
    if (!target) {
        showError("Unknown download target.");
        return;
    }
    const content = target.value;
    const file = new Blob([content], { type: 'text/plain' });
    link.href = URL.createObjectURL(file);
    link.download = textareaName.replace("-textarea", "") + ".asc";
    link.click();
    URL.revokeObjectURL(link.href);
};

const copyToClipboard = (element) => {

    const textareaName = element.dataset.target;

    const textarea = getTextareaByName(textareaName);
    if (!textarea) {
        showError("Unknown copy target.");
        return;
    }

    navigator.clipboard.writeText(textarea.value).then(() => {
        const originalText = element.innerText;
        element.innerText = "Copied!";
        setTimeout(() => {
            element.innerText = originalText;
        }, 2000);
    }).catch(err => {
        console.error("Failed to copy: ", err);
        showError("Failed to copy to clipboard. Please copy the text manually.");
    });
}

const keyAlgorithmChanged = (element) => {

    if (element.value == "rsa") {
        keySizeSelectHolder.classList.remove("key-size-select-holder");
    } else {
        keySizeSelectHolder.classList.add("key-size-select-holder");
    }
};

const worker = new Worker("worker.js");

worker.onerror = (error) => {
    console.error("Worker error:", error);
    showError("An error occurred with the background worker. Please reload the page.");
    buttonGenerateKeys.disabled = false;
    buttonGenerateKeys.innerText = "Generate Keys";
};

// Pending resolver for MCP tool calls that need to await key generation.
// Guarded so concurrent/overlapping calls can never hand the wrong result
// (or a manually generated key) to an agent.
let _mcpPendingResolve = null;
let _mcpPendingReject = null;
let _mcpGenerationActive = false;
let _mcpQueue = Promise.resolve();

worker.onmessage = async function handleMessageFromMain(msg) {

    if (msg.data.error) {
        if (_mcpPendingReject) {
            const reject = _mcpPendingReject;
            _mcpPendingResolve = null;
            _mcpPendingReject = null;
            _mcpGenerationActive = false;
            reject(new Error(msg.data.error));
        } else {
            showError("Error generating keys: " + msg.data.error);
        }
        buttonGenerateKeys.disabled = false;
        buttonGenerateKeys.innerText = "Generate Keys";
        return;
    }

    // Reply to fingerprint lookups requested by the WebMCP tool handler.
    if (msg.data.fingerprint !== undefined) {
        return; // handled by its own one-shot listener in app.js
    }

    privateKeyTextarea.value = msg.data.privateKey;
    publicKeyTextarea.value = msg.data.publicKey;
    revocationCertificateTextarea.value = msg.data.revocationCertificate;

    copyPrivateKeyButton.classList.add("copy-button");
    copyPublicKeyButton.classList.add("copy-button");
    copyRevocationCertificateButton.classList.add("copy-button");

    downloadPrivateKeyButton.classList.add("download-button");
    downloadPublicKeyButton.classList.add("download-button");
    downloadRevocationCertificateButton.classList.add("download-button");

    buttonGenerateKeys.disabled = false;
    buttonGenerateKeys.innerText = "Generate Keys";

    copyPrivateKeyButton.disabled = false;
    copyPublicKeyButton.disabled = false;
    copyRevocationCertificateButton.disabled = false;

    downloadPrivateKeyButton.disabled = false;
    downloadPublicKeyButton.disabled = false;
    downloadRevocationCertificateButton.disabled = false;

    privateKeyTextarea.disabled = false;
    publicKeyTextarea.disabled = false;
    revocationCertificateTextarea.disabled = false;

    // Resolve MCP tool call if one is pending (only while an MCP
    // generation is actually active — manual clicks can't leak keys to agents)
    if (_mcpGenerationActive && _mcpPendingResolve) {
        const resolve = _mcpPendingResolve;
        _mcpPendingResolve = null;
        _mcpPendingReject = null;
        _mcpGenerationActive = false;
        resolve({
            privateKey: msg.data.privateKey,
            publicKey: msg.data.publicKey,
            revocationCertificate: msg.data.revocationCertificate
        });
    }

    // Wipe the passphrase from the DOM as soon as the protected key has
    // been generated (it only lived in memory long enough for the worker).
    // Defer by one tick so a fingerprint lookup queued right after
    // generation can resolve first — otherwise this unrelated message would
    // be mistaken for a key-generation result and clear the field early.
    if (!_mcpGenerationActive && !_mcpPendingResolve) {
        optionsPassphrase.value = "";
    } else {
        setTimeout(() => { optionsPassphrase.value = ""; }, 0);
    }
};

const generateKeys = () => {

    const optionsTypeValue = optionsType.value;
    const optionsKeySizeValue = optionsKeySize.value;
    const optionsNameValue = optionsName.value.trim();
    const optionsEmailValue = optionsEmail.value.trim();
    const optionsPassphraseValue = optionsPassphrase.value;
    const optionsExpirationTimeValue = optionsExpirationTime.value;

    const optionsObject = {
        optionsTypeValue,
        optionsKeySizeValue, optionsNameValue,
        optionsEmailValue, optionsPassphraseValue,
        optionsExpirationTimeValue
    };

    if (!optionsEmail.checkValidity()) {
        showError("Please enter a valid email address.");
        return;
    }

    clearError();

    copyPrivateKeyButton.classList.remove("copy-button");
    copyPublicKeyButton.classList.remove("copy-button");
    copyRevocationCertificateButton.classList.remove("copy-button");

    downloadPrivateKeyButton.classList.remove("download-button");
    downloadPublicKeyButton.classList.remove("download-button");
    downloadRevocationCertificateButton.classList.remove("download-button");

    buttonGenerateKeys.disabled = true;
    buttonGenerateKeys.innerText = "Generating...";

    copyPrivateKeyButton.disabled = true;
    copyPublicKeyButton.disabled = true;
    copyRevocationCertificateButton.disabled = true;
    downloadPrivateKeyButton.disabled = true;
    downloadPublicKeyButton.disabled = true;
    downloadRevocationCertificateButton.disabled = true;

    worker.postMessage(optionsObject);

};

// ── Event listeners ────────────────────────────────────────────────────────
buttonGenerateKeys.addEventListener("click", generateKeys);
optionsType.addEventListener("change", function () { keyAlgorithmChanged(this); });

copyPrivateKeyButton.addEventListener("click", function () { copyToClipboard(this); });
copyPublicKeyButton.addEventListener("click", function () { copyToClipboard(this); });
copyRevocationCertificateButton.addEventListener("click", function () { copyToClipboard(this); });

downloadPrivateKeyButton.addEventListener("click", function () { downloadFile(this); });
downloadPublicKeyButton.addEventListener("click", function () { downloadFile(this); });
downloadRevocationCertificateButton.addEventListener("click", function () { downloadFile(this); });

optionsEmail.addEventListener("input", clearError);

// ── WebMCP (Chrome Canary navigator.modelContext) ──────────────────────────
// Registers a generate_pgp_keys tool so in-browser AI agents can call it.
// Gracefully does nothing on browsers that don't support the API yet.
//
// SECURITY NOTES:
//  - The tool NEVER returns private key material or the revocation
//    certificate to the agent. Those stay in the page UI for the human user
//    to copy/download. Returning them would let an AI agent (or a prompt
//    injection against one) exfiltrate secrets or revoke keys.
//  - Arguments are validated against whitelists before touching the form,
//    and invalid values fall back to safe defaults instead of silently
//    corrupting generation.
//  - Calls are serialized through a queue so two concurrent tool calls can
//    never cross-resolve each other's promises.
if (typeof navigator !== 'undefined' && navigator.modelContext) {

    const MCP_VALID_TYPES = ['ecc', 'rsa'];
    const MCP_VALID_KEY_SIZES = ['2048', '4096'];
    const MCP_VALID_EXPIRATIONS = ['0', '31536000', '63072000', '126144000', '252288000'];
    const MCP_MAX_NAME_LEN = 200;
    const MCP_MAX_EMAIL_LEN = 254;
    const MCP_MAX_PASSPHRASE_LEN = 1024;

    const runMcpGeneration = ({ name, email, type, keySize, passphrase, expirationTime }) =>
        new Promise((resolve, reject) => {
            if (_mcpGenerationActive) {
                reject(new Error('Another key generation is already in progress. Please retry.'));
                return;
            }

            // Populate the form fields so the UI reflects the generation
            optionsName.value = name;
            optionsEmail.value = email;
            optionsType.value = type;
            keyAlgorithmChanged(optionsType);
            optionsKeySize.value = keySize;
            optionsPassphrase.value = passphrase;
            optionsExpirationTime.value = expirationTime;

            _mcpPendingResolve = resolve;
            _mcpPendingReject = reject;
            _mcpGenerationActive = true;

            try {
                generateKeys();
            } catch (err) {
                _mcpPendingResolve = null;
                _mcpPendingReject = null;
                _mcpGenerationActive = false;
                reject(err);
            }
        });

    navigator.modelContext.registerTool({
        name: 'generate_pgp_keys',
        description: 'Generate a PGP key pair (private key, public key, and revocation certificate) using OpenPGP.js. All computation happens client-side in the browser. For security, the private key and revocation certificate are NOT returned to the caller — they are displayed on the page for the user to copy or download. Only the public key and fingerprint are returned.',
        inputSchema: {
            type: 'object',
            properties: {
                name: {
                    type: 'string',
                    description: 'Full name for the PGP user ID (e.g. "Alice Smith")'
                },
                email: {
                    type: 'string',
                    description: 'Email address for the PGP user ID (e.g. "alice@example.com")'
                },
                type: {
                    type: 'string',
                    enum: ['ecc', 'rsa'],
                    description: 'Key algorithm. "ecc" uses Curve25519 (modern, fast, recommended). "rsa" uses RSA. Defaults to "ecc".'
                },
                keySize: {
                    type: 'number',
                    enum: [2048, 4096],
                    description: 'RSA key size in bits. Only used when type is "rsa". Defaults to 4096.'
                },
                passphrase: {
                    type: 'string',
                    description: 'Optional passphrase to protect the private key. Leave empty for no passphrase.'
                },
                expirationTime: {
                    type: 'number',
                    description: 'Key expiration time in seconds from now. Use 0 for no expiration. Common values: 31536000 (1 year), 63072000 (2 years). Defaults to 0.'
                }
            },
            required: ['name', 'email']
        },
        execute: async (args) => {
            args = args || {};

            // ── Validate/sanitize every argument (never trust agent input) ──
            const cleanString = (v, maxLen) =>
                typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, maxLen) : '';

            const name = cleanString(args.name, MCP_MAX_NAME_LEN);
            const email = cleanString(args.email, MCP_MAX_EMAIL_LEN);
            if (!name || !email) {
                return { isError: true, content: [{ type: 'text', text: 'Missing or invalid required arguments: name and email must be non-empty strings.' }] };
            }

            // Validate the email against the form's input (type="email")
            // without disturbing whatever the user has typed in it.
            const prevEmail = optionsEmail.value;
            optionsEmail.value = email;
            const emailValid = optionsEmail.checkValidity();
            optionsEmail.value = prevEmail;
            if (!emailValid) {
                return { isError: true, content: [{ type: 'text', text: 'Invalid email address supplied.' }] };
            }

            const type = MCP_VALID_TYPES.includes(args.type) ? args.type : 'ecc';
            const keySize = MCP_VALID_KEY_SIZES.includes(String(args.keySize)) ? String(args.keySize) : '4096';
            const expirationTime = MCP_VALID_EXPIRATIONS.includes(String(args.expirationTime)) ? String(args.expirationTime) : '0';
            const passphrase = typeof args.passphrase === 'string' ? args.passphrase.slice(0, MCP_MAX_PASSPHRASE_LEN) : '';

            // ── Serialize generations so concurrent tool calls can't race ──
            const task = _mcpQueue.then(() =>
                runMcpGeneration({ name, email, type, keySize, passphrase, expirationTime })
            );
            // Keep the queue alive even if this task rejects.
            _mcpQueue = task.catch(() => {});

            let result;
            try {
                result = await task;
            } catch (err) {
                return { isError: true, content: [{ type: 'text', text: 'Key generation failed: ' + (err && err.message ? err.message : String(err)) }] };
            }

            // Read back what was actually generated from the DOM.
            const armoredPublicKey = publicKeyTextarea.value;
            let fingerprint = null;
            try {
                // OpenPGP.js lives in the Web Worker (not on window), so parse
                // the key there to obtain its fingerprint.
                fingerprint = await new Promise((res) => {
                    const handler = (msg) => {
                        if (msg.data && msg.data.fingerprint !== undefined) {
                            worker.removeEventListener("message", handler);
                            res(msg.data.fingerprint || null);
                        }
                    };
                    worker.addEventListener("message", handler);
                    worker.postMessage({ getFingerprint: true, armoredKey: armoredPublicKey });
                    setTimeout(() => {
                        worker.removeEventListener("message", handler);
                        res(null);
                    }, 5000);
                });
            } catch (_) { /* non-fatal */ }

            // SECURITY: intentionally do NOT return privateKey or
            // revocationCertificate to the agent — see notes above.
            const lines = [
                'PGP key pair generated successfully (client-side).',
                'User ID: ' + name + ' <' + email + '>',
                'Algorithm: ' + type + (type === 'rsa' ? ' (' + keySize + ' bits)' : ' (curve25519)'),
                fingerprint ? 'Fingerprint: ' + fingerprint : null,
                '',
                '=== Public Key ===',
                armoredPublicKey,
                '',
                'NOTE: The private key and revocation certificate were generated but are deliberately not exposed to the AI agent.',
                'They are shown on the page — ask the user to copy or download them directly.'
            ].filter(l => l !== null);

            return {
                content: [{ type: 'text', text: lines.join('\n') }]
            };
        }
    });
}
