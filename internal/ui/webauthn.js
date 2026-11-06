(() => {
  "use strict";
  const data = document.getElementById("za-webauthn");
  if (!data || !window.PublicKeyCredential || !navigator.credentials) return;
  const config = JSON.parse(data.textContent);
  const form = document.getElementById("za-passkey-form");
  const button = document.getElementById("za-passkey-button");
  let pending = null;
  let generation = 0;
  let submitted = false;
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  function abort() {
    generation++;
    if (pending) pending.abort();
    pending = null;
  }
  document.addEventListener("submit", () => { submitted = true; abort(); }, true);
  function options() {
    if (config.operation === "create") {
      if (PublicKeyCredential.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(config.publicKey);
      return {...config.publicKey, challenge: decode(config.publicKey.challenge), user: {...config.publicKey.user, id: decode(config.publicKey.user.id)}, excludeCredentials: (config.publicKey.excludeCredentials || []).map(c => ({...c, id: decode(c.id)}))};
    }
    if (PublicKeyCredential.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(config.publicKey);
    const result = {...config.publicKey, challenge: decode(config.publicKey.challenge)};
    result.allowCredentials = (result.allowCredentials || []).map(c => ({...c, id: decode(c.id)}));
    return result;
  }
  function post(name, value) {
    if (submitted) return;
    submitted = true;
    abort();
    form.elements[name].value = value;
    form.action = config.operation === "create" ? "/u/signup/passkey" : "/u/login/passkey";
    form.submit();
  }
  async function get(conditional) {
    abort();
    if (submitted) return;
    const serial = generation;
    const controller = new AbortController();
    pending = controller;
    try {
      const credential = await navigator.credentials[config.operation === "create" ? "create" : "get"]({publicKey: options(), signal: controller.signal, ...(conditional ? {mediation: "conditional"} : {})});
      if (serial !== generation || submitted || !credential) return;
      const response = credential.response;
      const result = config.operation === "create" ? {clientDataJSON: encode(response.clientDataJSON), attestationObject: encode(response.attestationObject), transports: response.getTransports ? response.getTransports() : []} : {clientDataJSON: encode(response.clientDataJSON), authenticatorData: encode(response.authenticatorData), signature: encode(response.signature), userHandle: response.userHandle ? encode(response.userHandle) : null};
      post("credential", JSON.stringify({id: credential.id, rawId: encode(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment, response: result, clientExtensionResults: credential.getClientExtensionResults()}));
    } catch (error) {
      if (serial !== generation || submitted) return;
      post("webauthn_error", error instanceof DOMException ? error.name : "UnknownError");
    }
  }
  if (button) button.addEventListener("click", () => get(false));
  if (config.operation !== "create" && config.mediation !== "button" && PublicKeyCredential.isConditionalMediationAvailable) {
    const serial = generation;
    PublicKeyCredential.isConditionalMediationAvailable().then(available => {
      if (available && serial === generation && !submitted) get(true);
    }).catch(() => {});
  }
})();
