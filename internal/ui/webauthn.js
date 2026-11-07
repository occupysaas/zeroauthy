(() => {
  "use strict";
  const data = document.getElementById("za-webauthn");
  if (!data) return;
  const config = JSON.parse(data.textContent);
  const form = document.getElementById("za-passkey-form");
  const button = document.getElementById("za-passkey-button");
  if (config.operation === "detect") {
    const available = !!(window.PublicKeyCredential && navigator.credentials);
    form.elements.webauthn.value = available ? "1" : "0";
    const check = available && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable;
    Promise.resolve(check ? check.call(PublicKeyCredential) : false).catch(() => false).then(platform => {
      form.elements.platform.value = platform ? "1" : "0";
      form.submit();
    });
    return;
  }
  const skip = config.enrollment ? document.getElementById("za-passkey-skip") : null;
  if (!window.PublicKeyCredential || !navigator.credentials) {
    if (skip) {
      skip.elements.snooze.checked = false;
      skip.submit();
    }
    return;
  }
  let platformAvailable = false;
  const platform = PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable;
  const platformCheck = platform ? platform.call(PublicKeyCredential).catch(() => false) : Promise.resolve(false);
  platformCheck.then(available => {
    platformAvailable = available;
    if (skip && (!platform || (config.enrollment === "local" && !available)) && !submitted) {
      submitted = true;
      abort();
      skip.elements.snooze.checked = false;
      skip.submit();
    }
  });
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
    if (!config.enrollment && !config.mfa) form.action = config.operation === "create" ? "/u/signup/passkey" : "/u/login/passkey";
    if (form.elements.platform_available) form.elements.platform_available.value = platformAvailable ? "1" : "0";
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
      platformAvailable = await platformCheck;
      if (serial !== generation || submitted) return;
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
