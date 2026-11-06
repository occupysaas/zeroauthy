import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source = fs.readFileSync(new URL("webauthn.js", import.meta.url), "utf8");
const tick = () => new Promise(resolve => setImmediate(resolve));
function harness(mode = "both", supported = true, creation = false) {
  const calls = [], posts = [], listeners = {};
  const form = {elements: {credential: {value: ""}, webauthn_error: {value: ""}}, submit() {posts.push({credential: this.elements.credential.value, error: this.elements.webauthn_error.value, action: this.action});}};
  const button = {addEventListener(name, fn) {listeners.click = fn;}};
  const pk = {isConditionalMediationAvailable: async () => true};
  const data = {textContent: JSON.stringify({challenge_id: "id", publicKey: creation ? {challenge: "AQID", rp: {id:"a.test"}, user: {id:"BAU",name:"new@a.test",displayName:"New"}, excludeCredentials: [{type:"public-key",id:"Bgc"}]} : {challenge: "AQID", rpId: "a.test", allowCredentials: []}, mediation: mode, operation: creation ? "create" : undefined, action: creation ? "/u/signup/passkey" : undefined})};
  const context = {Uint8Array, ArrayBuffer, AbortController, DOMException, atob, btoa, PublicKeyCredential: pk, window: supported ? {PublicKeyCredential: pk} : {}, navigator: {credentials: {create(options) {return new Promise((resolve, reject) => calls.push({options, resolve, reject}));}, get(options) {return new Promise((resolve, reject) => calls.push({options, resolve, reject}));}}}, document: {getElementById(id) {return id === "za-webauthn" ? data : id === "za-passkey-form" ? form : mode !== "autofill" ? button : null;}, addEventListener(name, fn) {listeners[name] = fn;}}};
  vm.runInNewContext(source, context);
  return {calls, posts, listeners};
}
const credential = {id: "id", rawId: new Uint8Array([1]).buffer, type: "public-key", response: {clientDataJSON: new Uint8Array([2]).buffer, authenticatorData: new Uint8Array([3]).buffer, signature: new Uint8Array([4]).buffer, userHandle: new Uint8Array([5]).buffer}, getClientExtensionResults: () => ({})};
test("button aborts conditional request and only current ceremony posts", async () => {
  const h = harness(); await tick(); assert.equal(h.calls.length, 1); assert.equal(h.calls[0].options.mediation, "conditional");
  h.listeners.click(); assert.equal(h.calls[0].options.signal.aborted, true); assert.equal(h.calls.length, 2);
  h.calls[0].resolve(credential); h.calls[1].resolve(credential); await tick(); assert.equal(h.posts.length, 1); assert.equal(h.posts[0].action, "/u/login/passkey"); assert.equal(JSON.parse(h.posts[0].credential).response.userHandle, "BQ");
});
test("ordinary identifier submit aborts conditional and prevents late result", async () => {
  const h = harness(); await tick(); h.listeners.submit(); assert.equal(h.calls[0].options.signal.aborted, true); h.calls[0].resolve(credential); await tick(); assert.equal(h.posts.length, 0);
});
test("rapid explicit clicks keep exactly one active assertion", async () => {
  const h = harness("button"); h.listeners.click(); h.listeners.click(); assert.equal(h.calls[0].options.signal.aborted, true); h.calls[0].reject(new DOMException("secret", "AbortError")); h.calls[1].resolve(credential); await tick(); assert.equal(h.posts.length, 1);
});
test("browser failures post the exception name only", async () => {
  const h = harness("button"); h.listeners.click(); h.calls[0].reject(new DOMException("private message", "SecurityError")); await tick(); assert.deepEqual(h.posts, [{credential: "", error: "SecurityError", action: "/u/login/passkey"}]);
});
test("autofill unsupported leaves ordinary form usable", async () => {const h = harness("autofill", false); await tick(); assert.equal(h.calls.length, 0); assert.equal(h.posts.length, 0);});

test("registration decodes creation options and posts attestation through the signup form", async () => {
 const h=harness("button",true,true); h.listeners.click();
 assert.equal(h.calls.length,1); assert.deepEqual(Array.from(h.calls[0].options.publicKey.user.id),[4,5]);
 assert.deepEqual(Array.from(h.calls[0].options.publicKey.excludeCredentials[0].id),[6,7]);
 h.calls[0].resolve({...credential,response:{clientDataJSON:new Uint8Array([2]).buffer,attestationObject:new Uint8Array([3]).buffer,getTransports:()=>["internal"]}}); await tick();
 assert.equal(h.posts.length,1); assert.equal(h.posts[0].action,"/u/signup/passkey");
 const body=JSON.parse(h.posts[0].credential); assert.equal(body.response.attestationObject,"Aw"); assert.deepEqual(body.response.transports,["internal"]); assert.equal(body.response.signature,undefined);
});
test("plain password submit aborts creation and discards a late attestation",async()=>{const h=harness("button",true,true);h.listeners.click();h.listeners.submit();assert.equal(h.calls[0].options.signal.aborted,true);h.calls[0].resolve(credential);await tick();assert.equal(h.posts.length,0);});
