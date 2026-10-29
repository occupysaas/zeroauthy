import {readFile} from 'node:fs/promises';
export {api,token,primary,fixtureFetch,fixtureDispatcher} from '../social/client.mjs';
export const email='organizations-user@e2e.local';
export const password='Plan29-User-Password-2026';
export const decode=raw=>JSON.parse(Buffer.from(raw.split('.')[1],'base64url'));
export const state=async()=>JSON.parse(await readFile(process.env.E2E_M29_STATE,'utf8'));
