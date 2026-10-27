// Shared public fixture contract. Credentials are reinjected by test processes;
// exports and checked-in migration artifacts contain public options only.
export const microsoftClientID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
export const directoryTenant = '11111111-1111-4111-8111-111111111111';
export const upstreamSecret = 'm24-upstream-secret-not-for-production';
export const personalOptions = { client_id: microsoftClientID, strategy_version: 2 };
export const organizationOptions = { client_id: microsoftClientID, identity_api: 'microsoft-identity-platform-v2.0', waad_protocol: 'openid-connect', userid_attribute: 'oid' };
export const emailConnections = [
 {name:'microsoft-personal',strategy:'windowslive',options:personalOptions},
 {name:'microsoft-directory',strategy:'waad',options:{...organizationOptions,useCommonEndpoint:false,tenant_domain:directoryTenant}},
 {name:'microsoft-organizations',strategy:'waad',options:{...organizationOptions,useCommonEndpoint:true}},
 {name:'google-oauth2',strategy:'google-oauth2',options:{client_id:'m24-upstream-client',email:true,profile:true}},
];
export const personas = [
 ['microsoft-directory','11111111-1111-4111-8111-111111111111','work','waad|microsoft-directory|aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','shared@enterprise.test'],
 ['microsoft-directory','11111111-1111-4111-8111-111111111111','school','waad|microsoft-directory|bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','shared@enterprise.test'],
 ['microsoft-personal','consumers','outlook','windowslive|Sub-outlook','person@outlook.com'],
 ['microsoft-personal','consumers','hotmail','windowslive|Sub-hotmail','person@hotmail.com'],
 ['google-oauth2','google','gmail','google-oauth2|gmail','gmail@gmail.com'],
 ['google-oauth2','google','workspace','google-oauth2|workspace','workspace@enterprise.test'],
 ['google-oauth2','google','nongmail','google-oauth2|nongmail','google@example.test'],
 ['microsoft-directory','11111111-1111-4111-8111-111111111111','noemail','waad|microsoft-directory|cccccccc-cccc-4ccc-8ccc-cccccccccccc',undefined],
 ['microsoft-organizations','organizations','work','waad|microsoft-organizations|11111111-1111-4111-8111-111111111111:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','shared@enterprise.test'],
];
