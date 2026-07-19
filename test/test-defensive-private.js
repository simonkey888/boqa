'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { DefensiveValidationService } = require('../lib/defensive-validation');
const { createBillingAuth, MAX_FAILURES } = require('../lib/billing-auth');

function response() { return { statusCode: 200, headers: {}, body: null, set(k,v){this.headers[k]=v;return this}, status(n){this.statusCode=n;return this}, json(v){this.body=v;return this} }; }
async function run() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'boqa-defensive-'));
  const allowlist = path.join(tmp, 'assets.json');
  fs.writeFileSync(allowlist, JSON.stringify({ validation_mode:'DEFENSIVE_VALIDATION', assets:[{ id:'lab', type:'fixture_local', ownership_status:'verified', authorization_status:'verified', scope_status:'in_scope', environment_type:'owned_or_lab', validation_mode:'non_destructive', checks:['availability','schema'] }] }));
  const engine = new DefensiveValidationService({ allowlistPath:allowlist, statePath:path.join(tmp,'state.json'), intervalMs:999999 });
  const status = await engine.runCycle();
  assert.equal(status.scheduler_status, 'ACTIVE'); assert.equal(status.controls_completed, 2); assert.equal(status.activity[0].asset, 'Laboratorio controlado'); assert.equal(status.evidence[0].integrity, 'valid');
  assert.equal(engine.authorize({ type:'owned_service' }).allowed, false);
  assert.equal(engine.authorize({ type:'owned_service', ownership_status:'verified', authorization_status:'verified', scope_status:'in_scope', environment_type:'owned_or_lab', validation_mode:'non_destructive', authorization_evidence:'doc' }).allowed, true);
  const owned={ type:'owned_service', ownership_status:'verified', authorization_status:'verified', scope_status:'in_scope', environment_type:'owned_or_lab', validation_mode:'non_destructive', authorization_evidence:'doc', allowed_origins:['https://owned.invalid'] };
  assert.equal(engine.authorizeRedirect(owned,'https://outside.invalid/path').reason,'REDIRECT_OUT_OF_SCOPE');
  const duplicate = engine.running.add('lab'); assert.equal((await engine.validate({ id:'lab', type:'fixture_local', ownership_status:'verified', authorization_status:'verified', scope_status:'in_scope', environment_type:'owned_or_lab', validation_mode:'non_destructive' })).reason, 'DUPLICATE_EXECUTION'); engine.running.delete('lab');
  const recovered = new DefensiveValidationService({ allowlistPath:allowlist, statePath:path.join(tmp,'state.json') }); assert.equal(recovered.state.recovered_after_restart, true);

  process.env.BOQA_BILLING_PIN='test-only-pin'; const auth=createBillingAuth({secure:true}); const req={ip:'local',headers:{cookie:''},body:{pin:'wrong'},get(){return null}};
  for(let i=0;i<MAX_FAILURES;i++){const res=response();auth.authenticate(req,res);assert.ok([401,429].includes(res.statusCode))} const blocked=response();auth.authenticate({...req,body:{pin:'test-only-pin'}},blocked);assert.equal(blocked.statusCode,429);
  const auth2=createBillingAuth({secure:true}); const ok=response();auth2.authenticate({...req,body:{pin:'test-only-pin'}},ok);assert.equal(ok.statusCode,200);assert.match(ok.headers['Set-Cookie'],/HttpOnly/);assert.match(ok.headers['Set-Cookie'],/SameSite=Strict/);assert.match(ok.headers['Set-Cookie'],/Secure/);assert.doesNotMatch(ok.headers['Set-Cookie'],/test-only-pin/);
  const cookie=ok.headers['Set-Cookie'].split(';')[0]; const privateReq={headers:{cookie},get(name){return name==='X-CSRF-Token'?ok.body.csrf_token:null}}; let passed=false;auth2.requireSession(privateReq,response(),()=>passed=true);assert.equal(passed,true);const logout=response();auth2.logout(privateReq,logout);passed=false;auth2.requireSession(privateReq,response(),()=>passed=true);assert.equal(passed,false);
  passed=false;auth2.requireSession({headers:{cookie:'boqa_billing_session=tampered'}},response(),()=>passed=true);assert.equal(passed,false);
  delete process.env.BOQA_BILLING_PIN; fs.rmSync(tmp,{recursive:true,force:true}); console.log('defensive/private: PASS');
}
run().catch(e=>{console.error(e);process.exit(1)});
