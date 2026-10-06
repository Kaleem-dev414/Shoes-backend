const mongoose=require('mongoose');
const express=require('express'),cors=require('cors'),fs=require('fs'),path=require('path'),bcrypt=require('bcrypt'),jwt=require('jsonwebtoken');require('dotenv').config({path:path.join(__dirname,'.env')});
const app=express(),port=process.env.PORT||process.env.port||5000,JWT_SECRET=process.env.JWT_SECRET||'change-this-secret-in-production',FRONTEND_URL=process.env.FRONTEND_URL||'',ADMIN_PIN=process.env.ADMIN_SECURITY_PIN||'',ADMIN_ENTRY_CODE=String(process.env.ADMIN_ENTRY_CODE||'').trim(),DATA_FILE=process.env.SHOES_DATA_FILE||path.join(__dirname,'data.json');
const ENV_ADMIN={username:process.env.ADMIN_USERNAME||'Kaleem Ullah Khan Durrani',email:process.env.ADMIN_EMAIL||'admin@sajidshoes.local',password:process.env.ADMIN_PASSWORD||''};
app.use(cors({origin(o,cb){const a=['http://localhost:5173','http://localhost:5174',FRONTEND_URL].filter(Boolean);if(!o||a.includes(o)||/^https:\/\/[^/]+\.vercel\.app$/.test(o))return cb(null,true);cb(new Error('CORS: frontend origin is not allowed'));},credentials:true}));app.use(express.json({limit:'100mb'}));app.use(express.urlencoded({extended:true,limit:'100mb'}));
const blankState=()=>({products:[],customers:[],bills:[],expenses:[],incomes:[],purchases:[]});
const emptyDB=()=>({state:blankState(),users:[],userStates:{},protectedSnapshots:{},adminRestoreDrafts:{},archives:{},deletedUsers:[],restoreNotices:{},resetRequests:[],settings:{}});
const recordCount=s=>Object.values(s||{}).reduce((n,a)=>n+(Array.isArray(a)?a.length:0),0);
function protectSnapshot(db,id,state,reason){if(!recordCount(state))return;db.protectedSnapshots=db.protectedSnapshots||{};const copy=structuredClone(state);const digest=require("crypto").createHash("sha256").update(JSON.stringify(copy)).digest("hex");if(db.protectedSnapshots[id]?.digest===digest)return;const prior=db.protectedSnapshots[id];db.protectedSnapshots[id]={state:copy,digest,createdAt:new Date().toISOString(),reason};}
function bestProtectedState(db,id){const current=db.userStates[id]||blankState();const protectedState=db.protectedSnapshots?.[id]?.state;/* The live account is authoritative while it has records. A larger historical snapshot must not silently undo intentional edits. */return recordCount(current)?current:(protectedState||current);}
// Admin retention is independent of live/user View Data. User removals never remove saved rows.
function mergeAdminRows(target, incoming){
 for(const section of Object.keys(blankState())){
  const rows=target[section]||(target[section]=[]);
  for(const row of incoming?.[section]||[]){const key=row.id==null?JSON.stringify(row):String(row.id);const index=rows.findIndex(r=>(r.id==null?JSON.stringify(r):String(r.id))===key);if(index<0)rows.push(structuredClone(row));else rows[index]=structuredClone(row);}
 }
 return target;
}
function ensureAdminSaved(db,id){
 db.adminSavedStates=db.adminSavedStates||{};
 if(!db.adminSavedStates[id]){
  const state=blankState();
  // Seed existing installations from their latest recovery copy and live state.
  for(const source of [db.protectedSnapshots?.[id]?.state,db.viewDataStates?.[id]?.state,db.adminRestoreDrafts?.[id]?.state,db.userStates?.[id]])mergeAdminRows(state,source);
  db.adminSavedStates[id]={state,updatedAt:new Date().toISOString()};
 }
 return db.adminSavedStates[id];
}
function bestAdminState(db,id){return ensureAdminSaved(db,id).state;}
function retainAdminRecords(db,previousDB,skipId){
 for(const [id,state] of Object.entries(db.userStates||{})){
  if(String(id)===String(skipId))continue;
  if(!db.adminSavedStates?.[id]){const prior=structuredClone(previousDB||db);ensureAdminSaved(prior,id);db.adminSavedStates=db.adminSavedStates||{};db.adminSavedStates[id]=prior.adminSavedStates[id];}
  const saved=ensureAdminSaved(db,id),old=previousDB?.userStates?.[id]||blankState(),changed=blankState();
  const content=r=>{const copy=structuredClone(r);delete copy.createdAt;delete copy.updatedAt;delete copy.stockUpdatedAt;return JSON.stringify(copy);};
  for(const section of Object.keys(blankState()))for(const row of state[section]||[]){const before=(old[section]||[]).find(r=>r.id!=null&&String(r.id)===String(row.id));if(!before||content(before)!==content(row))changed[section].push(row);}
  if(recordCount(changed)){mergeAdminRows(saved.state,changed);saved.updatedAt=new Date().toISOString();}
 }
}
let liveDB=null, mongoWrites=Promise.resolve();
const StoredDB=mongoose.model('AppDatabase',new mongoose.Schema({_id:String,payload:mongoose.Schema.Types.Mixed},{strict:false,versionKey:false}));

async function persistMongoSnapshot(snapshot){
 const compressed=require('zlib').gzipSync(Buffer.from(JSON.stringify(snapshot)),{level:4}),generation=require('crypto').randomUUID(),chunkIds=[];
 for(let start=0,index=0;start<compressed.length;start+=6*1024*1024,index++){const id='snapshot-'+generation+'-'+index;await StoredDB.replaceOne({_id:id},{_id:id,payload:{data:compressed.subarray(start,start+6*1024*1024).toString('base64')}},{upsert:true});chunkIds.push(id);}
 const previous=await StoredDB.findById('main').lean();await StoredDB.replaceOne({_id:'main'},{_id:'main',payload:{storageFormat:'shoes-compressed-chunks-v1',chunkIds}},{upsert:true});
 if(previous?.payload?.storageFormat==='shoes-compressed-chunks-v1')try{await StoredDB.deleteMany({_id:{$in:previous.payload.chunkIds}});}catch(error){console.error('Old snapshot cleanup deferred:',error.message);}
}
async function loadMongoSnapshot(payload){
 if(payload?.storageFormat!=='shoes-compressed-chunks-v1')return payload;
 const parts=[];for(const id of payload.chunkIds){const row=await StoredDB.findById(id).lean();if(!row?.payload?.data)throw Error('Saved database snapshot is incomplete.');parts.push(Buffer.from(row.payload.data,'base64'));}return JSON.parse(require('zlib').gunzipSync(Buffer.concat(parts)).toString('utf8'));
}
function readDB(){if(liveDB)return structuredClone(liveDB);try{return Object.assign(emptyDB(),JSON.parse(fs.readFileSync(DATA_FILE,'utf8')))}catch{return emptyDB()}}

const ACCOUNT_SECTIONS=['products','customers','bills','expenses','incomes','purchases'];
function recordSummary(row){return {id:row.id,name:row.name,code:row.code,number:row.number,desc:row.desc,customer:row.customer,amount:row.amount,total:row.total,paid:row.paid,remaining:row.remaining,qty:row.qty,stock:row.stock,date:row.date,items:(row.items||[]).map(i=>({id:i.id,code:i.code,name:i.name,size:i.size,qty:i.qty,price:i.price})),returns:(row.returns||[]).map(r=>({id:r.id,date:r.date,amount:r.amount,refund:r.refund,khataReduction:r.khataReduction,items:(r.items||[]).map(i=>({id:i.id,size:i.size,qty:i.qty,price:i.price}))})),allocations:row.allocations};}
function stampAccountChanges(db,previousDB,skipActivityUserId){
 const now=new Date().toISOString();db.recordActivity=db.recordActivity||{};
 for(const [userId,state] of Object.entries(db.userStates||{})){
  const old=previousDB?.userStates?.[userId]||{};const events=[];
  for(const section of ACCOUNT_SECTIONS){const prior=new Map((old[section]||[]).map(r=>[String(r.id),r]));
   for(const row of state[section]||[]){const before=prior.get(String(row.id));prior.delete(String(row.id));
    const comparable=r=>{const c=structuredClone(r);delete c.createdAt;delete c.updatedAt;delete c.stockUpdatedAt;return JSON.stringify(c);};
    const changed=!before||comparable(before)!==comparable(row);
    row.createdAt=before?.createdAt||row.createdAt||(!before?now:null);row.updatedAt=changed?now:(before?.updatedAt||row.updatedAt||null);
    if(section==='products'&&(!before||JSON.stringify(before.stock)!==JSON.stringify(row.stock)))row.stockUpdatedAt=now;else if(section==='products')row.stockUpdatedAt=before?.stockUpdatedAt||row.stockUpdatedAt||null;
    if(section==='bills')for(const r of row.returns||[]){const oldReturn=(before?.returns||[]).find(x=>String(x.id)===String(r.id));r.createdAt=oldReturn?.createdAt||r.createdAt||(!oldReturn?now:null);r.updatedAt=!oldReturn||JSON.stringify(oldReturn.items)!==JSON.stringify(r.items)||oldReturn.amount!==r.amount?now:oldReturn.updatedAt;}
    if(changed&&String(userId)!==String(skipActivityUserId))events.push({id:require('crypto').randomUUID(),section,recordId:row.id,action:before?'edit':'add',date:now,before:before?recordSummary(before):null,after:recordSummary(row)});
   }

  }
  db.recordActivity[userId]=[...(db.recordActivity[userId]||[]).filter(event=>event.action!=='delete'&&(state[event.section]||[]).some(row=>String(row.id)===String(event.recordId))),...events];
 }
}

function writeDB(db,skipActivityUserId,skipAdminRetentionId){const previous=liveDB||readDB();stampAccountChanges(db,previous,skipActivityUserId);retainAdminRecords(db,previous,skipAdminRetentionId);liveDB=structuredClone(db);fs.writeFileSync(DATA_FILE,JSON.stringify(db,null,2));if(mongoose.connection.readyState===1){const snapshot=structuredClone(db);mongoWrites=mongoWrites.catch(e=>console.error('Previous database save failed:',e)).then(()=>persistMongoSnapshot(snapshot));}}
 function tok(p,e='7d'){return jwt.sign(p,JWT_SECRET,{expiresIn:e})}
function auth(req,res,next){
 try{req.user=jwt.verify((req.headers.authorization||'').replace(/^Bearer\s+/i,''),JWT_SECRET);}
 catch{return res.status(401).json({message:'Unauthorized'});}
 if(req.user.role==='user'){
  const user=readDB().users.find(u=>String(u.id)===String(req.user.id));
  if(!user||!user.approved)return res.status(403).json({message:'Account unavailable or deleted.'});
  if(user.accessEnabled===false&&req.path!=='/api/auth/me')return res.status(403).json({code:'ACCOUNT_DISABLED',message:'Your account is OFF. Contact your admin.'});
 }
 next();
}
function adminOnly(req,res,next){if(req.user.role!=='admin')return res.status(403).json({message:'Admin only'});next()}
const ACCOUNT_PAGES=['dashboard','sale','products','stock','purchases','customers','khata','bills','income','reports'];

async function adminCreds(db){if(!db.settings.adminPasswordHash)db.settings.adminPasswordHash=await bcrypt.hash(ENV_ADMIN.password,10);return {username:db.settings.adminUsername||ENV_ADMIN.username,email:db.settings.adminEmail||ENV_ADMIN.email,passwordHash:db.settings.adminPasswordHash}}
const publicUser=u=>({id:u.id,username:u.username,email:u.email,approved:u.approved,accessEnabled:u.accessEnabled!==false,shopName:/^sajid\s+shoes$/i.test(u.shopName||'')?'Shoes':(u.shopName||'Shoes'),shopLogo:u.shopLogo||'',requestedShopName:u.requestedShopName||'',shopAddress:u.shopAddress||'',shopContact:u.shopContact||'',contactChangePending:null,allowSelfReset:!!u.allowSelfReset,lowStockAlertsEnabled:u.lowStockAlertsEnabled!==false,pages:Object.fromEntries(ACCOUNT_PAGES.map(page=>[page,u.accessEnabled!==false])),createdAt:u.createdAt});
// Cloudinary secrets remain on the backend; browsers receive only photo URLs.
// Cloudinary is built into this server; no separate cloudinary.cjs file is required.
const {cloudinaryConfig,uploadImage}=(()=>{
const crypto=require('node:crypto');
function cloudinaryConfig(env=process.env){
 let config={cloudName:env.CLOUDINARY_CLOUD_NAME,apiKey:env.CLOUDINARY_API_KEY,apiSecret:env.CLOUDINARY_API_SECRET};
 if(env.CLOUDINARY_URL){try{const u=new URL(env.CLOUDINARY_URL);if(u.protocol==='cloudinary:')config={cloudName:u.hostname,apiKey:decodeURIComponent(u.username),apiSecret:decodeURIComponent(u.password),...Object.fromEntries(Object.entries(config).filter(([,v])=>v))};}catch{}}
 for(const k of Object.keys(config))config[k]=String(config[k]||'').trim();
 return {...config,configured:!!(config.cloudName&&config.apiKey&&config.apiSecret&&/^[a-zA-Z0-9_-]+$/.test(config.cloudName))};
}
function imageData(value){
 const match=String(value||'').match(/^data:image\/(jpeg|png|webp|gif);base64,([A-Za-z0-9+/]+={0,2})$/);
 if(!match){const e=Error('Choose a JPG, PNG, WebP or GIF photo.');e.status=400;throw e;}
 const bytes=Buffer.from(match[2],'base64');
 if(!bytes.length||bytes.length>5*1024*1024){const e=Error('Photo must be 5 MB or smaller.');e.status=413;throw e;}
 const valid=match[1]==='jpeg'?bytes.subarray(0,3).equals(Buffer.from([255,216,255])):match[1]==='png'?bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])):match[1]==='gif'?/^GIF8[79]a$/.test(bytes.subarray(0,6).toString()):bytes.subarray(0,4).toString()==='RIFF'&&bytes.subarray(8,12).toString()==='WEBP';
 if(!valid){const e=Error('The selected file is not a valid image.');e.status=400;throw e;}
 return bytes;
}
async function uploadImage(data,userId,category='products',options={}){
 const bytes=imageData(data),config=cloudinaryConfig(options.env||process.env);
 if(!config.configured){const e=Error('Cloudinary is not configured. Add CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET to the backend environment.');e.status=503;e.code='CLOUDINARY_NOT_CONFIGURED';throw e;}
 const owner=String(userId).replace(/[^a-zA-Z0-9_-]/g,'_'),kind=category==='customers'?'customers':'products';
 const params={overwrite:'false',public_id:'shoes/users/'+owner+'/'+kind+'/'+crypto.createHash('sha256').update(bytes).digest('hex'),timestamp:String(Math.floor(Date.now()/1000))};
 const signed=Object.keys(params).sort().map(k=>k+'='+params[k]).join('&');
 const form=new FormData();for(const [k,v] of Object.entries(params))form.set(k,v);
 form.set('file',data);form.set('api_key',config.apiKey);form.set('signature',crypto.createHash('sha1').update(signed+config.apiSecret).digest('hex'));
 let response;
 try{response=await (options.fetch||fetch)('https://api.cloudinary.com/v1_1/'+encodeURIComponent(config.cloudName)+'/image/upload',{method:'POST',body:form,signal:AbortSignal.timeout(45000)});}
 catch{const e=Error('Cloudinary could not be reached. Please retry the photo upload.');e.status=502;throw e;}
 let result;try{result=await response.json();}catch{const e=Error('Cloudinary returned an invalid response. Please retry.');e.status=502;throw e;}
 if(!response.ok){const e=Error('Cloudinary upload failed. Check the backend Cloudinary settings and account upload limits.');e.status=502;throw e;}
 if(!result.secure_url||!/^https:\/\/res\.cloudinary\.com\//.test(result.secure_url)){const e=Error('Cloudinary did not return a secure photo URL.');e.status=502;throw e;}
 return {url:result.secure_url,secure_url:result.secure_url,public_id:result.public_id,width:result.width,height:result.height,provider:'cloudinary'};
}
return {cloudinaryConfig,imageData,uploadImage};

})();
app.get('/api/media/status',auth,(req,res)=>res.json({configured:cloudinaryConfig().configured,mode:'cloudinary'}));
app.post('/api/media/images',auth,async(req,res)=>{
 if(!['user','admin'].includes(req.user.role))return res.status(403).json({message:'Sign in to upload photos.'});
 try{const image=await uploadImage(req.body.image||req.body.dataUri,req.user.id||'admin',req.body.category);res.status(201).json(image);}
 catch(error){res.status(error.status||502).json({message:error.message,code:error.code||'PHOTO_UPLOAD_FAILED'});}
});
app.get('/health',(_q,r)=>r.json({ok:true,service:'Shoes API'}));app.get('/api/health',(_q,r)=>r.json({ok:true,version:'shoes-manage-data-20261005-v2',features:['manage-data','activity-history']}));
app.post('/api/auth/register',(_req,res)=>res.status(403).json({message:'Only the admin can create user accounts.'}));
app.post('/api/admin/users',auth,adminOnly,async(req,res)=>{const username=String(req.body.username||'').trim(),email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');if(!username||!email||password.length<6)return res.status(400).json({message:'Email, username and a password of at least 6 characters are required.'});const db=readDB();if(db.users.some(u=>u.username.toLowerCase()===username.toLowerCase()||u.email===email))return res.status(409).json({message:'Email or username already exists.'});const requestedShopName=String(req.body.requestedShopName||'Shoes').trim().slice(0,65)||'Shoes';const id=Date.now().toString();db.users.push({id,username,email,requestedShopName,shopName:requestedShopName,shopLogo:'',shopAddress:'',shopContact:'',contactChangePending:null,passwordHash:await bcrypt.hash(password,10),approved:true,pages:Object.fromEntries(['dashboard','sale','products','stock','purchases','customers','khata','bills','income','reports'].map(x=>[x,true])),createdAt:new Date().toISOString()});db.userStates[id]=blankState();db.archives[id]=[];writeDB(db);res.status(201).json({ok:true,message:'Account created. User can now log in.'})});
app.post('/api/auth/login',async(req,res)=>{const login=String(req.body.login||req.body.username||'').trim().toLowerCase(),password=String(req.body.password||''),db=readDB(),u=db.users.find(x=>x.username.toLowerCase()===login||x.email===login);if(!u||!await bcrypt.compare(password,u.passwordHash))return res.status(401).json({message:'Invalid email/username or password.'});if(!u.approved)return res.status(403).json({message:'Your account is waiting for admin approval.'});res.json({token:tok({id:u.id,username:u.username,role:'user'}),user:{...publicUser(u),role:'user'}})});
app.post('/api/auth/admin/access-code',(req,res)=>{if(!ADMIN_ENTRY_CODE)return res.status(503).json({message:'Admin verification is not configured. Copy your previous .env into the backend folder, check ADMIN_ENTRY_CODE, then restart the backend.'});if(String(req.body.code||'').trim()!==ADMIN_ENTRY_CODE)return res.status(401).json({message:'Incorrect admin verification code. Use the code configured in backend/.env (ADMIN_ENTRY_CODE).'});res.json({ok:true,gateToken:tok({role:'admin-gate'},'5m')})});
app.post('/api/auth/admin/login',async(req,res)=>{let gate;try{gate=jwt.verify(String(req.body.gateToken||''),JWT_SECRET)}catch{return res.status(401).json({message:'Admin verification is required again.'})}if(gate.role!=='admin-gate')return res.status(401).json({message:'Admin verification is required again.'});const login=String(req.body.login||req.body.username||'').trim().toLowerCase(),password=String(req.body.password||''),db=readDB(),a=await adminCreds(db);writeDB(db);if(![a.username.toLowerCase(),a.email.toLowerCase()].includes(login)||!await bcrypt.compare(password,a.passwordHash))return res.status(401).json({message:'Invalid admin email/username or password.'});res.json({ok:true,tempToken:tok({role:'admin-preverify',username:a.username},'5m')})});
app.post('/api/auth/admin/verify-pin',(req,res)=>{try{const t=jwt.verify(String(req.body.tempToken||''),JWT_SECRET);if(t.role!=='admin-preverify'||String(req.body.pin||'')!==ADMIN_PIN)throw 0;{const db=readDB();adminCreds(db).then(a=>res.json({token:tok({role:'admin',username:a.username}),user:{username:a.username,email:a.email,role:'admin'}}))}}catch{return res.status(401).json({message:'Invalid 6-digit private code.'})}});
app.get('/api/auth/me',auth,(req,res)=>{if(req.user.role==='admin')return res.json({token:tok({role:'admin',username:req.user.username}),user:{username:req.user.username,role:'admin'}});const db=readDB(),u=db.users.find(x=>x.id===req.user.id);if(!u||!u.approved)return res.status(403).json({message:'Account unavailable or not approved.'});res.json({token:tok({id:u.id,username:u.username,role:'user'}),user:{...publicUser(u),role:'user'}})});
app.get('/api/state',auth,(req,res)=>{if(req.user.role!=='user')return res.status(403).json({message:'User account required'});const db=readDB(),stored=db.userStates[req.user.id];res.json({data:stored?JSON.parse(JSON.stringify(stored)):blankState(),restoreNotice:(db.restoreNotices||{})[req.user.id]||null})});
// Saved View Data is independent of the active shop and survives a reset.
app.get('/api/state/view-data',auth,(req,res)=>{if(req.user.role!=='user')return res.status(403).json({message:'User account required'});const db=readDB(),id=req.user.id;res.json({data:structuredClone(db.viewDataStates?.[id]?.state||bestProtectedState(db,id))})});
app.post('/api/state/reset-data',auth,async(req,res)=>{try{if(req.user.role!=='user')return res.status(403).json({message:'User account required'});if(req.body?.confirmation!=='RESET DATA')return res.status(400).json({message:'Confirmation required'});const db=readDB(),id=req.user.id,previous=structuredClone(db.userStates[id]||blankState());if(recordCount(previous)){db.viewDataStates=db.viewDataStates||{};db.viewDataStates[id]={state:previous,updatedAt:new Date().toISOString()};protectSnapshot(db,id,previous,'before-reset-data');db.archives[id]=db.archives[id]||[];db.archives[id].unshift({id:'reset-data-'+Date.now(),createdAt:new Date().toISOString(),reason:'before-reset-data',state:previous});db.archives[id]=db.archives[id].slice(0,50);db.adminRestoreDrafts=db.adminRestoreDrafts||{};db.adminRestoreDrafts[id]={state:previous,updatedAt:new Date().toISOString(),edited:true};}db.userStates[id]=blankState();writeDB(db);await mongoWrites;res.json({ok:true,message:'Shop data reset. Saved View Data retained.'})}catch(e){res.status(503).json({message:'Reset could not be confirmed. Reload and check your saved data.'})}});
app.post('/api/state/restore-view-data',auth,async(req,res)=>{try{if(req.user.role!=='user')return res.status(403).json({message:'User account required'});if(req.body?.confirmReplace!==true)return res.status(400).json({message:'Confirmation required'});const db=readDB(),id=req.user.id,saved=db.viewDataStates?.[id]?.state||bestProtectedState(db,id);if(!recordCount(saved))return res.status(404).json({message:'No saved data to restore.'});db.archives[id]=db.archives[id]||[];db.archives[id].unshift({id:'restore-view-'+Date.now(),createdAt:new Date().toISOString(),state:structuredClone(db.userStates[id]||blankState())});db.archives[id]=db.archives[id].slice(0,50);db.userStates[id]=structuredClone(saved);protectSnapshot(db,id,saved,'restored-view-data');writeDB(db);await mongoWrites;res.json({ok:true,message:'Saved View Data restored to your account.'})}catch(e){res.status(503).json({message:'Restore could not be confirmed.'})}});
app.post('/api/state',auth,async(req,res)=>{try{if(req.user.role!=='user')return res.status(403).json({message:'User account required'});const db=readDB(),id=req.user.id,old=db.userStates[id]||blankState(),s=req.body||{};const next={products:Array.isArray(s.products)?s.products:[],customers:Array.isArray(s.customers)?s.customers:[],bills:Array.isArray(s.bills)?s.bills:[],expenses:Array.isArray(s.expenses)?s.expenses:[],incomes:Array.isArray(s.incomes)?s.incomes:[],purchases:Array.isArray(s.purchases)?s.purchases:[]};const oldCount=Object.values(old).reduce((n,a)=>n+(Array.isArray(a)?a.length:0),0),newCount=Object.values(next).reduce((n,a)=>n+(Array.isArray(a)?a.length:0),0);if(oldCount>0&&newCount===0&&s.allowEmptyState!==true)return res.status(409).json({message:'Empty browser state was not allowed to erase saved account data.'});if(oldCount>0&&newCount===0){db.viewDataStates=db.viewDataStates||{};db.viewDataStates[id]={state:structuredClone(old),updatedAt:new Date().toISOString()};}protectSnapshot(db,id,old,"last-synced-before-change");db.archives[id]=db.archives[id]||[];db.archives[id].unshift({id:Date.now().toString(),createdAt:new Date().toISOString(),state:JSON.parse(JSON.stringify(old))});db.archives[id]=db.archives[id].slice(0,50);db.userStates[id]=JSON.parse(JSON.stringify(next));if(!db.adminRestoreDrafts?.[id]){db.adminRestoreDrafts=db.adminRestoreDrafts||{};db.adminRestoreDrafts[id]={state:structuredClone(next),updatedAt:new Date().toISOString(),edited:false}}else if(!db.adminRestoreDrafts[id].edited){db.adminRestoreDrafts[id]={state:structuredClone(next),updatedAt:new Date().toISOString(),edited:false}}protectSnapshot(db,id,next,"latest-nonempty-sync");if(recordCount(next)){db.viewDataStates=db.viewDataStates||{};db.viewDataStates[id]={state:structuredClone(next),updatedAt:new Date().toISOString()};}writeDB(db);await mongoWrites;res.json({ok:true})}catch(e){console.error('Account save failed:',e);res.status(503).json({message:'Server could not confirm the account save. Retry when connected; do not clear your browser data.'})}});
// Explicit user reset: preserve admin recovery and a dated safety archive first.
app.post('/api/state/zero',auth,(req,res)=>res.status(403).json({message:'Only an administrator can reset a shop from Admin Control.'}));
app.post('/api/admin/users/:id/zero',auth,adminOnly,async(req,res)=>{
 try{
  if(req.body?.confirmation!=='ADMIN RESET USER SHOP')return res.status(400).json({message:'Confirmation required.'});
  const db=readDB(),id=req.params.id,u=db.users.find(x=>x.id===id);
  if(!u)return res.status(404).json({message:'User not found.'});
  const previous=structuredClone(db.userStates[id]||blankState());
  if(recordCount(previous)){
   protectSnapshot(db,id,previous,'before-admin-authorized-zero');
   db.archives[id]=db.archives[id]||[];
   db.archives[id].unshift({id:'admin-zero-'+Date.now(),createdAt:new Date().toISOString(),reason:'before-admin-authorized-zero',state:previous});
   db.archives[id]=db.archives[id].slice(0,50);
   db.adminRestoreDrafts=db.adminRestoreDrafts||{};
   db.adminRestoreDrafts[id]={state:structuredClone(previous),updatedAt:new Date().toISOString(),edited:true};
  }
  db.userStates[id]=blankState();db.restoreNotices=db.restoreNotices||{};
  db.restoreNotices[id]={restoredAt:new Date().toISOString(),message:'Admin reset this shop to zero. Please refresh your account.'};
  writeDB(db);await mongoWrites;res.json({ok:true,message:'Selected user shop reset; protected recovery retained.'});
 }catch(e){console.error(e);res.status(503).json({message:'Reset could not be confirmed.'})}
});
// Verified account backup import. Never accept a user id from the uploaded file.
app.post('/api/state/clear-reports',auth,async(req,res)=>{try{if(req.user.role!=='user')return res.status(403).json({message:'User account required'});const db=readDB(),id=req.user.id,u=db.users.find(x=>x.id===id);if(!u||!u.allowSelfReset)return res.status(403).json({message:'Ask Admin Control to authorize this destructive action.'});if(req.body?.confirmation!=='CLEAR REPORT DATA')return res.status(400).json({message:'Confirmation required'});const old=structuredClone(db.userStates[id]||blankState());if(recordCount(old)){protectSnapshot(db,id,old,'before-report-permanent-clear');db.archives[id]=db.archives[id]||[];db.archives[id].unshift({id:'report-clear-'+Date.now(),createdAt:new Date().toISOString(),reason:'before-report-permanent-clear',state:old});db.archives[id]=db.archives[id].slice(0,50);db.adminRestoreDrafts=db.adminRestoreDrafts||{};db.adminRestoreDrafts[id]={state:old,updatedAt:new Date().toISOString(),edited:true};}const next=structuredClone(old);next.bills=[];next.incomes=[];next.expenses=[];next.customers=(next.customers||[]).map(c=>({...c,balance:0}));db.userStates[id]=next;u.allowSelfReset=false;writeDB(db);await mongoWrites;res.json({ok:true,data:next,message:'Report records cleared from user account only; latest pre-clear copy retained in Admin View Data.'})}catch(e){res.status(503).json({message:'Protected clear failed; no success confirmed.'})}});
app.post('/api/state/import',auth,(req,res)=>{
 if(req.user.role!=='user')return res.status(403).json({message:'User account required'});
 const raw=req.body?.backup;
 if(!raw||raw.format!=='sajid-shoes-account-backup-v1'||!raw.state||typeof raw.state!=='object')return res.status(400).json({message:'Unsupported backup. Use a Shoes account backup exported by the admin.'});
 const keys=['products','customers','bills','expenses','incomes','purchases'];
 if(!keys.every(k=>Array.isArray(raw.state[k])))return res.status(400).json({message:'Backup data is incomplete or invalid. Existing account data is unchanged.'});
 if(!keys.some(k=>raw.state[k].length))return res.status(400).json({message:'This backup contains no records. An empty backup cannot replace an account.'});
 const db=readDB(),id=req.user.id;
 const user=db.users.find(u=>u.id===id);
 if(!user)return res.status(403).json({message:'Account unavailable.'});
 if(String(raw.userId)!==String(id))return res.status(403).json({message:'This backup belongs to another account. Ask admin for the correct backup.'});
 const digest=require('crypto').createHash('sha256').update(JSON.stringify(raw.state)).digest('hex');
 db.importHistory=db.importHistory||{};db.importHistory[id]=db.importHistory[id]||[];
 if(require('crypto').createHash('sha256').update(JSON.stringify(db.userStates[id]||blankState())).digest('hex')===digest)return res.json({ok:true,alreadyImported:true,message:'This account already matches the backup. No duplicate records were added.'});
 const current=db.userStates[id]||blankState();
 const currentCount=keys.reduce((n,k)=>n+(current[k]||[]).length,0);
 if(currentCount&&!req.body.confirmReplace)return res.status(409).json({requiresConfirmation:true,message:'This account already contains saved data. Confirm replacement; the existing data will first be saved in admin backup history.'});
 db.archives[id]=db.archives[id]||[];
 db.archives[id].unshift({id:'before-import-'+Date.now(),createdAt:new Date().toISOString(),reason:'before-user-import',state:structuredClone(current)});
 db.archives[id]=db.archives[id].slice(0,50);
 db.userStates[id]=Object.fromEntries(keys.map(k=>[k,structuredClone(raw.state[k])]));protectSnapshot(db,id,db.userStates[id],"restored-backup");
 db.importHistory[id].push(digest);db.importHistory[id]=db.importHistory[id].slice(-100);
 writeDB(db);
 // A failed database write must never be reported as a confirmed save.
 mongoWrites.then(()=>res.json({ok:true,message:'Backup restored to your account. Your previous data was saved in admin backup history.'})).catch(e=>res.status(503).json({message:'Database confirmation failed. Contact admin before trying again.'}));
});
app.get('/api/admin/users/:id/export-backup',auth,adminOnly,(req,res)=>{
 const db=readDB(),u=db.users.find(x=>x.id===req.params.id);
 if(!u)return res.status(404).json({message:'User not found'});
 res.json({format:'sajid-shoes-account-backup-v1',userId:u.id,username:u.username,createdAt:new Date().toISOString(),source:db.adminRestoreDrafts?.[u.id]?'admin-edited-draft':recordCount(db.userStates[u.id])?'current-account':'protected-admin-snapshot',state:bestAdminState(db,u.id)});
});
// One persistent, editable recovery draft per user. Editing never changes live account records.
app.get('/api/admin/users/:id/recovery-draft',auth,adminOnly,(req,res)=>{
 const db=readDB(),id=req.params.id;if(!db.users.some(u=>u.id===id))return res.status(404).json({message:'User not found'});
 const draft=db.adminRestoreDrafts?.[id];res.json({state:bestAdminState(db,id),updatedAt:draft?.updatedAt||null,edited:!!draft?.edited});
});
app.put('/api/admin/users/:id/recovery-draft',auth,adminOnly,async(req,res)=>{
 try{const db=readDB(),id=req.params.id,keys=Object.keys(blankState()),state=req.body?.state;
 if(!db.users.some(u=>u.id===id))return res.status(404).json({message:'User not found'});
 if(!state||typeof state!=='object'||Array.isArray(state)||keys.some(k=>!Array.isArray(state[k])))return res.status(400).json({message:'All six account sections must be arrays.'});
 const clean=Object.fromEntries(keys.map(k=>[k,structuredClone(state[k])]));db.adminRestoreDrafts=db.adminRestoreDrafts||{};
 db.adminRestoreDrafts[id]={state:clean,updatedAt:new Date().toISOString(),edited:true};db.adminSavedStates=db.adminSavedStates||{};db.adminSavedStates[id]={state:structuredClone(clean),updatedAt:new Date().toISOString()};writeDB(db,undefined,id);await mongoWrites;
 res.json({ok:true,message:'Recovery draft updated. Live user records remain unchanged.'});
 }catch(e){res.status(503).json({message:'Recovery draft could not be saved.'})}
});
app.post('/api/admin/users/:id/restore-draft',auth,adminOnly,async(req,res)=>{
 try{const db=readDB(),id=req.params.id,draft=ensureAdminSaved(db,id);if(!db.users.some(u=>u.id===id))return res.status(404).json({message:'User not found'});
 if(!draft)return res.status(400).json({message:'No recovery draft. Open View Data first and save an editable draft.'});
 db.archives[id]=db.archives[id]||[];db.archives[id].unshift({id:'before-draft-'+Date.now(),createdAt:new Date().toISOString(),reason:'before-admin-draft-restore',state:structuredClone(db.userStates[id]||blankState())});db.archives[id]=db.archives[id].slice(0,50);
 db.userStates[id]=structuredClone(draft.state);protectSnapshot(db,id,draft.state,'admin-draft-restore');db.restoreNotices=db.restoreNotices||{};db.restoreNotices[id]={restoredAt:new Date().toISOString(),message:'Admin restored the updated recovery data.'};writeDB(db);await mongoWrites;
 res.json({ok:true,message:'Updated recovery draft restored to the user account.'});
 }catch(e){res.status(503).json({message:'Could not confirm restoration in database.'})}
});
app.post('/api/restore-notice/read',auth,(req,res)=>{if(req.user.role!=='user')return res.status(403).json({message:'User account required'});const db=readDB();db.restoreNotices=db.restoreNotices||{};delete db.restoreNotices[req.user.id];writeDB(db);res.json({ok:true})});
app.post('/api/state/request-shop-reset',auth,(req,res)=>{if(req.user.role!=='user')return res.status(403).json({message:'User only'});const db=readDB(),u=db.users.find(x=>x.id===req.user.id);if(!u)return res.status(404).json({message:'Account not found'});db.shopResetRequests=db.shopResetRequests||[];if(db.shopResetRequests.some(r=>r.userId===u.id&&r.status==='pending'))return res.json({ok:true,message:'Your reset request is already waiting for admin approval.'});db.shopResetRequests.push({id:Date.now().toString()+'-'+u.id,userId:u.id,username:u.username,status:'pending',createdAt:new Date().toISOString()});writeDB(db);res.json({ok:true,message:'Request sent. Please ask Admin Control for approval.'})});
app.get('/api/admin/shop-reset-requests',auth,adminOnly,(req,res)=>{const db=readDB();res.json({requests:(db.shopResetRequests||[]).filter(r=>r.status==='pending')})});
app.post('/api/admin/shop-reset-requests/:id/approve',auth,adminOnly,(req,res)=>{const db=readDB(),r=(db.shopResetRequests||[]).find(x=>x.id===req.params.id&&x.status==='pending');if(!r)return res.status(404).json({message:'Pending request not found'});const u=db.users.find(x=>x.id===r.userId);if(!u)return res.status(404).json({message:'User not found'});u.allowSelfReset=true;r.status='approved';r.approvedAt=new Date().toISOString();writeDB(db);res.json({ok:true,message:'Approved. User may now reset once; protected recovery is created before reset.'})});
app.patch('/api/admin/users/:id/lowstock-permission',auth,adminOnly,(req,res)=>{const db=readDB(),u=db.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({message:'User not found'});u.lowStockAlertsEnabled=req.body.enabled===true;writeDB(db);res.json({ok:true,enabled:u.lowStockAlertsEnabled})});
app.patch('/api/admin/users/:id/reset-permission',auth,adminOnly,(req,res)=>{const db=readDB(),u=db.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({message:'User not found'});u.allowSelfReset=req.body.enabled===true;writeDB(db);res.json({ok:true,allowSelfReset:u.allowSelfReset})});
app.post('/api/state/authorized-zero',auth,async(req,res)=>{try{if(req.user.role!=='user')return res.status(403).json({message:'User only'});const db=readDB(),id=req.user.id,u=db.users.find(x=>x.id===id);if(!u||!u.allowSelfReset)return res.status(403).json({message:'Admin has not enabled shop reset.'});if(req.body.confirmation!=='RESET MY SHOP')return res.status(400).json({message:'Confirmation required'});const previous=structuredClone(db.userStates[id]||blankState());if(recordCount(previous)){protectSnapshot(db,id,previous,'before-authorized-user-reset');db.archives[id]=db.archives[id]||[];db.archives[id].unshift({id:'user-zero-'+Date.now(),createdAt:new Date().toISOString(),reason:'before-authorized-user-reset',state:previous});db.archives[id]=db.archives[id].slice(0,50);db.adminRestoreDrafts=db.adminRestoreDrafts||{};db.adminRestoreDrafts[id]={state:previous,updatedAt:new Date().toISOString(),edited:true};}db.userStates[id]=blankState();u.allowSelfReset=false;writeDB(db);await mongoWrites;res.json({ok:true,message:'Shop reset completed. Protected admin recovery retained.'})}catch(e){res.status(503).json({message:'Reset failed; please check backup before retrying.'})}});
app.patch('/api/user/shop-name',auth,async(req,res)=>{try{if(req.user.role!=='user')return res.status(403).json({message:'User only'});const name=String(req.body.shopName||'').trim();if(!name||name.length>65)return res.status(400).json({message:'Shop name must be 1–65 characters.'});const db=readDB(),u=db.users.find(x=>x.id===req.user.id);if(!u)return res.status(404).json({message:'Account not found'});u.shopName=name;u.requestedShopName=name;writeDB(db);await mongoWrites;res.json({ok:true,user:publicUser(u),message:'Shop name saved.'})}catch(e){res.status(503).json({message:'Shop name save could not be confirmed.'})}});
app.patch('/api/admin/users/:id/access',auth,adminOnly,async(req,res)=>{
 try{
  if(typeof req.body.enabled!=='boolean')return res.status(400).json({message:'enabled must be true or false.'});
  const db=readDB(),user=db.users.find(u=>String(u.id)===String(req.params.id));
  if(!user)return res.status(404).json({message:'User not found'});
  user.accessEnabled=req.body.enabled;
  if(user.accessEnabled)user.pages=Object.fromEntries(ACCOUNT_PAGES.map(page=>[page,true]));
  writeDB(db);await mongoWrites;
  res.json({ok:true,user:publicUser(user),message:user.accessEnabled?'Account ON. All sections are available.':'Account OFF. Saved data is retained.'});
 }catch(error){res.status(503).json({message:'Account access change could not be confirmed. Refresh and retry.'});}
});
app.get('/api/admin/users',auth,adminOnly,(req,res)=>res.json({users:readDB().users.map(publicUser)}));
app.patch('/api/admin/users/:id/shop',auth,adminOnly,(req,res)=>{
 const name=String(req.body.shopName||'').trim(),logo=String(req.body.shopLogo||'').trim();
 if(!name||name.length>65)return res.status(400).json({message:'Shop name must be 1–65 characters.'});
 if(logo&&(!/^https:\/\/[^\s]+$/i.test(logo)||logo.length>1000))return res.status(400).json({message:'Logo must be a valid HTTPS image URL.'});
 const db=readDB(),u=db.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({message:'User not found.'});
 u.shopName=name;u.shopLogo='';writeDB(db);res.json({ok:true,message:'Shop identity approved and saved.',user:publicUser(u)});
});
// Shop contact details are administrator-owned; a user can only request a change.
app.patch('/api/admin/users/:id/contact',auth,adminOnly,(req,res)=>res.status(403).json({message:'Shop details are managed by the user.'}));
// Users save their own shop details directly; the legacy URL remains compatible.
async function saveUserShopContact(req,res){try{if(req.user.role!=='user')return res.status(403).json({message:'User only'});const db=readDB(),u=db.users.find(x=>x.id===req.user.id);if(!u)return res.status(404).json({message:'Account not found'});const shopContact=String(req.body.shopContact??u.shopContact??'').trim(),shopAddress=String(req.body.shopAddress??u.shopAddress??'').trim();if(shopContact.length>40)return res.status(400).json({message:'Contact number must be 40 characters or fewer.'});if(shopAddress.length>220)return res.status(400).json({message:'Shop address must be 220 characters or fewer.'});u.shopContact=shopContact;u.shopAddress=shopAddress;u.contactChangePending=null;writeDB(db);await mongoWrites;res.json({ok:true,user:publicUser(u),message:'Shop details saved.'});}catch(e){res.status(503).json({message:'Shop details save could not be confirmed. Please try again.'})}}
app.patch('/api/user/shop-contact',auth,saveUserShopContact);
app.post('/api/user/shop-contact-request',auth,saveUserShopContact);
app.post('/api/admin/users/:id/contact-request',auth,adminOnly,(req,res)=>res.status(410).json({message:'Contact approval has been removed. Users save their own details.'}));
app.patch('/api/admin/users/:id/approve',auth,adminOnly,(req,res)=>{const db=readDB(),u=db.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({message:'User not found'});u.shopName=String(u.requestedShopName||u.shopName||'Shoes').trim().slice(0,65)||'Shoes';u.shopLogo='';u.contactChangePending=null;u.approved=true;writeDB(db);res.json({ok:true,shopName:u.shopName})});
app.delete('/api/admin/users/:id',auth,adminOnly,async(req,res)=>{
 try{const db=readDB(),id=String(req.params.id),index=db.users.findIndex(u=>String(u.id)===id);if(index<0)return res.status(404).json({message:'User not found'});
 const u=db.users[index],state=structuredClone(bestAdminState(db,id));
 db.deletedUsers=db.deletedUsers||[];db.deletedUsers.unshift({id:'deleted-'+Date.now(),originalUserId:id,username:u.username,email:u.email,shopName:u.shopName,deletedAt:new Date().toISOString(),state,archives:structuredClone(db.archives[id]||[])});
 protectSnapshot(db,id,state,'before-admin-user-delete');db.users.splice(index,1);
 for(const key of ['userStates','archives','adminRestoreDrafts','restoreNotices'])if(db[key])delete db[key][id];
 db.resetRequests=(db.resetRequests||[]).filter(r=>String(r.userId)!==id);
 writeDB(db);await mongoWrites;res.json({ok:true,message:'Account deleted. Login is disabled. Protected View Data retained.'});
 }catch(error){console.error('User deletion failed:',error);res.status(503).json({message:'Could not confirm account deletion. Refresh the users list before retrying.'});}
});
app.get('/api/admin/deleted-users',auth,adminOnly,(req,res)=>{const db=readDB();res.json({users:(db.deletedUsers||[]).map(u=>({id:u.id,originalUserId:u.originalUserId,username:u.username,email:u.email,shopName:u.shopName,deletedAt:u.deletedAt,records:recordCount(u.state)}))})});
app.get('/api/admin/deleted-users/:id/data',auth,adminOnly,(req,res)=>{const db=readDB(),u=(db.deletedUsers||[]).find(x=>x.id===req.params.id);if(!u)return res.status(404).json({message:'Protected deleted-account backup not found'});res.json({state:u.state,archives:u.archives||[],username:u.username,deletedAt:u.deletedAt})});
app.patch('/api/admin/users/:id/pages',auth,adminOnly,(req,res)=>{const page=String(req.body.page||''),allowed=['dashboard','sale','products','stock','purchases','customers','khata','bills','income','reports'];if(page==='reports'&&req.body.enabled===false)return res.status(400).json({message:'Reports must remain available to users.'});if(!allowed.includes(page))return res.status(400).json({message:'Invalid page'});const db=readDB(),u=db.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({message:'User not found'});u.pages={...(u.pages||{}),[page]:!!req.body.enabled};writeDB(db);res.json({ok:true,pages:u.pages})});
app.get('/api/admin/users/:id/data',auth,adminOnly,(req,res)=>{const db=readDB(),id=req.params.id;if(!db.users.some(u=>u.id===id))return res.status(404).json({message:'User not found'});res.json({state:bestAdminState(db,id),protectedSnapshot:db.protectedSnapshots?.[id]||null,archives:(db.archives[id]||[]).slice(0,15)})});
app.post('/api/admin/users/:id/backup',auth,adminOnly,(req,res)=>{const db=readDB(),id=req.params.id,u=db.users.find(x=>x.id===id);if(!u)return res.status(404).json({message:'User not found'});db.archives[id]=db.archives[id]||[];db.archives[id].unshift({id:Date.now().toString(),createdAt:new Date().toISOString(),state:JSON.parse(JSON.stringify(db.userStates[id]||blankState()))});db.archives[id]=db.archives[id].slice(0,50);writeDB(db);res.json({ok:true,message:'Protected backup saved successfully.'})});
app.post('/api/admin/users/:id/restore/:archiveId',auth,adminOnly,(req,res)=>{const db=readDB(),id=req.params.id,a=(db.archives[id]||[]).find(x=>String(x.id)===String(req.params.archiveId));if(!a)return res.status(404).json({message:'Backup not found'});db.archives[id]=db.archives[id]||[];db.archives[id].unshift({id:'safety-'+Date.now(),createdAt:new Date().toISOString(),reason:'before-admin-restore',state:JSON.parse(JSON.stringify(db.userStates[id]||blankState()))});db.archives[id]=db.archives[id].slice(0,50);db.userStates[id]=JSON.parse(JSON.stringify(a.state||blankState()));protectSnapshot(db,id,db.userStates[id],"admin-restored");db.restoreNotices=db.restoreNotices||{};db.restoreNotices[id]={backupDate:a.createdAt,restoredAt:new Date().toISOString()};writeDB(db);res.json({ok:true,message:'Saved data restored successfully. User will receive it on login.'})});
app.patch('/api/admin/users/:id/password',auth,adminOnly,async(req,res)=>{try{const password=String(req.body.password||'');if(password.length<6)return res.status(400).json({message:'Password must be at least 6 characters.'});const db=readDB(),user=db.users.find(u=>String(u.id)===String(req.params.id));if(!user)return res.status(404).json({message:'User not found.'});user.passwordHash=await bcrypt.hash(password,10);db.resetRequests=(db.resetRequests||[]).filter(r=>String(r.userId)!==String(user.id));writeDB(db);await mongoWrites;res.json({ok:true,message:'Password reset successfully.'});}catch(error){res.status(503).json({message:'Password reset could not be saved. Please retry.'});}});
app.post('/api/auth/password-reset/request',(req,res)=>{const login=String(req.body.login||'').trim().toLowerCase(),db=readDB(),u=db.users.find(x=>x.username.toLowerCase()===login||x.email===login);if(!u)return res.status(404).json({message:'No account found.'});db.resetRequests=db.resetRequests.filter(x=>!(x.userId===u.id&&!x.used));const r={id:Date.now().toString(),userId:u.id,username:u.username,email:u.email,status:'pending',createdAt:new Date().toISOString(),used:false};db.resetRequests.push(r);writeDB(db);res.json({ok:true,requestId:r.id,message:'Reset request sent to admin.'})});
app.get('/api/auth/password-reset/status/:id',(req,res)=>{const db=readDB(),r=db.resetRequests.find(x=>x.id===req.params.id);if(!r)return res.status(404).json({message:'Request not found'});res.json({status:r.status,expiresAt:r.expiresAt||null})});
app.get('/api/admin/reset-requests',auth,adminOnly,(req,res)=>res.json({requests:readDB().resetRequests.filter(x=>!x.used).slice(-30).reverse()}));
app.post('/api/admin/reset-requests/:id/approve',auth,adminOnly,(req,res)=>{const db=readDB(),r=db.resetRequests.find(x=>x.id===req.params.id);if(!r)return res.status(404).json({message:'Request not found'});r.status='approved';r.expiresAt=Date.now()+120000;writeDB(db);res.json({ok:true,expiresAt:r.expiresAt})});
app.post('/api/auth/password-reset/complete',async(req,res)=>{const db=readDB(),r=db.resetRequests.find(x=>x.id===String(req.body.requestId||'')),password=String(req.body.password||'');if(!r||r.status!=='approved'||r.used||Date.now()>Number(r.expiresAt||0))return res.status(400).json({message:'Approval is missing or the 2-minute reset window expired.'});if(password.length<6)return res.status(400).json({message:'Password must be at least 6 characters.'});const u=db.users.find(x=>x.id===r.userId);u.passwordHash=await bcrypt.hash(password,10);r.used=true;r.status='completed';writeDB(db);res.json({ok:true,message:'Password changed successfully.'})});
app.post('/api/auth/admin/reset/verify-pin',(req,res)=>{if(String(req.body.pin||'')!==ADMIN_PIN)return res.status(401).json({message:'Invalid private 6-digit code.'});res.json({resetToken:tok({role:'admin-reset'},'2m')})});
app.post('/api/auth/admin/reset/complete',async(req,res)=>{try{const t=jwt.verify(String(req.body.resetToken||''),JWT_SECRET);if(t.role!=='admin-reset')throw 0;const password=String(req.body.password||'');if(password.length<6)return res.status(400).json({message:'Password must be at least 6 characters.'});const db=readDB();db.settings.adminPasswordHash=await bcrypt.hash(password,10);writeDB(db);res.json({ok:true,message:'Admin password changed.'})}catch{return res.status(400).json({message:'Verification expired. Verify the private code again.'})}});

function manageReturnRecord(s,command){
 const eq=(a,b)=>String(a)===String(b),round=n=>Math.round(n*100)/100;
 const b=s.bills.find(b=>eq(b.id,command.billId)),r=b?.returns?.find(r=>eq(r.id,command.id));if(!r)throw Error('Return record not found.');
 const values=command.values||{},deleting=command.action==='delete';if(!deleting&&command.action!=='edit')throw Error('Invalid return action.');
 if(!deleting&&(!Array.isArray(values.items)||values.items.length!==r.items.length))throw Error('All return items are required.');
 const nextItems=r.items.map((i,index)=>{const qty=deleting?0:Number(values.items[index].qty);if(!Number.isInteger(qty)||qty<0)throw Error('Invalid return quantity.');return {...i,qty};});
 const oldRaw=r.items.reduce((n,i)=>n+Number(i.qty)*Number(i.price),0),newRaw=nextItems.reduce((n,i)=>n+i.qty*Number(i.price),0);
 if(!deleting&&newRaw<=0)throw Error('Use Delete to reverse the entire return.');
 const newAmount=deleting?0:round(oldRaw?newRaw*Number(r.amount)/oldRaw:0),delta=round(newAmount-Number(r.amount||0));
 for(let i=0;i<r.items.length;i++){const old=r.items[i],next=nextItems[i],diff=next.qty-Number(old.qty),product=s.products.find(p=>eq(p.id,old.id));if(!product)throw Error('Restore the product before changing its return.');product.stock=product.stock||{};if(Number(product.stock[old.size]||0)+diff<0)throw Error('Returned stock has already been sold; not enough stock to reverse this return.');product.stock[old.size]=Number(product.stock[old.size]||0)+diff;let item=b.items.find(x=>eq(x.id,old.id)&&String(x.size)===String(old.size)&&Number(x.price)===Number(old.price));if(diff>0&&(!item||Number(item.qty)<diff))throw Error('Return exceeds the remaining sold quantity.');if(!item&&diff<0){item={...old,qty:0};delete item.itemIndex;b.items.push(item);}if(item)item.qty-=diff;}
 b.items=b.items.filter(i=>i.qty>0);let refundDelta=0,khataDelta=0;
 if(delta>=0){khataDelta=Math.min(Number(b.remaining||0),delta);refundDelta=round(delta-khataDelta);}else{const ratio=Number(r.amount)>0?-delta/Number(r.amount):0;refundDelta=-round(Number(r.refund||0)*ratio);khataDelta=round(delta-refundDelta);}
 b.total=round(Number(b.total||0)-delta);b.subtotal=round(Number(b.subtotal||0)-delta);b.paid=round(Number(b.paid||0)-refundDelta);b.remaining=round(b.total-b.paid);
 if(refundDelta>0){let left=refundDelta;for(const entry of s.incomes){if(Array.isArray(entry.allocations)){for(const a of entry.allocations.filter(a=>eq(a.billId,b.id))){const used=Math.min(left,Number(a.amount||0));a.amount=round(a.amount-used);entry.amount=round(entry.amount-used);left=round(left-used);if(!left)break;}entry.allocations=entry.allocations.filter(a=>a.amount>0);}else if(eq(entry.billId,b.id)){const used=Math.min(left,Number(entry.amount||0));entry.amount=round(entry.amount-used);left=round(left-used);}if(!left)break;}}
 if(refundDelta<0){let entry=s.incomes.find(e=>eq(e.billId,b.id)&&!Array.isArray(e.allocations));if(!entry){entry={id:'sale-'+b.id,billId:b.id,type:'sale',desc:'Sale '+b.number,amount:0,date:b.date};s.incomes.push(entry);}entry.amount=round(Number(entry.amount||0)-refundDelta);}
 s.incomes=s.incomes.filter(e=>Number(e.amount)>0);
 for(const bill of s.bills){for(const p of bill.payments||[]){const e=s.incomes.find(e=>eq(e.id,p.id)&&Array.isArray(e.allocations));p.amount=e?Number(e.allocations.find(a=>eq(a.billId,bill.id))?.amount||0):0;}bill.payments=(bill.payments||[]).filter(p=>p.amount>0);}
 if(deleting)b.returns=b.returns.filter(x=>!eq(x.id,r.id));else{r.items=nextItems.filter(i=>i.qty>0);r.amount=newAmount;r.refund=round(Number(r.refund||0)+refundDelta);r.khataReduction=round(Number(r.khataReduction||0)+khataDelta);if(values.date){const d=new Date(values.date);if(!Number.isFinite(d.getTime()))throw Error('Invalid date.');r.date=d.toISOString();}}
 for(const c of s.customers)if(eq(c.id,b.customerId))c.balance=round(s.bills.filter(x=>eq(x.customerId,c.id)).reduce((n,x)=>n+Number(x.remaining||0),0));return s;
}

function manageShopRecord(state,command){
 const s=structuredClone(state),keys=['products','customers','bills','expenses','incomes','purchases'];
 keys.forEach(k=>{if(!Array.isArray(s[k]))s[k]=[];});
 const eq=(a,b)=>String(a)===String(b),round=v=>Math.round(Number(v)*100)/100;
 const num=(v,label,integer=false)=>{const n=Number(v);if(v===''||v===null||!Number.isFinite(n)||n<0||(integer&&!Number.isInteger(n)))throw Error('Invalid '+label);return round(n);};
 const find=(k,id)=>s[k].find(r=>eq(r.id,id));
 const remove=(k,id)=>{s[k]=s[k].filter(r=>!eq(r.id,id));};
 const stock=(id,size,delta)=>{const p=find('products',id);if(!p){if(delta>0)throw Error('Restore the deleted product before reversing its stock.');throw Error('Product no longer exists.');}p.stock=p.stock||{};const next=Number(p.stock[size]||0)+delta;if(next<0)throw Error('Change exceeds available stock.');p.stock[size]=next;};
 const fields=command.values||{},kind=command.section,action=command.action;
 if(kind==='stock'){const product=find('products',command.id),size=String(command.size||'');if(!product||!Object.hasOwn(product.stock||{},size))throw Error('Stock size not found.');if(action==='delete')delete product.stock[size];else if(action==='edit')product.stock[size]=num(fields.qty,'stock',true);else throw Error('Invalid action.');return s;}
 if(kind==='returns'){return manageReturnRecord(s,command);}
 if(!keys.includes(kind)||!['edit','delete'].includes(action))throw Error('Invalid action.');
 const row=find(kind,command.id);if(!row)throw Error('Record no longer exists. Reload data.');
 const moneyReverse=(entry,amount)=>{
  if(entry.billId&&!Array.isArray(entry.allocations)){const b=find('bills',entry.billId);if(b)b.paid=round(Math.max(0,Number(b.paid||0)-amount));}
  if(Array.isArray(entry.allocations))for(const a of entry.allocations){const b=find('bills',a.billId);if(!b)continue;b.paid=round(Math.max(0,Number(b.paid||0)-Number(a.amount||0)));b.payments=(b.payments||[]).filter(p=>!eq(p.id,entry.id));}
 };
 const purchaseChange=(p,values,deleting)=>{
  const oldQty=Number(p.qty||0),qty=deleting?0:num(values.qty??p.qty,'quantity',true),cost=deleting?Number(p.purchase||0):num(values.purchase??p.purchase,'purchase cost');
  const product=find('products',p.productId??p.idProduct)||s.products.find(x=>String(x.code)===String(p.code));if(qty!==oldQty){if(!product)throw Error('Restore the deleted product before reversing this purchase.');stock(product.id,p.size,qty-oldQty);}
  const linked=s.expenses.find(e=>eq(e.purchaseId,p.id));
  if(deleting){remove('purchases',p.id);s.expenses=s.expenses.filter(e=>!eq(e.purchaseId,p.id));}
  else{p.qty=qty;p.purchase=cost;if(!linked&&qty*cost>0)s.expenses.push({id:'purchase-'+p.id,purchaseId:p.id,type:'stock-purchase',category:'Stock Purchase',amount:round(qty*cost),date:p.date,desc:'Stock purchase: '+p.name});if(linked){linked.amount=round(qty*cost);linked.desc='Stock purchase: '+p.name+' / Size '+p.size+' / '+qty+' pairs';}}
 };
 if(kind==='bills'){
  if(action==='delete'){
   for(const item of row.items||[])stock(item.id,item.size,Number(item.qty||0));
   for(const inc of s.incomes){if(Array.isArray(inc.allocations)){inc.allocations=inc.allocations.filter(a=>!eq(a.billId,row.id));inc.amount=round(inc.allocations.reduce((n,a)=>n+Number(a.amount||0),0));}}
   s.incomes=s.incomes.filter(e=>!eq(e.billId,row.id)&&(!Array.isArray(e.allocations)||e.allocations.length));s.expenses=s.expenses.filter(e=>!eq(e.billId,row.id));remove(kind,row.id);
  }else{
   const items=structuredClone(row.items||[]);if(!Array.isArray(fields.items)||fields.items.length!==items.length)throw Error('All bill items are required.');
   const deltas=new Map();
   items.forEach((item,i)=>{const qty=num(fields.items[i].qty,'item quantity',true),price=num(fields.items[i].price,'item price');const key=JSON.stringify([item.id,String(item.size)]),d=deltas.get(key)||{id:item.id,size:item.size,qty:0};d.qty+=Number(item.qty||0)-qty;deltas.set(key,d);item.qty=qty;item.price=price;});
   const subtotal=round(items.reduce((n,i)=>n+i.qty*i.price,0)),discount=num(fields.discount??row.discount??0,'discount');if(discount>subtotal)throw Error('Discount exceeds bill subtotal.');const total=round(subtotal-discount),paid=num(fields.paid??row.paid??0,'paid amount');if(paid>total)throw Error('Paid amount exceeds bill total.');
   const kahta=s.incomes.filter(e=>Array.isArray(e.allocations)).reduce((n,e)=>n+e.allocations.filter(a=>eq(a.billId,row.id)).reduce((m,a)=>m+Number(a.amount||0),0),0);if(paid<round(kahta))throw Error('Reverse linked Kahta collections first.');
   for(const d of deltas.values())if(d.qty!==0)stock(d.id,d.size,d.qty);
   row.items=items.filter(i=>i.qty>0);row.subtotal=subtotal;row.discount=discount;row.total=total;row.paid=paid;row.handledBy=String(fields.handledBy??row.handledBy??'').trim();
   s.incomes=s.incomes.filter(e=>!eq(e.billId,row.id));if(paid>kahta)s.incomes.push({id:'sale-'+row.id,billId:row.id,type:'sale',desc:'Sale '+row.number,amount:round(paid-kahta),date:row.date});
  }
 }else if(kind==='incomes'){
  if(action==='delete'){moneyReverse(row,Number(row.amount||0));remove(kind,row.id);}
  else{
   const amount=num(fields.amount,'amount');if(amount<=0)throw Error('Amount must be greater than zero.');
   if(Array.isArray(row.allocations)){
    const customer=find('customers',row.customerId);if(!customer)throw Error('Customer not found.');moneyReverse(row,Number(row.amount||0));let left=amount;const allocations=[];
    for(const b of s.bills.filter(b=>eq(b.customerId,customer.id)).sort((a,b)=>String(a.date).localeCompare(String(b.date)))){const due=round(Math.max(0,Number(b.total||0)-Number(b.paid||0))),used=Math.min(left,due);if(used<=0)continue;b.paid=round(Number(b.paid||0)+used);b.payments=b.payments||[];b.payments.push({id:row.id,date:row.date,amount:used,type:'kahta'});allocations.push({billId:b.id,billNumber:b.number,amount:used});left=round(left-used);}
    if(left>0)throw Error('Payment exceeds customer outstanding balance.');row.allocations=allocations;
   }
   if(row.billId&&!Array.isArray(row.allocations)){const b=find('bills',row.billId);if(!b)throw Error('Linked bill not found.');const next=round(Number(b.paid||0)-Number(row.amount||0)+amount);if(next<0||next>Number(b.total||0))throw Error('Amount exceeds the linked bill balance.');b.paid=next;}
   row.amount=amount;row.desc=String(fields.desc??row.desc).trim();if(!row.desc)throw Error('Description required.');
  }
 }else if(kind==='expenses'&&row.purchaseId){const p=find('purchases',row.purchaseId);if(!p)throw Error('Linked purchase missing.');if(action==='delete')purchaseChange(p,{},true);else{const amount=num(fields.amount,'amount');if(!Number(p.qty))throw Error('Purchase has no quantity.');purchaseChange(p,{qty:p.qty,purchase:amount/Number(p.qty)},false);}}
 else if(kind==='purchases')purchaseChange(row,fields,action==='delete');
 else if(kind==='products'){
  if(action==='delete'){if(s.bills.some(b=>(b.items||[]).some(i=>eq(i.id,row.id))||(b.returns||[]).some(r=>(r.items||[]).some(i=>eq(i.id,row.id))))||s.purchases.some(p=>eq(p.productId??p.idProduct,row.id)||String(p.code)===String(row.code)))throw Error('Remove linked bills, returns and purchases before deleting this product.');remove(kind,row.id);}
  else{const name=String(fields.name??row.name).trim(),code=String(fields.code??row.code).trim();if(!name||!code)throw Error('Product name and code required.');if(s.products.some(p=>!eq(p.id,row.id)&&String(p.code).toLowerCase()===code.toLowerCase()))throw Error('Product code already exists.');const amounts=fields.stock??row.stock;if(!amounts||typeof amounts!=='object'||Array.isArray(amounts))throw Error('Stock must contain sizes and quantities.');const clean={};for(const [size,q] of Object.entries(amounts)){if(!size.trim())throw Error('Size required.');clean[size]=num(q,'stock',true);}const oldCode=row.code;Object.assign(row,{name,code,purchase:num(fields.purchase??row.purchase??0,'purchase cost'),price:num(fields.price??row.price??0,'sale price'),stock:clean});const linked=item=>eq(item.id??item.productId,row.id)||String(item.code||'').trim().toLowerCase()===String(oldCode||'').trim().toLowerCase();for(const b of s.bills)for(const item of [...(b.items||[]),...(b.returns||[]).flatMap(r=>r.items||[])])if(linked(item)){item.name=name;item.code=code;}for(const p of s.purchases)if(eq(p.productId,row.id)||String(p.code||'').trim().toLowerCase()===String(oldCode||'').trim().toLowerCase()){p.productId=row.id;p.name=name;p.code=code;for(const e of s.expenses)if(eq(e.purchaseId,p.id))e.desc='Stock purchase: '+name+' / Size '+p.size+' / '+p.qty+' pairs';}}
 }else if(kind==='customers'){
  if(action==='delete'){if(s.bills.some(b=>eq(b.customerId,row.id)))throw Error('Delete or reassign the customer bills before deleting this customer.');if(Number(row.balance||0)>0)throw Error('Clear the customer balance first.');remove(kind,row.id);}
  else{const name=String(fields.name??row.name).trim();if(!name)throw Error('Customer name required.');Object.assign(row,{name,phone:String(fields.phone??row.phone??''),address:String(fields.address??row.address??'')});for(const b of s.bills.filter(b=>eq(b.customerId,row.id))){b.customer=name;b.customerPhone=row.phone;b.customerAddress=row.address;}}
 }else{
  if(action==='delete')remove(kind,row.id);else{row.amount=num(fields.amount,'amount');if(row.amount<=0)throw Error('Amount must be greater than zero.');row.desc=String(fields.desc??row.desc).trim();if(!row.desc)throw Error('Description required.');}
 }
 for(const b of s.bills){b.remaining=round(Math.max(0,Number(b.total||0)-Number(b.paid||0)));}
 const affected=new Set((state.bills||[]).map(b=>String(b.customerId)).concat(s.bills.map(b=>String(b.customerId))));for(const c of s.customers)if(affected.has(String(c.id)))c.balance=round(s.bills.filter(b=>eq(b.customerId,c.id)).reduce((n,b)=>n+b.remaining,0));
 if(action==='edit'&&typeof fields.date==='string'){const d=new Date(fields.date);if(!Number.isFinite(d.getTime()))throw Error('Invalid record date.');row.date=d.toISOString();if(kind==='purchases')for(const e of s.expenses.filter(e=>eq(e.purchaseId,row.id)))e.date=row.date;if(kind==='bills')for(const e of s.incomes.filter(e=>eq(e.billId,row.id)&&!Array.isArray(e.allocations)))e.date=row.date;if(kind==='incomes')for(const b of s.bills)for(const p of b.payments||[])if(eq(p.id,row.id))p.date=row.date;}
 if(kind==='purchases'&&action==='edit')row.supplier=String(fields.supplier??row.supplier??'').trim();
 return s;
}
async function applyManagedRecord(req,res){
 try{
  const db=readDB(),id=req.user.role==='admin'?String(req.params.id):String(req.user.id);
  if(!db.users.some(u=>String(u.id)===id))return res.status(404).json({message:'User not found'});
  const isAdmin=req.user.role==='admin';
  const previous=isAdmin?bestAdminState(db,id):(db.userStates[id]||blankState()),next=manageShopRecord(previous,req.body||{});
  db.archives[id]=db.archives[id]||[];db.archives[id].unshift({id:'manage-'+Date.now(),createdAt:new Date().toISOString(),reason:'before-record-edit',state:structuredClone(previous)});db.archives[id]=db.archives[id].slice(0,50);
  if(isAdmin){
   // Update the retained copy even when the user already removed the record.
   // Only apply to live shop if that record still exists; do not restore other removed rows.
   const live=db.userStates[id]||blankState(),kind=String(req.body.kind||req.body.section||''),recordId=req.body.id;
   const liveKind=kind==='stock'?'products':kind;
   const exists=kind==='returns'?(live.bills||[]).some(b=>(b.returns||[]).some(r=>String(r.id)===String(recordId))):(live[liveKind]||[]).some(r=>String(r.id)===String(recordId));
   if(exists)db.userStates[id]=manageShopRecord(live,req.body||{});
   db.adminSavedStates[id]={state:structuredClone(next),updatedAt:new Date().toISOString()};
   db.adminRestoreDrafts=db.adminRestoreDrafts||{};db.adminRestoreDrafts[id]={state:structuredClone(next),updatedAt:new Date().toISOString(),edited:true};
  }else{
   protectSnapshot(db,id,previous,'before-record-edit');db.userStates[id]=next;
   db.viewDataStates=db.viewDataStates||{};if(recordCount(next))db.viewDataStates[id]={state:structuredClone(next),updatedAt:new Date().toISOString()};
  }
  writeDB(db,req.body?.action==='delete'?id:undefined,isAdmin?id:undefined);await mongoWrites;res.json({ok:true,data:isAdmin?next:db.userStates[id],message:'Data updated. Admin saved records are retained until admin deletes them.'});
 }catch(error){res.status(400).json({message:error.message||'Record change failed.'});}
}
app.get('/api/admin/users/:id/manage-data',auth,adminOnly,(req,res)=>{const db=readDB(),id=req.params.id;if(!db.users.some(u=>String(u.id)===String(id)))return res.status(404).json({message:'User not found'});res.json({data:bestAdminState(db,id)});});
app.post('/api/admin/users/:id/manage-data',auth,adminOnly,applyManagedRecord);
app.post('/api/state/manage-data',auth,(req,res)=>{if(req.user.role!=='user')return res.status(403).json({message:'User account required'});return applyManagedRecord(req,res);});

app.get('/api/state/activity',auth,(req,res)=>{if(req.user.role!=='user')return res.status(403).json({message:'User account required'});res.json({events:(readDB().recordActivity?.[req.user.id]||[]).filter(event=>event.action!=='delete')});});
app.get('/api/admin/users/:id/activity',auth,adminOnly,(req,res)=>res.json({events:(readDB().recordActivity?.[req.params.id]||[]).filter(event=>event.action!=='delete')}));
app.use('/api',(req,res)=>res.status(404).json({message:'API endpoint not found: '+req.method+' '+req.originalUrl+'. Check the backend version and requested address.'}));
app.use(express.static(path.join(__dirname,'public')));app.get(/.*/,(_q,r)=>r.sendFile(path.join(__dirname,'public','index.html')));app.use((e,_q,r,_n)=>{console.error(e);r.status(500).json({message:e.message||'Server error'})});
async function start(){
 if(process.env.MONGODB_URI){
   await mongoose.connect(process.env.MONGODB_URI,{serverSelectionTimeoutMS:15000});
   const saved=await StoredDB.findById('main').lean();
   if(saved?.payload){liveDB=Object.assign(emptyDB(),await loadMongoSnapshot(saved.payload));fs.writeFileSync(DATA_FILE,JSON.stringify(liveDB,null,2));}
   else {liveDB=readDB();await persistMongoSnapshot(liveDB);}
   console.log('MongoDB connected: account data is database-backed');
 }else if(process.env.NODE_ENV==='production')throw Error('MONGODB_URI is required in production to protect account data across redeploys.');
 else console.warn('Local JSON mode: set MONGODB_URI before deploying for permanent storage.');
 app.listen(port,()=>console.log(`server is running on port ${port}`));
}
start().catch(e=>{console.error('Startup failed:',e.message);process.exit(1)});
