require("dotenv").config();
const path=require("path"), http=require("http"), crypto=require("crypto");
const express=require("express"), {WebSocketServer}=require("ws");
const multer=require("multer");
const bcrypt=require("bcryptjs"), jwt=require("jsonwebtoken"), rateLimit=require("express-rate-limit");
const {Pool}=require("pg");
const helmet=require("helmet"), cors=require("cors");

const app=express();
const server=http.createServer(app);
const wss=new WebSocketServer({server});
const pool=new Pool({connectionString:process.env.DATABASE_URL, ssl:process.env.DATABASE_SSL==="true"?{rejectUnauthorized:false}:undefined});
const PORT=process.env.PORT||3000, JWT_SECRET=process.env.JWT_SECRET||"change-me";
if(JWT_SECRET==="change-me") console.warn("WARNING: configure a strong JWT_SECRET in production.");
if(!process.env.DATABASE_URL) console.warn("WARNING: DATABASE_URL is not configured.");

app.use(helmet({contentSecurityPolicy:false}));
app.use(cors({origin:process.env.FRONTEND_ORIGIN||true}));
app.use(express.json({limit:"32kb"}));
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:5*1024*1024}});
app.use("/api/auth",rateLimit({windowMs:15*60*1000,max:30}));
app.use("/api",rateLimit({windowMs:60*1000,max:180}));
app.use(express.static(path.join(__dirname,"public")));
app.get("/",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.get("/api/health",(req,res)=>res.json({ok:true}));
app.get("/api/rtc-config",(req,res)=>{const iceServers=[{urls:["stun:stun.l.google.com:19302","stun:stun1.l.google.com:19302"]}];if(process.env.TURN_URL&&process.env.TURN_USERNAME&&process.env.TURN_CREDENTIAL)iceServers.push({urls:process.env.TURN_URL.split(',').map(x=>x.trim()).filter(Boolean),username:process.env.TURN_USERNAME,credential:process.env.TURN_CREDENTIAL});res.json({iceServers})});


const sockets=new Map(), rooms=new Map();
const clean=u=>String(u||"").trim().toLowerCase().replace(/^@/,"");
const id=()=>crypto.randomUUID();
const send=(ws,o)=>ws?.readyState===1&&ws.send(JSON.stringify(o));
function auth(req){try{return jwt.verify((req.headers.authorization||"").replace("Bearer ",""),JWT_SECRET)}catch{return null}}

async function initDB(){
 await pool.query(`CREATE TABLE IF NOT EXISTS users(
 id UUID PRIMARY KEY, username VARCHAR(24) UNIQUE NOT NULL,
 display_name VARCHAR(60) NOT NULL, password_hash TEXT NOT NULL,
 avatar_image_id UUID,
 created_at TIMESTAMPTZ DEFAULT now()
 );
 CREATE TABLE IF NOT EXISTS friendships(
 user_id UUID REFERENCES users(id) ON DELETE CASCADE,
 friend_id UUID REFERENCES users(id) ON DELETE CASCADE,
 status VARCHAR(12) NOT NULL CHECK(status IN ('pending','accepted')),
 created_at TIMESTAMPTZ DEFAULT now(),
 PRIMARY KEY(user_id,friend_id)
 );
 CREATE TABLE IF NOT EXISTS groups(
 id UUID PRIMARY KEY, name VARCHAR(80) NOT NULL, owner_id UUID REFERENCES users(id) ON DELETE CASCADE, created_at TIMESTAMPTZ DEFAULT now()
 );
 CREATE TABLE IF NOT EXISTS group_members(
 group_id UUID REFERENCES groups(id) ON DELETE CASCADE, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
 PRIMARY KEY(group_id,user_id)
 );
 CREATE TABLE IF NOT EXISTS messages(
 id UUID PRIMARY KEY, room VARCHAR(100) NOT NULL, user_id UUID REFERENCES users(id) ON DELETE SET NULL,
 text TEXT NOT NULL, image_id UUID, created_at TIMESTAMPTZ DEFAULT now()
 );
 CREATE INDEX IF NOT EXISTS messages_room_time ON messages(room,created_at);
 CREATE TABLE IF NOT EXISTS read_receipts(user_id UUID REFERENCES users(id) ON DELETE CASCADE, room TEXT NOT NULL, last_read_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(user_id,room));
 ALTER TABLE messages ADD COLUMN IF NOT EXISTS image_id UUID;
 ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_image_id UUID;
ALTER TABLE users ADD COLUMN IF NOT EXISTS banner_image_id UUID;
ALTER TABLE users ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS name_color TEXT NOT NULL DEFAULT '#d44e82';
ALTER TABLE users ADD COLUMN IF NOT EXISTS status_text TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS status_expires_at TIMESTAMPTZ;
ALTER TABLE friendships ADD COLUMN IF NOT EXISTS nickname TEXT NOT NULL DEFAULT '';
 CREATE TABLE IF NOT EXISTS images(
 id UUID PRIMARY KEY, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
 mime_type VARCHAR(100) NOT NULL, data BYTEA NOT NULL, created_at TIMESTAMPTZ DEFAULT now()
 );`);
}
function publicUser(u){const expired=u.status_expires_at && new Date(u.status_expires_at)<=new Date();return {username:u.username,displayName:u.display_name,description:u.description||'',nameColor:u.name_color||'#d44e82',online:!!sockets.get(u.username),avatarId:u.avatar_image_id||null,status:expired?'':(u.status_text||''),statusExpiresAt:expired?null:(u.status_expires_at||null),bannerId:u.banner_image_id||null}}
function broadcast(o){for(const ws of sockets.values())send(ws,o)}
async function notifyProfile(username){const r=await pool.query("SELECT username,display_name,description,name_color,avatar_image_id,banner_image_id,status_text,status_expires_at FROM users WHERE username=$1",[username]);if(r.rows[0])broadcast({type:'profile-update',user:publicUser(r.rows[0])})}
async function notifyUnread(room,sender,item){let names=[];if(room.startsWith('group:')){const gid=room.slice(6);const r=await pool.query("SELECT u.username FROM group_members gm JOIN users u ON u.id=gm.user_id WHERE gm.group_id=$1",[gid]);names=r.rows.map(x=>x.username)}else if(room.includes(':')) names=room.split(':').slice(0,2);for(const name of names){if(name===sender)continue;const peer=sockets.get(name);if(peer&&peer.room!==room)send(peer,{type:'unread-message',room,message:item})}}

app.post("/api/auth/register",async(req,res)=>{
 try{
  const u=clean(req.body.username), p=String(req.body.password||""), d=String(req.body.displayName||u).trim().slice(0,60);
  if(!/^[a-z0-9_.-]{2,24}$/.test(u)||p.length<8)return res.status(400).json({error:"Username inválido ou senha deve ter 8+ caracteres."});
  const hash=await bcrypt.hash(p,12), idv=id();
  const r=await pool.query("INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,$4) RETURNING id,username,display_name",[idv,u,d,hash]);
  const token=jwt.sign({id:idv,username:u},JWT_SECRET,{expiresIn:"30d"});res.json({token,user:publicUser(r.rows[0])});
 }catch(e){res.status(e.code==="23505"?409:500).json({error:e.code==="23505"?"Username já existe.":"Erro no servidor."})}
});
app.post("/api/auth/login",async(req,res)=>{
 const u=clean(req.body.username), p=String(req.body.password||"");
 const r=await pool.query("SELECT * FROM users WHERE username=$1",[u]); const user=r.rows[0];
 if(!user||!(await bcrypt.compare(p,user.password_hash)))return res.status(401).json({error:"Login inválido."});
 res.json({token:jwt.sign({id:user.id,username:u},JWT_SECRET,{expiresIn:"30d"}),user:publicUser(user)});
});
app.get("/api/me",async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();const r=await pool.query("SELECT id,username,display_name,description,name_color,avatar_image_id,banner_image_id,status_text,status_expires_at FROM users WHERE id=$1",[a.id]);if(!r.rows[0])return res.status(401).end();res.setHeader("X-Session-Token",jwt.sign({id:r.rows[0].id,username:r.rows[0].username},JWT_SECRET,{expiresIn:"30d"}));res.json(publicUser(r.rows[0]))});
app.get("/api/users/:username",async(req,res)=>{const r=await pool.query("SELECT id,username,display_name,description,name_color,avatar_image_id,banner_image_id,status_text,status_expires_at FROM users WHERE username=$1",[clean(req.params.username)]);if(!r.rows[0])return res.status(404).json({error:"Usuário não encontrado"});res.json(publicUser(r.rows[0]))});
app.post("/api/friends/request",async(req,res)=>{
 const a=auth(req), to=clean(req.body.username);if(!a)return res.status(401).end();
 const r=await pool.query("SELECT id,username FROM users WHERE username=$1",[to]);if(!r.rows[0])return res.status(404).json({error:"Usuário não encontrado"});
 if(to===a.username)return res.status(400).json({error:"Não pode adicionar você mesma."});
 await pool.query("INSERT INTO friendships(user_id,friend_id,status) VALUES($1,$2,'pending') ON CONFLICT DO NOTHING",[a.id,r.rows[0].id]);
 send(sockets.get(to),{type:"friend-request",from:a.username});res.json({ok:true});
});
app.post("/api/friends/accept",async(req,res)=>{
 const a=auth(req), from=clean(req.body.username);if(!a)return res.status(401).end();
 const r=await pool.query("SELECT id FROM users WHERE username=$1",[from]);if(!r.rows[0])return res.status(404).end();
 await pool.query("UPDATE friendships SET status='accepted' WHERE user_id=$1 AND friend_id=$2",[r.rows[0].id,a.id]);
 await pool.query("INSERT INTO friendships(user_id,friend_id,status) VALUES($1,$2,'accepted') ON CONFLICT(user_id,friend_id) DO UPDATE SET status='accepted'",[a.id,r.rows[0].id]);
 send(sockets.get(from),{type:"friend-accepted",username:a.username});res.json({ok:true});
});
app.get("/api/friends",async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();const r=await pool.query("SELECT u.username,u.display_name,u.description,u.name_color,u.avatar_image_id,u.status_text,u.status_expires_at,f.nickname FROM friendships f JOIN users u ON u.id=f.friend_id WHERE f.user_id=$1 AND f.status='accepted' ORDER BY u.username",[a.id]);res.json(r.rows.map(u=>({...publicUser(u),nickname:u.nickname||''})))});
app.patch("/api/friends/:username/nickname",async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();const username=clean(req.params.username),nickname=String(req.body.nickname||'').trim().slice(0,40);const r=await pool.query("SELECT id FROM users WHERE username=$1",[username]);if(!r.rows[0])return res.status(404).json({error:'Usuário não encontrado.'});const q=await pool.query("UPDATE friendships SET nickname=$1 WHERE user_id=$2 AND friend_id=$3 AND status='accepted' RETURNING nickname",[nickname,a.id,r.rows[0].id]);if(!q.rows[0])return res.status(404).json({error:'Essa pessoa não está na sua lista de amigos.'});res.json({ok:true,nickname:q.rows[0].nickname})});
app.get("/api/friend-requests",async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();const r=await pool.query("SELECT u.username,u.display_name,u.description,u.name_color,u.avatar_image_id,u.status_text,u.status_expires_at FROM friendships f JOIN users u ON u.id=f.user_id WHERE f.friend_id=$1 AND f.status='pending' ORDER BY f.created_at",[a.id]);res.json(r.rows.map(publicUser))});
app.post("/api/friends/reject",async(req,res)=>{const a=auth(req),from=clean(req.body.username);if(!a)return res.status(401).end();const r=await pool.query("SELECT id FROM users WHERE username=$1",[from]);if(r.rows[0])await pool.query("DELETE FROM friendships WHERE user_id=$1 AND friend_id=$2 AND status='pending'",[r.rows[0].id,a.id]);res.json({ok:true})});
app.patch("/api/profile",async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();const displayName=String(req.body.displayName||"").trim().slice(0,40);const description=String(req.body.description||"").trim().slice(0,160);const nameColor=/^#[0-9a-fA-F]{6}$/.test(String(req.body.nameColor||""))?String(req.body.nameColor):"#d44e82";if(!displayName)return res.status(400).json({error:"Informe um nome."});const r=await pool.query("UPDATE users SET display_name=$1,description=$2,name_color=$3 WHERE id=$4 RETURNING username,display_name,description,name_color,avatar_image_id,banner_image_id,status_text,status_expires_at",[displayName,description,nameColor,a.id]);const user=publicUser(r.rows[0]);broadcast({type:'profile-update',user});res.json(user)});
app.patch("/api/profile/status",async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();const status=String(req.body.status||"").trim().slice(0,120);let expires=null;if(status)expires=new Date(Date.now()+24*60*60*1000);const r=await pool.query("UPDATE users SET status_text=$1,status_expires_at=$2 WHERE id=$3 RETURNING username,display_name,description,name_color,avatar_image_id,banner_image_id,status_text,status_expires_at",[status,expires,a.id]);const user=publicUser(r.rows[0]);broadcast({type:"profile-update",user});res.json(user)});
app.post("/api/profile/avatar",upload.single("image"),async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();if(!req.file||!req.file.mimetype.startsWith("image/"))return res.status(400).json({error:"Envie uma imagem."});const imageId=id();await pool.query("INSERT INTO images(id,user_id,mime_type,data) VALUES($1,$2,$3,$4)",[imageId,a.id,req.file.mimetype,req.file.buffer]);const r=await pool.query("UPDATE users SET avatar_image_id=$1 WHERE id=$2 RETURNING username,display_name,description,name_color,avatar_image_id",[imageId,a.id]);const user=publicUser(r.rows[0]);broadcast({type:'profile-update',user});res.json({id:imageId,url:"/api/images/"+imageId,user})});
app.post("/api/profile/banner",upload.single("image"),async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();if(!req.file||!req.file.mimetype.startsWith("image/"))return res.status(400).json({error:"Envie uma imagem."});const imageId=id();await pool.query("INSERT INTO images(id,user_id,mime_type,data) VALUES($1,$2,$3,$4)",[imageId,a.id,req.file.mimetype,req.file.buffer]);const r=await pool.query("UPDATE users SET banner_image_id=$1 WHERE id=$2 RETURNING username,display_name,description,name_color,avatar_image_id,banner_image_id,status_text,status_expires_at",[imageId,a.id]);const user=publicUser(r.rows[0]);broadcast({type:'profile-update',user});res.json({id:imageId,url:"/api/images/"+imageId,user})});
app.post("/api/groups/:id/leave",async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();const gid=req.params.id;const r=await pool.query("SELECT owner_id FROM groups WHERE id=$1",[gid]);if(!r.rows[0])return res.status(404).json({error:"Grupo não encontrado."});if(r.rows[0].owner_id===a.id)return res.status(400).json({error:"A dona do grupo não pode sair. Exclua o grupo ou transfira a propriedade primeiro."});await pool.query("DELETE FROM group_members WHERE group_id=$1 AND user_id=$2",[gid,a.id]);res.json({ok:true})});
app.get("/api/groups",async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();const r=await pool.query("SELECT g.id,g.name,COALESCE((SELECT json_agg(json_build_object('username',u.username,'displayName',u.display_name,'avatarId',u.avatar_image_id,'status',CASE WHEN u.status_expires_at IS NOT NULL AND u.status_expires_at<=NOW() THEN '' ELSE COALESCE(u.status_text,'') END) ORDER BY u.username) FROM group_members gm JOIN users u ON u.id=gm.user_id WHERE gm.group_id=g.id),'[]') AS members FROM groups g JOIN group_members mine ON mine.group_id=g.id WHERE mine.user_id=$1 ORDER BY g.created_at",[a.id]);res.json(r.rows.map(g=>({...g,members:(g.members||[]).map(u=>({...u,online:!!sockets.get(u.username)}))})))});
app.post("/api/groups",async(req,res)=>{const a=auth(req),name=String(req.body.name||"").trim().slice(0,80),names=Array.isArray(req.body.usernames)?req.body.usernames.map(clean).filter(Boolean):[];if(!a)return res.status(401).end();if(!name||!names.length)return res.status(400).json({error:"Informe o nome e pelo menos um amigo."});const unique=[...new Set(names.filter(n=>n!==a.username))];const r=await pool.query("SELECT u.id,u.username FROM users u JOIN friendships f ON f.friend_id=u.id WHERE f.user_id=$1 AND f.status='accepted' AND u.username=ANY($2::text[])",[a.id,unique]);if(r.rows.length!==unique.length)return res.status(400).json({error:"Só é possível adicionar amigos."});const gid=id();await pool.query("INSERT INTO groups(id,name,owner_id) VALUES($1,$2,$3)",[gid,name,a.id]);await pool.query("INSERT INTO group_members(group_id,user_id) VALUES($1,$2)",[gid,a.id]);for(const u of r.rows)await pool.query("INSERT INTO group_members(group_id,user_id) VALUES($1,$2)",[gid,u.id]);for(const u of [a.username,...r.rows.map(x=>x.username)])send(sockets.get(u),{type:"group-created",groupId:gid,name});res.json({id:gid,name})});
app.get("/api/unread",async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();const u=(await pool.query("SELECT username FROM users WHERE id=$1",[a.id])).rows[0]?.username;const r=await pool.query(`SELECT m.room,COUNT(*)::int AS count FROM messages m LEFT JOIN read_receipts rr ON rr.user_id=$1 AND rr.room=m.room WHERE m.user_id<>$1 AND m.created_at>COALESCE(rr.last_read_at,'epoch'::timestamptz) AND ((m.room LIKE '%:%' AND (split_part(m.room,':',1)=$2 OR split_part(m.room,':',2)=$2)) OR m.room LIKE 'group:%' AND EXISTS(SELECT 1 FROM group_members gm JOIN groups g ON g.id=split_part(m.room,'group:',2)::uuid WHERE gm.group_id=g.id AND gm.user_id=$1)) GROUP BY m.room`,[a.id,u]);res.json(Object.fromEntries(r.rows.map(x=>[x.room,x.count])))});
app.post("/api/rooms/:room/read",async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();const room=String(req.params.room).slice(0,100);await pool.query(`INSERT INTO read_receipts(user_id,room,last_read_at) VALUES($1,$2,NOW()) ON CONFLICT(user_id,room) DO UPDATE SET last_read_at=EXCLUDED.last_read_at`,[a.id,room]);res.json({ok:true})});
app.get("/api/rooms/:room/messages",async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();const room=String(req.params.room).slice(0,100);const r=await pool.query(`SELECT m.id,u.username,u.display_name AS "displayName",u.description,u.name_color AS "nameColor",u.avatar_image_id AS "avatarId",m.text,m.image_id AS "imageId",m.created_at AS time FROM messages m LEFT JOIN users u ON u.id=m.user_id WHERE room=$1 ORDER BY m.created_at DESC LIMIT 100`,[room]);res.json(r.rows.reverse())});
app.post("/api/upload-image",upload.single("image"),async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();if(!req.file)return res.status(400).json({error:"Imagem não enviada."});if(!req.file.mimetype.startsWith("image/"))return res.status(400).json({error:"Envie uma imagem."});const imageId=id();await pool.query("INSERT INTO images(id,user_id,mime_type,data) VALUES($1,$2,$3,$4)",[imageId,a.id,req.file.mimetype,req.file.buffer]);res.json({id:imageId,url:"/api/images/"+imageId})});
app.get("/api/images/:id",async(req,res)=>{const r=await pool.query("SELECT mime_type,data FROM images WHERE id=$1",[req.params.id]);if(!r.rows[0])return res.status(404).end();res.setHeader("Content-Type",r.rows[0].mime_type);res.setHeader("Cache-Control","public,max-age=31536000,immutable");res.end(r.rows[0].data)});

wss.on("connection",ws=>{
 ws.id=id();ws.username=null;ws.room=null;
 ws.on("message",async raw=>{
  let m;try{m=JSON.parse(raw)}catch{return}
  if(m.type==="auth"){try{const a=jwt.verify(m.token,JWT_SECRET);const r=await pool.query("SELECT username FROM users WHERE id=$1",[a.id]);if(!r.rows[0])throw 0;ws.username=r.rows[0].username;sockets.set(ws.username,ws);send(ws,{type:"ready",username:ws.username});broadcast({type:"presence",username:ws.username,online:true})}catch{send(ws,{type:"error",message:"Sessão inválida."})}return}
  if(!ws.username)return;
  if(m.type==="join"){if(ws.room)rooms.get(ws.room)?.delete(ws);ws.room=String(m.room||"geral").slice(0,100);if(!rooms.has(ws.room))rooms.set(ws.room,new Set);rooms.get(ws.room).add(ws);return}
  if(m.type==="mark-read"){const room=String(m.room||"").slice(0,100);if(room){const r=await pool.query("SELECT id FROM users WHERE username=$1",[ws.username]);if(r.rows[0])await pool.query(`INSERT INTO read_receipts(user_id,room,last_read_at) VALUES($1,$2,NOW()) ON CONFLICT(user_id,room) DO UPDATE SET last_read_at=EXCLUDED.last_read_at`,[r.rows[0].id,room])}return}
  if(m.type==="room-chat"){const text=String(m.text||"").trim().slice(0,3000);if(!text||!ws.room)return;const r=await pool.query("SELECT id FROM users WHERE username=$1",[ws.username]);const sender=(await pool.query("SELECT username,display_name,description,name_color,avatar_image_id,banner_image_id,status_text,status_expires_at FROM users WHERE username=$1",[ws.username])).rows[0];const item={id:id(),room:ws.room,username:ws.username,displayName:sender?.display_name||ws.username,description:sender?.description||"",nameColor:sender?.name_color||"#d44e82",avatarId:sender?.avatar_image_id||null,text,time:new Date().toISOString()};await pool.query("INSERT INTO messages(id,room,user_id,text) VALUES($1,$2,$3,$4)",[item.id,ws.room,r.rows[0].id,text]);for(const c of rooms.get(ws.room)||[])send(c,{type:"chat",...item});await notifyUnread(ws.room,ws.username,item)}
  if(m.type==="room-image"){if(!ws.room||!m.imageId)return;const r=await pool.query("SELECT id FROM users WHERE username=$1",[ws.username]);const sender=(await pool.query("SELECT username,display_name,description,name_color,avatar_image_id,banner_image_id,status_text,status_expires_at FROM users WHERE username=$1",[ws.username])).rows[0];const item={id:id(),room:ws.room,username:ws.username,displayName:sender?.display_name||ws.username,description:sender?.description||"",nameColor:sender?.name_color||"#d44e82",avatarId:sender?.avatar_image_id||null,text:"",imageId:m.imageId,time:new Date().toISOString()};await pool.query("INSERT INTO messages(id,room,user_id,text,image_id) VALUES($1,$2,$3,$4,$5)",[item.id,ws.room,r.rows[0].id,"[imagem]",m.imageId]);for(const c of rooms.get(ws.room)||[])send(c,{type:"chat",...item});await notifyUnread(ws.room,ws.username,item);return}
  if(["call-offer","call-answer","ice-candidate","call-end","call-renegotiate","call-media"].includes(m.type)){const peer=sockets.get(clean(m.target));if(peer)send(peer,{...m,from:ws.username})}
 });
 ws.on("close",()=>{if(ws.username&&sockets.get(ws.username)===ws){sockets.delete(ws.username);broadcast({type:"presence",username:ws.username,online:false})}if(ws.room)rooms.get(ws.room)?.delete(ws)});
});
initDB().then(()=>server.listen(PORT,()=>console.log(`PastelChat production on :${PORT}`))).catch(e=>{console.error(e);process.exit(1)});
