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
app.get("/api/health",(req,res)=>res.json({ok:true}));

const sockets=new Map(), rooms=new Map();
const clean=u=>String(u||"").trim().toLowerCase().replace(/^@/,"");
const id=()=>crypto.randomUUID();
const send=(ws,o)=>ws?.readyState===1&&ws.send(JSON.stringify(o));
function auth(req){try{return jwt.verify((req.headers.authorization||"").replace("Bearer ",""),JWT_SECRET)}catch{return null}}

async function initDB(){
 await pool.query(`CREATE TABLE IF NOT EXISTS users(
 id UUID PRIMARY KEY, username VARCHAR(24) UNIQUE NOT NULL,
 display_name VARCHAR(60) NOT NULL, password_hash TEXT NOT NULL,
 created_at TIMESTAMPTZ DEFAULT now()
 );
 CREATE TABLE IF NOT EXISTS friendships(
 user_id UUID REFERENCES users(id) ON DELETE CASCADE,
 friend_id UUID REFERENCES users(id) ON DELETE CASCADE,
 status VARCHAR(12) NOT NULL CHECK(status IN ('pending','accepted')),
 created_at TIMESTAMPTZ DEFAULT now(),
 PRIMARY KEY(user_id,friend_id)
 );
 CREATE TABLE IF NOT EXISTS messages(
 id UUID PRIMARY KEY, room VARCHAR(100) NOT NULL, user_id UUID REFERENCES users(id) ON DELETE SET NULL,
 text TEXT NOT NULL, image_id UUID, created_at TIMESTAMPTZ DEFAULT now()
 );
 CREATE INDEX IF NOT EXISTS messages_room_time ON messages(room,created_at);
 ALTER TABLE messages ADD COLUMN IF NOT EXISTS image_id UUID;
 CREATE TABLE IF NOT EXISTS images(
 id UUID PRIMARY KEY, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
 mime_type VARCHAR(100) NOT NULL, data BYTEA NOT NULL, created_at TIMESTAMPTZ DEFAULT now()
 );`);
}
function publicUser(u){return {username:u.username,displayName:u.display_name,online:!!sockets.get(u.username)}}

app.post("/api/auth/register",async(req,res)=>{
 try{
  const u=clean(req.body.username), p=String(req.body.password||""), d=String(req.body.displayName||u).trim().slice(0,60);
  if(!/^[a-z0-9_.-]{2,24}$/.test(u)||p.length<8)return res.status(400).json({error:"Username inválido ou senha deve ter 8+ caracteres."});
  const hash=await bcrypt.hash(p,12), idv=id();
  const r=await pool.query("INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,$4) RETURNING id,username,display_name",[idv,u,d,hash]);
  const token=jwt.sign({id:idv,username:u},JWT_SECRET,{expiresIn:"7d"});res.json({token,user:publicUser(r.rows[0])});
 }catch(e){res.status(e.code==="23505"?409:500).json({error:e.code==="23505"?"Username já existe.":"Erro no servidor."})}
});
app.post("/api/auth/login",async(req,res)=>{
 const u=clean(req.body.username), p=String(req.body.password||"");
 const r=await pool.query("SELECT * FROM users WHERE username=$1",[u]); const user=r.rows[0];
 if(!user||!(await bcrypt.compare(p,user.password_hash)))return res.status(401).json({error:"Login inválido."});
 res.json({token:jwt.sign({id:user.id,username:u},JWT_SECRET,{expiresIn:"7d"}),user:publicUser(user)});
});
app.get("/api/me",async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();const r=await pool.query("SELECT id,username,display_name FROM users WHERE id=$1",[a.id]);if(!r.rows[0])return res.status(401).end();res.json(publicUser(r.rows[0]))});
app.get("/api/users/:username",async(req,res)=>{const r=await pool.query("SELECT id,username,display_name FROM users WHERE username=$1",[clean(req.params.username)]);if(!r.rows[0])return res.status(404).json({error:"Usuário não encontrado"});res.json(publicUser(r.rows[0]))});
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
app.get("/api/friends",async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();const r=await pool.query("SELECT u.username,u.display_name FROM friendships f JOIN users u ON u.id=f.friend_id WHERE f.user_id=$1 AND f.status='accepted' ORDER BY u.username",[a.id]);res.json(r.rows.map(publicUser))});
app.get("/api/rooms/:room/messages",async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();const room=String(req.params.room).slice(0,100);const r=await pool.query("SELECT m.id,u.username,m.text,m.image_id,m.created_at AS time FROM messages m LEFT JOIN users u ON u.id=m.user_id WHERE room=$1 ORDER BY m.created_at DESC LIMIT 100",[room]);res.json(r.rows.reverse())});
app.post("/api/upload-image",upload.single("image"),async(req,res)=>{const a=auth(req);if(!a)return res.status(401).end();if(!req.file)return res.status(400).json({error:"Imagem não enviada."});if(!req.file.mimetype.startsWith("image/"))return res.status(400).json({error:"Envie uma imagem."});const imageId=id();await pool.query("INSERT INTO images(id,user_id,mime_type,data) VALUES($1,$2,$3,$4)",[imageId,a.id,req.file.mimetype,req.file.buffer]);res.json({id:imageId,url:"/api/images/"+imageId})});
app.get("/api/images/:id",async(req,res)=>{const r=await pool.query("SELECT mime_type,data FROM images WHERE id=$1",[req.params.id]);if(!r.rows[0])return res.status(404).end();res.setHeader("Content-Type",r.rows[0].mime_type);res.setHeader("Cache-Control","public,max-age=31536000,immutable");res.end(r.rows[0].data)});

wss.on("connection",ws=>{
 ws.id=id();ws.username=null;ws.room=null;
 ws.on("message",async raw=>{
  let m;try{m=JSON.parse(raw)}catch{return}
  if(m.type==="auth"){try{const a=jwt.verify(m.token,JWT_SECRET);const r=await pool.query("SELECT username FROM users WHERE id=$1",[a.id]);if(!r.rows[0])throw 0;ws.username=r.rows[0].username;sockets.set(ws.username,ws);send(ws,{type:"ready",username:ws.username})}catch{send(ws,{type:"error",message:"Sessão inválida."})}return}
  if(!ws.username)return;
  if(m.type==="join"){if(ws.room)rooms.get(ws.room)?.delete(ws);ws.room=String(m.room||"geral").slice(0,100);if(!rooms.has(ws.room))rooms.set(ws.room,new Set);rooms.get(ws.room).add(ws);return}
  if(m.type==="room-chat"){const text=String(m.text||"").trim().slice(0,3000);if(!text||!ws.room)return;const r=await pool.query("SELECT id FROM users WHERE username=$1",[ws.username]);const item={id:id(),username:ws.username,text,time:new Date().toISOString()};await pool.query("INSERT INTO messages(id,room,user_id,text) VALUES($1,$2,$3,$4)",[item.id,ws.room,r.rows[0].id,text]);for(const c of rooms.get(ws.room)||[])send(c,{type:"chat",...item})}
  if(m.type==="room-image"){if(!ws.room||!m.imageId)return;const r=await pool.query("SELECT id FROM users WHERE username=$1",[ws.username]);const item={id:id(),username:ws.username,text:"",imageId:m.imageId,time:new Date().toISOString()};await pool.query("INSERT INTO messages(id,room,user_id,text,image_id) VALUES($1,$2,$3,$4,$5)",[item.id,ws.room,r.rows[0].id,"[imagem]",m.imageId]);for(const c of rooms.get(ws.room)||[])send(c,{type:"chat",...item});return}
  if(["call-offer","call-answer","ice-candidate","call-end","call-renegotiate"].includes(m.type)){const peer=sockets.get(clean(m.target));if(peer)send(peer,{...m,from:ws.username})}
 });
 ws.on("close",()=>{if(ws.username&&sockets.get(ws.username)===ws)sockets.delete(ws.username);if(ws.room)rooms.get(ws.room)?.delete(ws)});
});
initDB().then(()=>server.listen(PORT,()=>console.log(`PastelChat production on :${PORT}`))).catch(e=>{console.error(e);process.exit(1)});
