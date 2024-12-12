import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import 'dotenv/config';

var app=express();
const db = new pg.Client({
    user:"postgres",
    host:"localhost",
    database:"todo",
    password:"Shubha1@2#",
    port:5432
});
db.connect();
async function findOrCreateUser(profile, cb) { 
    try { 
        const result = await db.query("SELECT * FROM users WHERE google_id = $1", [profile.id]); 
        if (result.rows.length > 0) { 
            // User exists 
            return cb(null, result.rows[0]); 
        } else { 
            // User does not exist, create a new user 
            const newUser = { 
                username: profile.displayName, 
                googleId: profile.id, 
                password: await bcrypt.hash('default_password', 10) // This is a placeholder, handle password more securely 
            }; 
            const insertResult = await db.query( "INSERT INTO users (email, google_id, password) VALUES ($1, $2, $3) RETURNING *", 
                [newUser.username, newUser.googleId, newUser.password] ); 
                return cb(null, insertResult.rows[0]); 
            } 
        } catch (err){
            console.log(err)
        }
    }


passport.use(new GoogleStrategy({
    clientID: process.env.clientID,
    clientSecret: process.env.clientSecret,
    callbackURL: "http://localhost:3000/auth/google/t",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    findOrCreateUser(profile, cb);   
  }
));
passport.serializeUser((user, done) => { 
    done(null, user.id); 
}); 
passport.deserializeUser(async (id, done) => { 
    try { const result = await db.query("SELECT * FROM users WHERE id = $1", [id]); 
        done(null, result.rows[0]); 
    } catch (err) { 
        done(err, null); 
    } 
});
app.use(bodyParser.json());
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended:true}));
app.use(session({ 
    secret: process.env.key, 
    resave: false, 
    saveUninitialized: true, 
    cookie: { secure: false }  
    }));

app.use(passport.initialize());
app.use(passport.session());
let date=new Date().toISOString().split('T')[0];

app.get("/register", (req,res)=>{
    res.render("register.ejs");
})

app.post("/register", async(req,res)=>{
    var password = await bcrypt.hash(req.body.password, 10);
    await db.query("insert into users(email,password) values($1,$2)", [req.body.username, password]);
    const result = await db.query("select * from users where email=$1", [req.body.username]);
    req.session.userId = result.rows[0].id;
    res.redirect("/");
})

app.get("/login", (req,res)=>{
    res.render("login.ejs");
})
app.post("/login", async(req,res)=>{
    const result = await db.query("select * from users where email=$1", [req.body.username]);
    if(result.rows.length>0){
        if(await bcrypt.compare(req.body.password, result.rows[0].password)){
            req.session.userId = result.rows[0].id;
            req.logIn(result.rows[0], function(err){
                if(err){
                    console.log(err);
                }
                else{
                    res.redirect("/");
                }
            })
        }
    }else{
        res.render("login.ejs");
    }
})

app.get("/",async(req,res)=>{
    if (req.session.userId) {
    if(req.query.date){
        date=req.query.date;
    }else{
        date = date;
    }
    const result = await db.query("SELECT * FROM mytodo WHERE dates=$1 AND user_id=$2", [date, req.session.userId]);
    res.render("index.ejs",{
        date:date,
        tasks:result.rows
    });
    }else{
        res.redirect("/login");
    }
});
app.post("/add", async(req,res)=>{
    await db.query("insert into mytodo(tdo,dates,user_id) values($1,$2,$3)", [req.body.task, req.body.date, req.session.userId]);
    res.redirect("/");
})
app.post("/delete", async(req,res)=>{
    await db.query("DELETE FROM mytodo WHERE tdo = $1 AND dates = $2 AND user_id = $3;", [req.body.task, req.body.date, req.session.userId]);
    res.redirect("/");
})
app.get("/auth/google", (req, res) => {
    passport.authenticate("google", { scope: ["profile", "email"] })(req, res);
})
app.get("/auth/google/t", 
    passport.authenticate("google", { failureRedirect: "/login" }), async(req, res) => {
    const result = await db.query("select * from users where google_id=$1", [req.user.google_id]);
    req.session.userId = result.rows[0].id;
    res.redirect("/");
})
app.get("/logout", (req, res) => {
    req.session.destroy((err) => { 
        if (err) { 
            return res.status(500).send('Error in session destruction'); 
        } 
        res.redirect('/login');
    });
});
app.listen(3000,()=>{
    console.log("server started");
});

