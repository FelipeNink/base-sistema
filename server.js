
const express = require("express");
const multer = require("multer");
const storage = multer.diskStorage({

    destination: (req, file, cb) => {

        cb(null, "uploads/");
    },

    filename: (req, file, cb) => {

        cb(
            null,
            Date.now() + "-" + file.originalname
        );
    }
});

const upload = multer({ storage });
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const path = require("path");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;


const app = express();
const db = new sqlite3.Database("./database/database.db");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
    secret: "segredo_sistema",
    resave: false,
    saveUninitialized: false
}));


app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({

    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"

},
(accessToken, refreshToken, profile, done) => {

    const email = profile.emails[0].value;

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [email],
        (err, user) => {

            if (user) {
                return done(null, user);
            }

            db.run(
                `
                INSERT INTO users (username, password)
                VALUES (?, ?)
                `,
                [email, "google_login"],
                function(err) {

                    db.get(
                        "SELECT * FROM users WHERE id = ?",
                        [this.lastID],
                        (err, novoUser) => {

                            done(null, novoUser);
                        }
                    );
                }
            );
        }
    );
}));
passport.serializeUser((user, done) => {

    done(null, user.id);
});

passport.deserializeUser((id, done) => {

    db.get(
        "SELECT * FROM users WHERE id = ?",
        [id],
        (err, user) => {

            done(err, user);
        }
    );
});
app.get("/auth/google",

    passport.authenticate("google", {
        scope: ["profile", "email"]
    })
);

app.get(
    "/auth/google/callback",

    passport.authenticate("google", {
        failureRedirect: "/"
    }),

    (req, res) => {

        req.session.userId = req.user.id;

        res.redirect("/dashboard.html");
    }
);

app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS pessoas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT,
            cpf TEXT,
            funcao TEXT,
            nascimento TEXT,
            email TEXT,
            telefone TEXT,
            endereco TEXT,
            arquivo TEXT,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);
    db.run(`
    CREATE TABLE IF NOT EXISTS funcoes (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        nome TEXT,

        user_id INTEGER,

        FOREIGN KEY(user_id) REFERENCES users(id)
    )
`);
});

function auth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect("/");
    }
}

app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.send(`
            <script>
                alert("Preencha todos os campos!");
                window.location.href = "/register.html";
            </script>
        `);
    }

    const hash = await bcrypt.hash(password, 10);

    db.run(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hash],
        function(err) {

            if (err) {
                return res.send(`
                    <script>
                        alert("Usuário já existe!");
                        window.location.href = "/register.html";
                    </script>
                `);
            }

            return res.send(`
                <script>
                    alert("Usuário cadastrado com sucesso!");
                    window.location.href = "/";
                </script>
            `);
        }
    );
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {
            if (!user) {
                return res.send("Usuário não encontrado.");
            }

            const valid = await bcrypt.compare(password, user.password);

            if (!valid) {
                return res.send("Senha inválida.");
            }

            req.session.userId = user.id;
            res.redirect("/dashboard.html");
        }
    );
});

app.post("/cadastrar", auth, upload.single("arquivo"), (req, res) => {

    const arquivo = req.file
        ? req.file.filename
        : null;

    const {
        nome,
        cpf,
        funcao,
        nascimento,
        email,
        telefone,
        endereco
    } = req.body;

    const userId = req.session.userId;

    db.run(
        `
        INSERT INTO pessoas
        (
            nome,
            cpf,
            funcao,
            nascimento,
            email,
            telefone,
            endereco,
            arquivo,
            user_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
            nome,
            cpf,
            funcao,
            nascimento,
            email,
            telefone,
            endereco,
            arquivo,
            userId
        ],
        (err) => {

            if (err) {

                console.log(err);

                return res.send(`
                    <script>
                        alert("Erro ao cadastrar pessoa!");
                        window.location.href = "/cadastrar.html";
                    </script>
                `);
            }

            return res.send(`
                <script>
                    alert("Pessoa cadastrada com sucesso!");
                    window.location.href = "/pessoas.html";
                </script>
            `);
        }
    );
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});
app.get("/pessoas", auth, (req, res) => {

    const pesquisa = req.query.nome || "";
    const userId = req.session.userId;

    db.all(
        `
        SELECT * FROM pessoas
        WHERE nome LIKE ?
        AND user_id = ?
        `,
        [`%${pesquisa}%`, userId],
        (err, rows) => {

            if (err) {
                return res.json([]);
            }

            res.json(rows);
        }
    );
});
app.get("/pessoa/:id", auth, (req, res) => {

    const id = req.params.id;
    const userId = req.session.userId;

    db.get(
        `
        SELECT * FROM pessoas
        WHERE id = ?
        AND user_id = ?
        `,
        [id, userId],
        (err, row) => {

            if (err || !row) {
                return res.json(null);
            }

            res.json(row);
        }
    );
});
app.post("/editar/:id", auth, upload.single("arquivo"), (req, res) => {

    const id = req.params.id;
    const userId = req.session.userId;

    const arquivo = req.file
    ? req.file.filename
    : req.body.arquivoAtual;

    const {
    nome,
    cpf,
    funcao,
    nascimento,
    email,
    telefone,
    endereco
    } = req.body;

    db.run(
        `
        UPDATE pessoas
        SET
            nome = ?,
            cpf = ?,
            funcao = ?,
            nascimento = ?,
            email = ?,
            telefone = ?,
            endereco = ?,
            arquivo = ?
        WHERE id = ?
        AND user_id = ?
        `,
        [
            nome,
            cpf,
            funcao,
            nascimento,
            email,
            telefone,
            endereco,
            arquivo,
            id,
            userId
        ],
        function(err) {

            if (err) {

                return res.send(`
                    <script>
                        alert("Erro ao editar cadastro!");
                        window.history.back();
                    </script>
                `);
            }

            return res.send(`
                <script>
                    alert("Cadastro atualizado com sucesso!");
                    window.location.href = "/pessoas.html";
                </script>
            `);
        }
    );
});
app.post("/excluir/:id", auth, (req, res) => {

    const id = req.params.id;
    const userId = req.session.userId;

    db.run(
        `
        DELETE FROM pessoas
        WHERE id = ?
        AND user_id = ?
        `,
        [id, userId],
        function(err) {

            if (err) {

                return res.send(`
                    <script>
                        alert("Erro ao excluir cadastro!");
                        window.location.href = "/pessoas.html";
                    </script>
                `);
            }

            return res.send(`
                <script>
                    alert("Cadastro excluído com sucesso!");
                    window.location.href = "/pessoas.html";
                </script>
            `);
        }
    );
});
app.post("/funcoes", auth, (req, res) => {

    const { nome } = req.body;

    const userId = req.session.userId;

    db.run(
        `
        INSERT INTO funcoes (nome, user_id)
        VALUES (?, ?)
        `,
        [nome, userId],
        (err) => {

            if (err) {

                return res.send(`
                    <script>
                        alert("Erro ao criar função!");
                        window.location.href = "/funcoes.html";
                    </script>
                `);
            }

            return res.send(`
                <script>
                    alert("Função criada com sucesso!");
                    window.location.href = "/funcoes.html";
                </script>
            `);
        }
    );
});
app.get("/funcoes", auth, (req, res) => {

    const userId = req.session.userId;

    const pesquisa = req.query.nome || "";

    db.all(
        `
        SELECT
            funcoes.id,
            funcoes.nome,

            COUNT(pessoas.id) AS total_pessoas

        FROM funcoes

        LEFT JOIN pessoas
            ON pessoas.funcao = funcoes.nome
            AND pessoas.user_id = funcoes.user_id

        WHERE funcoes.user_id = ?
        AND funcoes.nome LIKE ?

        GROUP BY funcoes.id

        ORDER BY funcoes.nome ASC
        `,
        [userId, `%${pesquisa}%`],
        (err, rows) => {

            if (err) {

                return res.json([]);
            }

            res.json(rows);
        }
    );
});
app.get("/funcao/:id/pessoas", auth, (req, res) => {

    const id = req.params.id;
    const userId = req.session.userId;

    db.all(
        `
        SELECT * FROM pessoas
        WHERE funcao = (
            SELECT nome
            FROM funcoes
            WHERE id = ?
        )
        AND user_id = ?
        `,
        [id, userId],
        (err, rows) => {

            if (err) {
                return res.json([]);
            }

            res.json(rows);
        }
    );
});

app.listen(3000, () => {
    console.log("Servidor rodando em http://localhost:3000");
});
