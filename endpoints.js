const pg = require('pg')
const pool = new pg.Pool({
    user: 'your_username',
    host: 'your_hostname',
    database: 'your_database',
    password: 'your_password',  
    port: 5432,
})
const crypto = require('crypto')
const jwt = require('jsonwebtoken')

const jwtSecret = "jwt_secret"



module.exports = (app) => {
    app.post("/users", registra)
    app.post("/sessions", login)
    app.post("/sessions/:sessionID", auth, logout)
    app.post("/posts/text", auth, creapostTesto)
    app.post("/posts/image", auth, creapostImmagine)
    app.post("/users/follow/:username", auth, follow)
    app.post("/posts/likes/:postID", auth, likepost)
    app.post("/posts/flag/:postID", auth, flaggapost)
    app.post("/users/moderator/:username", auth, nominamod)
    app.post("/users/unmod/:username", auth, rimuovimod)
    app.post("/posts/moderation/:postID", auth, moderapost)
    app.post("/users/ban/:username", auth, ban)
    app.post("/users/unban/:username", auth, unban)
    app.get("/users/cerca", cercauser)  
    app.get("/feed", auth, bacheca)
    app.get("/users/following", auth, listaseguiti)
    app.get("/users/followers", auth, listafollowers)
    app.get("/posts/flagged", auth, elencaflaggati)
    app.get("/posts/flagged/:username", auth, postflaggati)
    app.get("/users/:username", auth, getprofile)
    app.get("/posts/:postID", auth, dettaglipost)
    app.put("/users/profilepic", auth, updatefoto)       
    app.delete("/users/unfollow/:username", auth, unfollow) 
    app.delete("/users/:username", auth, deleteuser)   
    app.delete("/posts/likes/:postID", auth, unlike)
    app.delete("/posts/flag/:postID", auth, unflag) 
    app.delete("/posts/moderation/:postID", auth, unmoderapost)
    app.delete("/posts/:postID", auth, eliminapost)   
}

const auth = (req, res, next) => {    //OK
  const token = req.headers['bearer']

    if(!token)
      return res.status(400).send({message: 'No token provided'})

    jwt.verify(token, jwtSecret, (err, payload) => {
      if(err)
        return res.status(401).send({message: 'Token not valid'})

      const sessionID = payload.sessionID
      if (!sessionID) return res.status(401).json({message: "Token senza sessione"})

      pool.query(
        `SELECT 1 FROM sessione WHERE idsessione = $1`,
        [ sessionID ]
      )
      .then(({rows}) => {
        if (!rows.length) {
          return res.status(401).json({message: "Sessione non valida"})
        }

        req.user = {
        username: payload.username,
        admin: payload.admin,
        moderatore: payload.mod,
        sessionID: sessionID,
        }
        
        next()
    })
    .catch(dbErr => {
      console.error("Auth session check error:", dbErr)
      res.status(500).json({message: "DB error"})
    })      
  })
}

const registra = (req, res) => {    //OK
    //#swagger.tags = ["Auth"]
    //#swagger.summary = 'Registra utente'
    if(!req.body || !req.body.mail || !req.body.username || !req.body.passw)
        return res.status(400).send({message: 'parametri non validi'})

    const mail = req.body.mail.trim()
    const username = req.body.username.trim()

    const salt = crypto.randomBytes(16).toString('hex')

    pool.query(
      `SELECT
        CASE WHEN mail = $1 THEN 'mail' END AS conflict_mail,
        CASE WHEN username = $2 THEN 'username' END AS conflict_username
      FROM utente
      WHERE mail = $1 OR username = $2
      LIMIT 1`,
      [ mail, username ]
    )
    .then(({ rows }) => {
      if (rows.length > 0) {
        const row = rows[0]
        if (row.conflict_mail) {
          return res.status(400).json({ message: 'Mail già esistente, usarne un\'altra' })
        }
        if (row.conflict_username) {
          return res.status(400).json({ message: 'Username già esistente, usarne un altro' })
        }
      }

    crypto.scrypt(req.body.passw, salt, 64, (err, hash) => {
        const query = `
        INSERT INTO UTENTE (mail, username, passw)
        VALUES ($1, $2, $3);
        `
        const qvals = [req.body.mail, req.body.username, hash.toString('hex') + "." + salt]

        pool.query(query, qvals).then((results) => {
            return res.send(results.rows[0])
        }).catch((err) => {
            return res.status(500).send({message: 'query error'})
        })
    })
  })
}

const login = (req, res) => {   //OK (questa versione funziona anche con password in chiaro inserite a mano nel database)
  //#swagger.tags = ["Auth"]
  //#swagger.summary = 'Login utente'
  const { mailutente, usernameutente, passwordutente } = req.body
  if (!mailutente || !usernameutente || !passwordutente) {
    return res.status(400).json({ message: 'Parameter missing or invalid' })
  }

  pool.query(
    'SELECT passw, èamministratore, èmoderatore FROM utente WHERE mail=$1 AND username=$2',
    [ mailutente, usernameutente ]
  )
  .then(({ rows }) => {
    if (!rows.length) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    const stored = rows[0].passw        
    const admin  = rows[0].èamministratore
    const mod    = rows[0].èmoderatore

    // Crea sessione + token
    const creaSessioneEToken = () => {
      pool.query(
        `INSERT INTO sessione (datalogin, mailutente, usernameutente, passwordutente)
         VALUES (CURRENT_TIMESTAMP, $1, $2, $3)
         RETURNING idsessione`,
        [ mailutente, usernameutente, stored ]
      )
      .then(({ rows: insertRows }) => {
        const sessionID = insertRows[0].idsessione
        const token = jwt.sign(
          { username: usernameutente, sessionID, admin, mod },
          jwtSecret,
          { expiresIn: 15*60 }
        );
        res.json({ sessionID, token });
      })
      .catch(err => {
        console.error('Insert session error:', err)
        res.status(500).json({ message: 'DB error' })
      })
    }

    // Verifica credenziali
    if (stored.includes('.')) {
      // Caso normale
      const [hashPart, salt] = stored.split('.');
      crypto.scrypt(passwordutente, salt, 64, (err, derived) => {
        if (err) {
          console.error('scrypt error', err);
          return res.status(500).json({ message: 'Hashing error' })
        }
        if (derived.toString('hex') !== hashPart) {
          return res.status(401).json({ message: 'Invalid credentials' })
        }
        
        creaSessioneEToken();
      });
    } else {
      // Caso speciale: password salvata in chiaro a mano
      if (stored !== passwordutente) {
        return res.status(401).json({ message: 'Invalid credentials' })
      }
      
      creaSessioneEToken()
    }
  })
  .catch(err => {
    console.error('Select user hash error:', err)
    res.status(500).json({ message: 'DB error' })
  })
}

const logout = (req, res) => {    //OK
  //#swagger.tags = ["Auth"]
  //#swagger.summary = 'Logout utente'
  const sessionID = req.params.sessionID;
  pool.query(
    'DELETE FROM sessione WHERE idsessione = $1',
    [ sessionID ]
  )
  .then(() => res.status(200).send({message: 'Logout effettuato con successo'}))
  .catch(err => {
    console.error('Logout error:', err);
    res.status(500).json({ message: 'DB error' });
  });
}

const cercauser = (req, res) => {   //OK
  //#swagger.tags = ["Relationships"]
  //#swagger.summary = 'Cerca utente'  
  const q = req.query.q || '';
  pool.query(
    `SELECT mail, username, immagine
       FROM utente
      WHERE username ILIKE '%' || $1 || '%'
         OR mail     ILIKE '%' || $1 || '%'
      LIMIT 50`,
    [ q ]
  )
  .then(({ rows }) => res.json(rows))
  .catch(err => {
    console.error('Cerca user error:', err);
    res.status(500).json({ message: 'DB error' });
  });
}

const getprofile = (req, res) => {    //OK 
  //#swagger.tags = ["Profile"]
  //#swagger.summary = 'Profilo utente' 
  const user = req.params.username;

  pool.query(
    `SELECT
       u.mail, u.username, u.immagine AS profileImage,
       u.numFollowers AS followers,
       u.numFollow     AS following,
       u.postModerati AS moderatedCount,
       u.èBannato      AS isBanned,
       u.èModeratore  AS moderatore,
       u.èAmministratore  AS admin
     FROM utente u
     WHERE u.username = $1`,
    [ user ]
  )
  .then(({ rows }) => {
    if (!rows.length) return res.status(404).json({ message: 'Not found' });
    const profile = rows[0];
    pool.query(
      `SELECT
         p.id           AS postID,
         p.data         AS creationDate,
         CASE WHEN p.eTesto THEN 'Text' ELSE 'Image' END AS tipo,
         p.textcontent  AS textContent,
         p.imageurl     AS imageUrl,
         p.numLike      AS likes,
         p.numFlag      AS flags
       FROM post p
       WHERE p.username = $1
         AND p.èModerato = FALSE
       ORDER BY p.data DESC
       LIMIT 20`,
      [ user ]
    )
    .then(({ rows: posts }) => {
      profile.posts = posts;
      res.json(profile);
    })
    .catch(err => {
      console.error('Get posts error:', err);
      res.status(500).send({ message: 'DB error' });
    });
  })
}

const updatefoto = (req, res) => {    //OK
  //#swagger.tags = ["Profile"]
  //#swagger.summary = 'Aggiorna foto profilo'
  /*#swagger.requestBody = {
    required: true,
    content: {
      "multipart/form-data": {
      schema: {
        type: "object",
        properties: {
          avatar: { type: "string", format: "binary" }
          }
        }
      }
    }
  }*/
  const owner = req.user.username;
  if (!req.files?.avatar) return res.status(400).json({ message: 'avatar richiesto' });

  const file = req.files.avatar;
  const safeName = Date.now() + '-' + file.name.replace(/\s+/g, '_');
  const diskPath = 'resources/' + safeName;
  const publicUrl = '/resources/' + safeName;

  file.mv(diskPath, (err) => {
    if (err) return res.status(500).json({ message: 'Errore upload' });

    pool.query(
      `UPDATE utente
       SET immagine = $1
       WHERE username = $2
       RETURNING username, immagine`,
      [ publicUrl, owner ]
    )
    .then(({ rows }) => rows.length
      ? res.json({ message:'Foto aggiornata', username: rows[0].username, profilepic: rows[0].immagine })
      : res.status(404).json({ message:'Utente non trovato' })
    )
    .catch(() => res.status(500).json({ message:'DB error' }));
  });
}

const deleteuser = (req, res) => {    //OK
  //#swagger.tags = ["Profile"]
  //#swagger.summary = 'Elimina utente (solo proprietario e admin)'
  const user = req.params.username;

  if (req.user.username !== user && req.user.admin !== true) {
    return res.status(403).json({ message: 'Forbidden' });
  }

      pool.query(
        'DELETE FROM utente WHERE username=$1',
        [ user ]
      )
      .then(() => res.status(200).send({message: 'Utente eliminato'}))
      .catch(err => {
        console.error('Delete user error:', err);
        res.status(500).json({ message: 'DB error' });
      })
}

const creapostTesto = (req, res) => {   //OK
  //#swagger.tags = ["Create a post"]
  //#swagger.summary = 'Crea post di testo'   
  /*#swagger.requestBody = {
    required: true,
    content: {
      "multipart/form-data": {
        schema: {
          type: "object",
          properties: {
            textcontent: { type: "string" }
          }
        }
      }
    }
  }*/
  const owner = req.user?.username;
  if (!owner) return res.status(401).json({ message: 'Unauthorized' });

  const text = (req.body?.textcontent || '').trim();
  if (!text) return res.status(400).json({ message: 'textcontent obbligatorio' });

    pool.query(
    `SELECT u.èbannato AS banned
     FROM utente u
     WHERE u.username = $1`,
    [ owner ]
  )
  .then(({ rows }) => {
    if (!rows.length) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    if (rows[0].banned) {
      return res.status(403).json({ message: 'Ban: non puoi creare post (utente bannato)' });
    }

  return pool.query(
      `INSERT INTO post (username, etesto, eimmagine, textcontent, imageurl)
       VALUES ($1, TRUE, FALSE, $2, NULL)
       RETURNING id, data`,
      [ owner, text ]
    );
  })
  .then(result => {
    if (!result || !result.rows) return;
    const r = result.rows[0];
    res.status(201).json({ idpost: r.id, tipo: 'testo', data: r.data, content: text });
  })
  .catch(err => {
    console.error('Insert testo error:', err.code, err.detail);
    res.status(500).json({ message: 'DB error' });
  });
}

const creapostImmagine = (req, res) => {    //OK
  //#swagger.tags = ["Create a post"]
  //#swagger.summary = 'Crea post di immagine'
  /*#swagger.requestBody = {
    required: true,
    content: {
      "multipart/form-data": {
        schema: {
          type: "object",
          properties: {
            pimage: { type: "string", format: "binary" }
          }
        }
      }
    }
  }*/
  const owner = req.user?.username;
  if (!owner) return res.status(401).json({ message: 'Unauthorized' });
  if (!req.files?.pimage) return res.status(400).json({ message: 'pimage (file) obbligatorio' });

  pool.query(
  ` SELECT u.èbannato AS banned
    FROM utente u
    WHERE u.username = $1`, 
  [ owner ]
  )
  .then(({ rows }) => {
    if (!rows.length) return res.status(401).json({ message: 'Unauthorized' });
    if (rows[0].banned) {
      return res.status(403).json({ message: 'Ban: non puoi creare post (utente bannato)' });
    }

    const file = req.files.pimage;
    const safeName = Date.now() + '-' + file.name.replace(/\s+/g, '_');
    const diskPath = 'resources/' + safeName;   
    const publicUrl = '/resources/' + safeName;

    file.mv(diskPath, (err) => {
      if (err) return res.status(500).json({ message: 'Errore salvataggio file' });

      pool.query(
        `INSERT INTO post (username, etesto, eimmagine, textcontent, imageurl)
         VALUES ($1, FALSE, TRUE, NULL, $2)
         RETURNING id, data`,
        [ owner, publicUrl ]
      )
      .then(({ rows:[r] }) => res.status(201).json({
        idpost: r.id, tipo: 'immagine', data: r.data, imageurl: publicUrl
      }))
      .catch(err => {
        console.error('Insert immagine error:', err.code, err.detail);
        res.status(500).json({ message: 'DB error' });
      });
    });
  })
  .catch(err => {
    console.error('Ban check (image) error:', err.code, err.detail, err.message);
    res.status(500).json({ message: 'DB error' });
  });
}

const dettaglipost = (req, res) => {    //OK
  //#swagger.tags = ["Posts"]
  //#swagger.summary = 'Dettagli post'
  const id = req.params.postID;
  pool.query(
    `SELECT
       p.id           AS postID,
       p.username     AS author,
       p.data         AS creationDate,
       CASE WHEN p.eTesto THEN 'Text' ELSE 'Image' END AS tipo,
       p.textcontent  AS textContent,
       p.imageurl     AS imageUrl,
       p.numLike      AS likes,
       p.numFlag      AS flags,
       p.èModerato    AS isModerated
     FROM post p
     WHERE p.id = $1`,
    [ id ]
  )
  .then(({ rows }) => {
    if (!rows.length) return res.status(404).json({ message: 'Not found' });
    res.json(rows[0]);
  })
  .catch(err => {
    console.error('Detail post error:', err);
    res.status(500).json({ message: 'DB error' });
  });
}

const eliminapost = (req, res) => {   //OK
  //#swagger.tags = ["Posts"]
  //#swagger.summary = 'Elimina post (solo proprietario e admin) '
  const postID   = req.params.postID;
  const user = req.user.username;
  const isAdmin = req.user.admin === true

  //console.log("l'id è:", postID)

  pool.query(
    `SELECT username FROM post WHERE id = $1`,
    [ postID ]
  )
  .then(({rows}) => {
    if (!rows.length) {
      return res.status(404).json({message: "Post non trovato"})
    }

    const owner = rows[0].username 

    if (user !== owner && !isAdmin) {
      return res.status(403).json({message: "Forbidden"})
    }

    pool.query(
      `DELETE FROM post WHERE id = $1`,
      [postID]
    )
    .then(() => res.status(200).json({message: "Post eliminato"}))
    .catch(err => {
      console.error("Errore DELETE post:", err)
      res.status(500).json({message: "DB error"})
    })
  })
  .catch(err => {
    console.error("Errore SELECT post:", err)
    res.status(500).json({message: "DB error"})
  })  
}

const bacheca = (req, res) => {   //OK
  //#swagger.tags = ["Feed"]
  //#swagger.summary = 'Visualizza feed'
  /*#swagger.parameters['page'] = {
                                    in: 'query', 
                                    type: 'integer', 
                                    required: false, 
                                    default: 1
                                  }*/
  /*#swagger.parameters['pageSize'] = {
                                        in: 'query',
                                        type: 'integer',
                                        required: false,
                                        default: 10
                                      } */
  const me = req.user?.username;
  if (!me) return res.status(401).json({ message: 'Unauthorized' });

  const page     = Math.max(parseInt(req.query.page || '1', 10), 1);
  const pageSize = Math.min(Math.max(parseInt(req.query.pageSize || '10', 10), 1), 50);
  const offset   = (page - 1) * pageSize;

  const pageSql = `
    WITH me AS (
      SELECT mail, username, passw
      FROM utente
      WHERE username = $1
    )
    SELECT
      p.id,
      p.username,
      u.immagine         AS profile_image_url,
      p.etesto,
      p.eimmagine,
      p.textcontent,
      p.imageurl,
      p.numlike,
      p.data
    FROM post p
    JOIN utente u ON u.username = p.username
    WHERE
      p.username = (SELECT username FROM me)
      OR EXISTS (
        SELECT 1
        FROM segue s
        WHERE (s.mailseguitore, s.usernameseguitore, s.passwseguitore)
              = (SELECT mail, username, passw FROM me)
          AND s.usernameseguito = p.username
      )
    AND u.èbannato = FALSE
    AND p.èmoderato = FALSE
    ORDER BY p.data DESC, p.id DESC
    LIMIT $2 OFFSET $3
  `;

  const countSql = `
    WITH me AS (
      SELECT mail, username, passw
      FROM utente
      WHERE username = $1
    )
    SELECT COUNT(*) AS total
    FROM post p
    WHERE
      p.username = (SELECT username FROM me)
      OR EXISTS (
        SELECT 1
        FROM segue s
        WHERE (s.mailseguitore, s.usernameseguitore, s.passwseguitore)
              = (SELECT mail, username, passw FROM me)
          AND s.usernameseguito = p.username
      )
  `;

  Promise.all([
    pool.query(pageSql,  [ me, pageSize, offset ]),
    pool.query(countSql, [ me ])
  ])
  .then(([pageRes, countRes]) => {
    const total = parseInt(countRes.rows[0].total, 10);
    const totalPages = Math.max(Math.ceil(total / pageSize), 1);

    const items = pageRes.rows.map(r => ({
      id: r.id,
      username: r.username,
      profileImageUrl: r.profile_image_url || null,
      type: r.etesto ? 'text' : 'image',
      text: r.etesto ? r.textcontent : null,
      image: r.eimmagine ? r.imageurl : null,
      likes: r.numlike,
      createdAt: r.data
    }));

    res.json({ page, pageSize, total, totalPages, items });
  })
  .catch(err => {
    console.error('Feed error:', err.code, err.detail, err.message);
    res.status(500).json({ message: 'DB error' });
  });
}

const follow = (req, res) => {    //OK
  //#swagger.tags = ["Relationships"]
  //#swagger.summary = 'Segui utente'
  const followerUname = req.user?.username;
  const followedUname = req.params.username;

  if (!followerUname) return res.status(401).json({ message: 'Unauthorized' });
  if (!followedUname)  return res.status(400).json({ message: 'Username da seguire mancante' });
  if (followerUname === followedUname) {
    return res.status(400).json({ message: 'Non puoi seguire te stesso' });
  }

  pool.query('BEGIN')
    .then(() => pool.query(`
      WITH me AS (
        SELECT mail, username, passw FROM utente WHERE username = $1
      ),
      tgt AS (
        SELECT mail, username, passw FROM utente WHERE username = $2
      ),
      ins AS (
        INSERT INTO segue (
          mailseguito, usernameseguito, passwseguito,
          mailseguitore, usernameseguitore, passwseguitore,
          datafollow
        )
        SELECT
          tgt.mail, tgt.username, tgt.passw,
          me.mail,  me.username,  me.passw,
          NOW()
        FROM me, tgt
        WHERE me.username <> tgt.username
        ON CONFLICT DO NOTHING
        RETURNING 1 AS inserted
      )
      SELECT COALESCE((SELECT inserted FROM ins), 0) AS inserted
    `, [followerUname, followedUname]))
    .then(({ rows }) => {
      const inserted = rows[0].inserted === 1;
      if (!inserted) return { inserted }; 
      return pool.query(`
        UPDATE utente SET numfollow = numfollow + 1 WHERE username = $1;
      `, [followerUname])
      .then(() => pool.query(`
        UPDATE utente SET numfollowers = numfollowers + 1 WHERE username = $1;
      `, [followedUname]))
      .then(() => ({ inserted }));
    })
    .then(({ inserted }) => {
      return pool.query('COMMIT')
        .then(() => res.status(200).json({
          message: inserted ? 'Ora segui questo utente' : 'Già lo seguivi (nessuna modifica)'
        }));
    })
    .catch(err => {
      console.error('follow error:', err.code, err.detail, err.message);
      pool.query('ROLLBACK')
        .then(() => res.status(500).json({ message: 'DB error' }))
        .catch(() => res.status(500).json({ message: 'DB error' }));
    });
  
}

const unfollow = (req, res) => {    //OK
  //#swagger.tags = ["Relationships"]
  //#swagger.summary = 'Unfollow utente'
  const followerUname = req.user?.username;
  const followedUname = req.params.username;

  if (!followerUname) return res.status(401).json({ message: 'Unauthorized' });
  if (!followedUname)  return res.status(400).json({ message: 'Username mancante' });
  if (followerUname === followedUname) {
    return res.status(400).json({ message: 'Non puoi unfolloware te stesso' });
  }

  pool.query('BEGIN')
    .then(() => pool.query(`
      WITH me AS (
        SELECT mail, username, passw FROM utente WHERE username = $1
      ),
      tgt AS (
        SELECT mail, username, passw FROM utente WHERE username = $2
      )
      DELETE FROM segue s
      USING me, tgt
      WHERE (s.mailseguitore, s.usernameseguitore, s.passwseguitore) = (me.mail, me.username, me.passw)
        AND (s.mailseguito,   s.usernameseguito,   s.passwseguito)   = (tgt.mail, tgt.username, tgt.passw)
      RETURNING 1 AS deleted
    `, [followerUname, followedUname]))
    .then(({ rowCount }) => {
      const deleted = rowCount > 0;
      if (!deleted) return { deleted }; 
      return pool.query(`UPDATE utente SET numfollow    = GREATEST(numfollow    - 1, 0) WHERE username = $1`, [followerUname])
        .then(() => pool.query(`UPDATE utente SET numfollowers = GREATEST(numfollowers - 1, 0) WHERE username = $1`, [followedUname]))
        .then(() => ({ deleted }));
    })
    .then(({ deleted }) => {
      return pool.query('COMMIT')
        .then(() => res.status(200).json({
          message: deleted ? 'Hai smesso di seguire' : 'Non lo seguivi (nessuna modifica)'
        }));
    })
    .catch(err => {
      console.error('unfollow error:', err.code, err.detail, err.message);
      pool.query('ROLLBACK')
        .then(() => res.status(500).json({ message: 'DB error' }))
        .catch(() => res.status(500).json({ message: 'DB error' }));
    });    
}

const listaseguiti = (req, res) => {    //OK
  //#swagger.tags = ["Relationships"]
  //#swagger.summary = 'Visualizza account che segui'
  //#swagger.parameters['page'] = { in:'query', type:'integer', required:false, default:1 }
  //#swagger.parameters['pageSize'] = { in:'query', type:'integer', required:false, default:10 }
  const me = req.user?.username;
  if (!me) return res.status(401).json({ message: 'Unauthorized' });

  const page     = Math.max(parseInt(req.query.page || '1', 10), 1);
  const pageSize = Math.min(Math.max(parseInt(req.query.pageSize || '10', 10), 1), 50);
  const offset   = (page - 1) * pageSize;

  const pageSql = `
    WITH me AS (
      SELECT mail, username, passw
      FROM utente
      WHERE username = $1
    )
    SELECT 
      u.username,
      u.immagine    AS profile_image_url,
      u.numfollow,
      u.numfollowers,
      u.èmoderatore,
      u.èamministratore,
      s.datafollow
    FROM segue s
    JOIN utente u
      ON (u.mail, u.username, u.passw) = (s.mailseguito, s.usernameseguito, s.passwseguito)
    WHERE (s.mailseguitore, s.usernameseguitore, s.passwseguitore)
          = (SELECT mail, username, passw FROM me)
    ORDER BY s.datafollow DESC
    LIMIT $2 OFFSET $3
  `;

  const countSql = `
    WITH me AS (SELECT mail, username, passw FROM utente WHERE username = $1)
    SELECT COUNT(*) AS total
    FROM segue s
    WHERE (s.mailseguitore, s.usernameseguitore, s.passwseguitore)
          = (SELECT mail, username, passw FROM me)
  `;

  Promise.all([ pool.query(pageSql, [me, pageSize, offset]), pool.query(countSql, [me]) ])
    .then(([{ rows }, { rows: c }]) => {
      const total = parseInt((c[0] && c[0].total) || '0', 10);
      const totalPages = Math.max(Math.ceil(total / pageSize), 1);

      const items = rows.map(r => ({
        username: r.username,
        profile: {
          imageUrl: r.profile_image_url || null,
          followers: r.numfollowers,
          following: r.numfollow,
          isModerator: r.èmoderatore,
          isAdmin: r.èamministratore,
        },
        followedSince: r.datafollow
      }));

      res.json({ page, pageSize, total, totalPages, items });
    })
    .catch(err => {
      console.error('listaseguiti error:', err.code, err.detail, err.message);
      res.status(500).json({ message: 'DB error' });
    });
}

const listafollowers = (req, res) => {    //OK
  //#swagger.tags = ["Relationships"]
  //#swagger.summary = 'Visualizza account che ti seguono'
  //#swagger.parameters['page'] = { in:'query', type:'integer', required:false, default:1 }
  //#swagger.parameters['pageSize'] = { in:'query', type:'integer', required:false, default:10 }
  const me = req.user?.username;
  if (!me) return res.status(401).json({ message: 'Unauthorized' });

  const page     = Math.max(parseInt(req.query.page || '1', 10), 1);
  const pageSize = Math.min(Math.max(parseInt(req.query.pageSize || '10', 10), 1), 50);
  const offset   = (page - 1) * pageSize;

  const pageSql = `
    WITH me AS (
      SELECT mail, username, passw
      FROM utente
      WHERE username = $1
    )
    SELECT 
      u.username,
      u.immagine    AS profile_image_url,
      u.numfollow,
      u.numfollowers,
      u.èmoderatore,
      u.èamministratore,
      s.datafollow
    FROM segue s
    JOIN utente u
      ON (u.mail, u.username, u.passw) = (s.mailseguitore, s.usernameseguitore, s.passwseguitore)
    WHERE (s.mailseguito, s.usernameseguito, s.passwseguito)
          = (SELECT mail, username, passw FROM me)
    ORDER BY s.datafollow DESC
    LIMIT $2 OFFSET $3
  `;

  const countSql = `
    WITH me AS (
      SELECT mail, username, passw
      FROM utente
      WHERE username = $1
    )
    SELECT COUNT(*) AS total
    FROM segue s
    WHERE (s.mailseguito, s.usernameseguito, s.passwseguito)
          = (SELECT mail, username, passw FROM me)
  `;

  Promise.all([ pool.query(pageSql, [me, pageSize, offset]), pool.query(countSql, [me]) ])
    .then(([{ rows }, { rows: c }]) => {
      const total = parseInt((c[0] && c[0].total) || '0', 10);
      const totalPages = Math.max(Math.ceil(total / pageSize), 1);

      const items = rows.map(r => ({
        username: r.username,
        profile: {
          imageUrl: r.profile_image_url || null,
          followers: r.numfollowers,
          following: r.numfollow,
          isModerator: r.èmoderatore,
          isAdmin: r.èamministratore
        },
        followerSince: r.datafollow
      }));

      res.json({ page, pageSize, total, totalPages, items });
    })
    .catch(err => {
      console.error('listafollowers error:', err.code, err.detail, err.message);
      res.status(500).json({ message: 'DB error' });
    });
}

const likepost = (req, res) => {    //OK 
  //#swagger.tags = ["Posts"]
  //#swagger.summary = 'Metti like'
  const postID = parseInt(req.params.postID, 10);
  if (Number.isNaN(postID)) return res.status(400).json({ message: 'postID non valido' });

  const me = req.user && req.user.username;
  if (!me) return res.status(401).json({ message: 'Unauthorized' });

  pool.query('BEGIN')
  .then(() => pool.query(`
    WITH me AS (
      SELECT mail, username, passw FROM utente WHERE username = $1
    ),
    ins AS (
      INSERT INTO like_post (mailu, usernameu, passwu, idpost, datalike)
      SELECT me.mail, me.username, me.passw, $2, NOW()
      FROM me
      ON CONFLICT DO NOTHING
      RETURNING 1 AS inserted
    )
    SELECT COALESCE((SELECT inserted FROM ins), 0) AS inserted
  `, [ me, postID ]))
  .then(({ rows }) => {
    const inserted = rows[0] && rows[0].inserted === 1;
    if (!inserted) return { inserted };
    return pool.query(`UPDATE post SET numlike = numlike + 1 WHERE id = $1 RETURNING numlike`, [ postID ])
               .then(({ rows }) => ({ inserted, likes: rows[0].numlike }));
  })
  .then(({ inserted, likes }) =>
    pool.query('COMMIT').then(() =>
      res.status(200).json(inserted
        ? { message: 'Like aggiunto', likes }
        : { message: 'Già presente (nessuna modifica)' }
      )
    )
  )
  .catch(err => {
    console.error('likepost error:', err.code, err.detail, err.message);
    pool.query('ROLLBACK').then(() => {
      if (err.code === '23503') return res.status(404).json({ message: 'Post o utente inesistente' });
      res.status(500).json({ message: 'DB error' });
    }).catch(() => res.status(500).json({ message: 'DB error' }));
  });
}

const unlike = (req, res) => {    //OK
  //#swagger.tags = ["Posts"]
  //#swagger.summary = 'Rimuovi like'
  const postID = parseInt(req.params.postID, 10);
  if (Number.isNaN(postID)) return res.status(400).json({ message: 'postID non valido' });

  const me = req.user && req.user.username;
  if (!me) return res.status(401).json({ message: 'Unauthorized' });

  pool.query('BEGIN')
  .then(() => pool.query(`
    WITH me AS (
      SELECT mail, username, passw FROM utente WHERE username = $1
    )
    DELETE FROM like_post l
    USING me
    WHERE l.idpost = $2
      AND (l.mailu, l.usernameu, l.passwu) = (me.mail, me.username, me.passw)
    RETURNING 1 AS deleted
  `, [ me, postID ]))
  .then(({ rowCount }) => {
    const deleted = rowCount > 0;
    if (!deleted) return { deleted };
    return pool.query(`UPDATE post SET numlike = GREATEST(numlike - 1, 0) WHERE id = $1 RETURNING numlike`, [ postID ])
               .then(({ rows }) => ({ deleted, likes: rows[0].numlike }));
  })
  .then(({ deleted, likes }) =>
    pool.query('COMMIT').then(() =>
      res.status(200).json(deleted
        ? { message: 'Like rimosso', likes }
        : { message: 'Nessun like presente (nessuna modifica)' }
      )
    )
  )
  .catch(err => {
    console.error('unlike error:', err.code, err.detail, err.message);
    pool.query('ROLLBACK')
      .then(() => res.status(500).json({ message: 'DB error' }))
      .catch(() => res.status(500).json({ message: 'DB error' }));
  });
}

const flaggapost = (req, res) => {    //OK 
  //#swagger.tags = ["Flags"]
  //#swagger.summary = 'Flagga post'
   const postID = parseInt(req.params.postID, 10);
  if (Number.isNaN(postID)) return res.status(400).json({ message: 'postID non valido' });

  const me = req.user && req.user.username;
  if (!me) return res.status(401).json({ message: 'Unauthorized' });

  pool.query('BEGIN')
  .then(() => pool.query(`
    WITH me AS (
      SELECT mail, username, passw FROM utente WHERE username = $1
    ),
    ins AS (
      INSERT INTO flag_post (mailu, usernameu, passwu, idpost, dataflag)
      SELECT me.mail, me.username, me.passw, $2, NOW()
      FROM me
      ON CONFLICT DO NOTHING
      RETURNING 1 AS inserted
    )
    SELECT COALESCE((SELECT inserted FROM ins), 0) AS inserted
  `, [ me, postID ]))
  .then(({ rows }) => {
    const inserted = rows[0] && rows[0].inserted === 1;
    if (!inserted) return { inserted };
    return pool.query(
      `UPDATE post SET numflag = numflag + 1 WHERE id = $1 RETURNING numflag`,
      [ postID ]
    ).then(({ rows }) => ({ inserted, flags: rows[0].numflag }));
  })
  .then(({ inserted, flags }) =>
    pool.query('COMMIT').then(() =>
      res.status(200).json(
        inserted ? { message: 'Flag aggiunto', flags } : { message: 'Già flaggato (nessuna modifica)' }
      )
    )
  )
  .catch(err => {
    console.error('flaggapost error:', err.code, err.detail, err.message);
    pool.query('ROLLBACK').then(() => {
      if (err.code === '23503') return res.status(404).json({ message: 'Post o utente inesistente' });
      res.status(500).json({ message: 'DB error' });
    }).catch(() => res.status(500).json({ message: 'DB error' }));
  });  
}

const unflag = (req, res) => {    //OK
  //#swagger.tags = ["Flags"]
  //#swagger.summary = 'Unflagga post'
  const postID = parseInt(req.params.postID, 10);
  if (Number.isNaN(postID)) return res.status(400).json({ message: 'postID non valido' });

  const me = req.user && req.user.username;
  if (!me) return res.status(401).json({ message: 'Unauthorized' });

  pool.query('BEGIN')
  .then(() => pool.query(`
    WITH me AS (
      SELECT mail, username, passw FROM utente WHERE username = $1
    )
    DELETE FROM flag_post f
    USING me
    WHERE f.idpost = $2
      AND (f.mailu, f.usernameu, f.passwu) = (me.mail, me.username, me.passw)
    RETURNING 1 AS deleted
  `, [ me, postID ]))
  .then(({ rowCount }) => {
    const deleted = rowCount > 0;
    if (!deleted) return { deleted };
    return pool.query(
      `UPDATE post SET numflag = GREATEST(numflag - 1, 0) WHERE id = $1 RETURNING numflag`,
      [ postID ]
    ).then(({ rows }) => ({ deleted, flags: rows[0].numflag }));
  })
  .then(({ deleted, flags }) =>
    pool.query('COMMIT').then(() =>
      res.status(200).json(
        deleted ? { message: 'Flag rimosso', flags } : { message: 'Nessun flag presente (nessuna modifica)' }
      )
    )
  )
  .catch(err => {
    console.error('unflag error:', err.code, err.detail, err.message);
    pool.query('ROLLBACK')
      .then(() => res.status(500).json({ message: 'DB error' }))
      .catch(() => res.status(500).json({ message: 'DB error' }));
  });
}

const postflaggati = (req, res) => {  //OK 
  //#swagger.tags = ["Flags"]
  //#swagger.summary = "Visualizza i tuoi post flaggati"
  //#swagger.parameters['page'] = { in:'query', type:'integer', required:false, default:1 }
  //#swagger.parameters['pageSize'] = { in:'query', type:'integer', required:false, default:10 }

  const targetUser = req.params.username;
  const me = req.user && req.user.username;

  if (!me) return res.status(401).json({ message: "Unauthorized" });
  if (targetUser !== me) {
    return res.status(403).json({ message: "Forbidden: puoi vedere solo i tuoi post flaggati" });
  }

  const page     = Math.max(parseInt(req.query.page || "1", 10), 1);
  const pageSize = Math.min(Math.max(parseInt(req.query.pageSize || "10", 10), 1), 50);
  const offset   = (page - 1) * pageSize;

  const pageSql = `
    WITH me AS (
      SELECT mail, username, passw
      FROM utente
      WHERE username = $1
    )
    SELECT
      p.id,
      p.username,
      u.immagine       AS profile_image_url,
      p.etesto,
      p.eimmagine,
      p.textcontent,
      p.imageurl,
      p.numlike,
      p.numflag,
      p.data,
      f.dataflag       AS flagged_since
    FROM flag_post f
    JOIN post   p ON p.id = f.idpost
    JOIN utente u ON u.username = p.username
    WHERE (f.mailu, f.usernameu, f.passwu) = (SELECT mail, username, passw FROM me)
    ORDER BY f.dataflag DESC, p.data DESC, p.id DESC
    LIMIT $2 OFFSET $3
  `;

  const countSql = `
    WITH me AS (
      SELECT mail, username, passw
      FROM utente
      WHERE username = $1
    )
    SELECT COUNT(*) AS total
    FROM flag_post f
    WHERE (f.mailu, f.usernameu, f.passwu) = (SELECT mail, username, passw FROM me)
  `;

  Promise.all([ pool.query(pageSql, [me, pageSize, offset]), pool.query(countSql, [me]) ])
    .then(([{ rows }, { rows: c }]) => {
      const total = parseInt((c[0] && c[0].total) || "0", 10);
      const totalPages = Math.max(Math.ceil(total / pageSize), 1);

      const items = rows.map(r => ({
        id: r.id,
        author: {
          username: r.username,
          profileImageUrl: r.profile_image_url || null
        },
        type: r.etesto ? "text" : "image",
        text: r.etesto ? r.textcontent : null,
        image: r.eimmagine ? r.imageurl : null,
        likes: r.numlike,
        flags: r.numflag,
        createdAt: r.data,
        flaggedSince: r.flagged_since
      }));

      res.json({ page, pageSize, total, totalPages, items });
    })
    .catch(err => {
      console.error("postflaggati error:", err.code, err.detail, err.message);
      res.status(500).json({ message: "DB error" });
    });
}

const elencaflaggati = (req, res) => {  //OK 
  //#swagger.tags = ["Moderation"]
  //#swagger.summary = 'Elenca post flaggati'
  //#swagger.parameters['page'] = { in:'query', type:'integer', required:false, default:1 }
  //#swagger.parameters['pageSize'] = { in:'query', type:'integer', required:false, default:10 }

  const isMod   = req.user && (req.user.moderatore === true);
  const isAdmin = req.user && (req.user.admin === true);
  if (!isMod && !isAdmin) {
    return res.status(403).json({ message: 'Forbidden: non sei moderatore' });
  }

  const page     = Math.max(parseInt(req.query.page || '1', 10), 1);
  const pageSize = Math.min(Math.max(parseInt(req.query.pageSize || '20', 10), 1), 100);
  const offset   = (page - 1) * pageSize;

  const pageSql = `
    SELECT
      p.id                  AS postid,
      p.username            AS author,
      u.immagine            AS author_image_url,
      p.etesto,
      p.eimmagine,
      p.textcontent,
      p.imageurl,
      p.numlike,
      p.numflag,
      p.data                AS creationdate,
      COUNT(f.idpost)       AS flags,
      MAX(f.dataflag)       AS lastflag
    FROM post p
    JOIN flag_post f ON f.idpost = p.id
    JOIN utente u    ON u.username = p.username
    GROUP BY p.id, p.username, u.immagine, p.etesto, p.eimmagine,
             p.textcontent, p.imageurl, p.numlike, p.numflag, p.data
    ORDER BY flags DESC, p.data DESC, p.id DESC
    LIMIT $1 OFFSET $2
  `;

  const countSql = `
    SELECT COUNT(*) AS total
    FROM (
      SELECT p.id
      FROM post p
      JOIN flag_post f ON f.idpost = p.id
      GROUP BY p.id
    ) sub
  `;

  Promise.all([
    pool.query(pageSql, [ pageSize, offset ]),
    pool.query(countSql)
  ])
  .then(([{ rows }, { rows: c }]) => {
    const total = parseInt(c[0].total, 10);
    const totalPages = Math.max(Math.ceil(total / pageSize), 1);

    const items = rows.map(r => ({
      postID:       r.postid,
      author:       r.author,
      authorImage:  r.author_image_url || null,
      type:         r.etesto ? 'text' : 'image',
      textContent:  r.etesto ? r.textcontent : null,
      imageUrl:     r.eimmagine ? r.imageurl : null,
      likes:        r.numlike,
      flags:        parseInt(r.flags, 10),
      totalFlags:   r.numflag, 
      creationDate: r.creationdate,
      lastFlag:     r.lastflag
    }));

    res.json({ page, pageSize, total, totalPages, items });
  })
  .catch(err => {
    console.error('elencaflaggati error:', err.code, err.detail, err.message);
    res.status(500).json({ message: 'DB error' });
  });
}

const nominamod = (req, res) => {   //OK
  //#swagger.tags = ["Moderation"]
  //#swagger.summary = 'Nomina moderatore (solo admin) '
  if (!req.user || req.user.admin !== true) {
    return res.status(403).json({ message: "Forbidden: solo l'admin può nominare moderatori" });
  }

  const targetUsername = req.params.username;
  if (!targetUsername) {
    return res.status(400).json({ message: "Username mancante" });
  }

  pool.query(
    `SELECT username, èmoderatore
     FROM utente
     WHERE username = $1`,
    [ targetUsername ]
  )
  .then(({ rows }) => {
    if (!rows.length) {
      return res.status(404).json({ message: "Utente non trovato" });
    }
    if (rows[0].èmoderatore === true) {
      return res.status(400).json({ message: "Utente è già moderatore" });
    }

    return pool.query(
      `UPDATE utente
       SET èmoderatore = TRUE, datanomina = NOW()
       WHERE username = $1
       RETURNING username, èmoderatore, datanomina`,
      [ targetUsername ]
    )
    .then(({ rows: updated }) => {
      res.status(200).json({
        message: `Utente ${updated[0].username} nominato moderatore con successo`,
        dataNomina: updated[0].datanomina
      });
    });
  })
  .catch(err => {
    console.error("nominamod error:", err.code, err.detail, err.message);
    res.status(500).json({ message: "DB error" });
  });
}

const rimuovimod = (req, res) => {    //OK
  //#swagger.tags = ["Moderation"]
  //#swagger.summary = 'Rimuovi moderatore (solo admin)'
  if (!req.user || req.user.admin !== true) {
    return res.status(403).json({ message: "Forbidden: solo l'admin può revocare moderatori" });
  }

  const targetUsername = req.params.username;
  if (!targetUsername) {
    return res.status(400).json({ message: "Username mancante" });
  }

  pool.query(
    `SELECT username, èmoderatore
     FROM utente
     WHERE username = $1`,
    [ targetUsername ]
  )
  .then(({ rows }) => {
    if (!rows.length) {
      return res.status(404).json({ message: "Utente non trovato" });
    }
    if (rows[0].èmoderatore !== true) {
      return res.status(400).json({ message: "Utente non è moderatore" });
    }

    return pool.query(
      `UPDATE utente
         SET èmoderatore = FALSE
       WHERE username = $1
       RETURNING username, èmoderatore`,
      [ targetUsername ]
    )
    .then(({ rows: updated }) => {
      res.status(200).json({
        message: `Utente ${updated[0].username} non è più moderatore`,
        moderatore: updated[0].èmoderatore
      });
    });
  })
  .catch(err => {
    console.error("rimuovimod error:", err.code, err.detail, err.message);
    res.status(500).json({ message: "DB error" });
  });
}

const moderapost = (req, res) => {    //OK
  //#swagger.tags = ["Moderation"]
  //#swagger.summary = 'Modera post'
  const isMod   = req.user && req.user.moderatore === true;
  const isAdmin = req.user && req.user.admin === true;
  if (!isMod && !isAdmin) {
    return res.status(403).json({ message: 'Forbidden' });
  }

  const postID = parseInt(req.params.postID, 10);
  if (Number.isNaN(postID)) {
    return res.status(400).json({ message: 'postID non valido' });
  }

  const me = req.user.username;

  pool.query('BEGIN')
  .then(() => pool.query(
    `SELECT mail, username, passw FROM utente WHERE username = $1`,
    [ me ]
  ))
  .then(({ rows }) => {
    if (!rows.length) throw new Error('USER_NOT_FOUND');
    const meTripla = rows[0];

    return pool.query(
      `UPDATE post
         SET èmoderato = TRUE
       WHERE id = $1 AND èmoderato = FALSE
       RETURNING id, username, èmoderato, data`,
      [ postID ]
    )
    .then(({ rows: upd }) => {
      const justModerated = upd.length === 1; 
      return pool.query(
        `INSERT INTO modera (mailu, usernameu, passwu, idpost, datamoderazione)
         VALUES ($1, $2, $3, $4, NOW())
         ON CONFLICT DO NOTHING
         RETURNING 1 AS inserted`,
        [ meTripla.mail, meTripla.username, meTripla.passw, postID ]
      )
      .then(({ rows: ins }) => ({ justModerated, inserted: ins.length === 1, meTripla, upd }));
    });
  })
  .then(({ justModerated, inserted, meTripla, upd }) => {
    if (!inserted) return { justModerated, inserted, upd };

    return pool.query(
      `UPDATE utente
         SET postmoderati = postmoderati + 1
       WHERE username = $1`,
      [ meTripla.username ]
    )
    .then(() => ({ justModerated, inserted, upd }));
  })
  .then(({ justModerated, inserted, upd }) => {
    return pool.query('COMMIT').then(() => {
      if (!justModerated && !inserted) {
        return res.status(200).json({ message: 'Già moderato (nessuna modifica)' });
      }
      if (!upd || upd.length === 0) {
        return res.status(404).json({ message: 'Post non trovato' });
      }
      const p = upd[0];
      return res.status(200).json({
        message: inserted ? 'Post moderato e registrato' : 'Post moderato (registrazione già presente)',
        post: {
          id: p.id,
          author: p.username,
          moderato: p.èmoderato,
          creationDate: p.data
        }
      });
    });
  })
  .catch(err => {
    if (err && err.message === 'USER_NOT_FOUND') {
      return pool.query('ROLLBACK')
        .then(() => res.status(401).json({ message: 'Utente non valido' }))
        .catch(() => res.status(401).json({ message: 'Utente non valido' }));
    }
    console.error('moderapost error:', err.code, err.detail, err.message || err);
    pool.query('ROLLBACK')
      .then(() => {
        if (err.code === '23503') return res.status(404).json({ message: 'Post inesistente' });
        res.status(500).json({ message: 'DB error' });
      })
      .catch(() => res.status(500).json({ message: 'DB error' }));
  });
}

const unmoderapost = (req, res) => {    //OK
  //#swagger.tags = ["Moderation"]
  //#swagger.summary = "Revoca la moderazione di un post (solo admin)"

  if (!req.user || req.user.admin !== true) {
    return res.status(403).json({ message: "Forbidden: solo l'admin può revocare moderazioni" });
  }

  const postID = parseInt(req.params.postID, 10);
  if (Number.isNaN(postID)) {
    return res.status(400).json({ message: "postID non valido" });
  }

  pool.query("BEGIN")
    .then(() => pool.query(
      `UPDATE post
         SET èmoderato = FALSE
       WHERE id = $1 AND èmoderato = TRUE
       RETURNING id, username, èmoderato, data`,
      [ postID ]
    ))
    .then(({ rows }) => {
      if (!rows.length) {
        throw new Error("NOT_FOUND_OR_NOT_MODERATED");
      }
      const post = rows[0];

      return pool.query(
        `DELETE FROM modera WHERE idpost = $1`,
        [ postID ]
      ).then(() => post);
    })
    .then(post => {
      return pool.query("COMMIT").then(() => {
        res.status(200).json({
          message: `Moderazione del post ${post.id} revocata con successo`,
          post: {
            id: post.id,
            author: post.username,
            moderato: post.èmoderato,
            creationDate: post.data
          }
        });
      });
    })
    .catch(err => {
      if (err.message === "NOT_FOUND_OR_NOT_MODERATED") {
        return pool.query("ROLLBACK")
          .then(() => res.status(404).json({ message: "Post non trovato o non moderato" }))
          .catch(() => res.status(404).json({ message: "Post non trovato o non moderato" }));
      }

      console.error("unmoderapost error:", err.code, err.detail, err.message || err);
      pool.query("ROLLBACK")
        .then(() => res.status(500).json({ message: "DB error" }))
        .catch(() => res.status(500).json({ message: "DB error" }));
    });
}

const ban = (req, res) => {   //OK
  //#swagger.tags = ["Moderation"]
  //#swagger.summary = 'Banna utente'
  const check = req.user && (req.user.admin === true || req.user.mod === true);
  if (!check) return res.status(403).json({ message: 'Forbidden' });

  const target = req.params.username;
  if (!target) return res.status(400).json({ message: 'Username mancante' });

  
  pool.query(`
    SELECT COUNT(*) AS c
    FROM modera m
    JOIN post   p ON p.id = m.idpost
    WHERE p.username = $1
      AND m.datamoderazione >= NOW() - INTERVAL '30 days'
  `, [ target ])
  .then(({ rows }) => {
    const count = parseInt(rows[0].c, 10);
    if (count < 3) {
      return res.status(400).json({ message: `Non raggiunta la soglia: ${count}/3 moderazioni negli ultimi 30 giorni` });
    }
  
    return pool.query(
      `UPDATE utente SET èbannato = TRUE WHERE username = $1 RETURNING username, èbannato`,
      [ target ]
    )
    .then(({ rows }) => {
      if (!rows.length) return res.status(404).json({ message: 'Utente non trovato' });
      res.json({ message: `Utente ${rows[0].username} bannato`});
    });
  })
  .catch(err => {
    console.error('ban error:', err.code, err.detail, err.message);
    res.status(500).json({ message: 'DB error' });
  });
}

const unban = (req, res) => {   //OK
  //#swagger.tags = ["Moderation"]
  //#swagger.summary = 'Sbanna utente'
  const check = req.user && (req.user.admin === true || req.user.mod === true);
  if (!check) return res.status(403).json({ message: 'Forbidden' });

  const target = req.params.username;
  if (!target) return res.status(400).json({ message: 'Username mancante' });

  pool.query(
    `UPDATE utente
       SET èbannato = FALSE
     WHERE username = $1 AND èbannato = TRUE
     RETURNING username, èbannato`,
    [ target ]
  )
  .then(({ rows }) => {
    if (!rows.length) {
      return res.status(404).json({ message: 'Utente non trovato o non bannato' });
    }
    res.status(200).json({ message: `Ban rimosso per ${rows[0].username}` });
  })
  .catch(err => {
    console.error('unban error:', err.code, err.detail, err.message);
    res.status(500).json({ message: 'DB error' });
  });
}
