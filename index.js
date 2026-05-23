const express = require('express')
const fileUpload = require('express-fileupload')
const swaggerUi = require('swagger-ui-express') 
 
const app = express()

const port = 3000

//middlewares applicati a tutte le funzioni
app.use(express.json()) //gestisce il json
app.use(express.urlencoded({extended:true})) //gestisce gli url
app.use(fileUpload())
app.use('/resources', express.static('resources'))

app.listen(port, () => {
    console.log(`fotogram on port ${port}`)
})

app.get("/", (req, res) => {
    res.status(200).send({info: "Node + Express + PG API"})
})

const swaggerFile = require('./swaggerFile.json')
app.use('/doc', swaggerUi.serve, swaggerUi.setup(swaggerFile)) 

require('./endpoints')(app)  //chiamata a file 'endpoints'

