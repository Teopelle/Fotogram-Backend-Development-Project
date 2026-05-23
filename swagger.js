const swaggerAutogen = require('swagger-autogen')({openapi: '3.0.4'}) //per auto-generare la config swagger

const doc = { //scheletro della configurazione swagger
    info: {
        title: 'fotogramAPI',
        description: 'API di Fotogram'
    },
    host: 'localhost:3000',
    components: {
        securitySchemes: {
            bearerAuth: {
                type: 'http',
                scheme: 'bearer'
            }
        }
    }
}

const swaggerFile = './swaggerFile.json' //salva la configurazione qua
const routes = ['./endpoints.js'] //processa questi endpoints per generare lo swagger
swaggerAutogen(swaggerFile, routes, doc) //autogenera la config
