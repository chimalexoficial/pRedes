const express = require('express')
const path = require('path')
const bcrypt = require('bcrypt')
const app = express()
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const mongo_uri = 'mongodb+srv://admin:nomelase@cluster0.nsxs1.mongodb.net/redes?retryWrites=true&w=majority'
const User = require('./user')
const speakeasy = require('speakeasy')
const qrcode = require('qrcode')
const https = require('https')
const fs = require('fs')
const multer = require('multer')
const crypto = require('crypto')
const secret = speakeasy.generateSecret({
    name: 'Seguridad en Redes'
})
var key = fs.readFileSync(__dirname + '/server.key');
var cert = fs.readFileSync(__dirname + '/server.crt');
var options = {
  key: key,
  cert: cert
};

var storage =   multer.diskStorage({
    destination: function (req, file, callback) {
      callback(null, './uploads');
    },
    filename: function (req, file, callback) {
      callback(null, 'archivo.txt');
    }
  });
  var upload = multer({ storage : storage}).single('txt');





app.use(bodyParser.json())
app.use(bodyParser.urlencoded({
    extended: false
}))

var server = https.createServer(options, app);

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({
    extended: false
}))

app.use(express.static(path.join(__dirname, 'public')))

mongoose.connect(mongo_uri, function (err) {
    if (err) {
        throw err;
    } else {
        console.log('Conectado a mongo');
    }
})


app.post('/register', (req, res) => {
    const {
        username,
        password
    } = req.body;
    const user = new User({
        username,
        password
    })
    user.save(err => {
        if (err) {
            res.status(500).send('Error al registralo')
        } else {
            res.status(200).send('Correctamente registrado')
        }
    })
})

app.post('/login', (req, res) => {
    console.log(secret);

    //action="/verify" method="get"

    qrcode.toDataURL(secret.otpauth_url, function (err, data) {
        console.log(data);
    })
    const {
        username,
        password
    } = req.body;
    User.findOne({
        username
    }, (err, user) => {
        if (err) {
            res.status(200).send('ERROR AL AUTENTICAR')
        } else if (!user) {
            res.status(500).send('ERROR AL AUTENTICAR')
        } else {
            user.isPSWcorrect(password, (err, result) => {
                if (err) {
                    res.status(500).send('ERROR AL AUTENTICAR')
                } else if (result) {
                    res.status(200).redirect('/qrcode')
                } else {
                    res.status(500).send('ERROR AL AUTENTICAR')
                }
            })
        }
    })
})

app.get('/verify', (req, res)=>{
    let verified = speakeasy.totp.verify({
        secret: secret.ascii,
        encoding: 'ascii',
        token: req.query.token
    })
    
    console.log(verified);
    if(verified == true) {
        console.log('Correcto, redireccionando');
        res.status(200).redirect('/upload')
    } else {
        console.log('Incorrecto');
        res.status(500).send('Intente de nuevo')
    }
    //console.log(req.query.token);
    //console.log('FUERA DE LA FUNCION'+secret.ascii);
})

app.get('/upload', (req,res)=>{
    res.status(200).sendFile(__dirname + '/public/subir.html')
})

app.get('/qrcode', (req, res) => {
    qrcode.toDataURL(secret.otpauth_url, function (err, data_url) {
        //console.log(data_url.ascii);
        //console.log('DENTRO DE LA FUNCION' + secret.ascii);
        res.end('<!DOCTYPE html>\
    <html lang="en">\
    <head>\
        <link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">\
        <script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>\
        <script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>\
        <meta charset="UTF-8">\
        <link rel="stylesheet" href="style.css">\
        <meta name="viewport" content="width=device-width, initial-scale=1.0">\
        <title>Login</title>\
    </head>\
    <body>\
        <div id="login">\
            <h3 class="text-center text-white pt-5">Escanea</h3>\
            <div class="container">\
                <div id="login-row" class="row justify-content-center align-items-center">\
                    <div id="login-column" class="col-md-6">\
                        <div id="login-box" class="col-md-12">\
                            <form id="login-form" class="form" method="get" action="/verify">\
                                <h3 class="text-center text-info">Codigo QR</h3>\
                                <img src="' + data_url + '" alt="qr">\
                                <p>La llave generada es: "' + secret.ascii + '"  </p>\
                                <div class="form-group">\
                                    <label for="token" class="text-info">token:</label><br>\
                                    <input type="text" name="token" id="token" class="form-control">\
                                </div>\
                                <div class="form-group">\
                                <button onclick="verify()">Verificar token y entrar</button>\
                                </div>\
                            </form>\
                        </div>\
                    </div>\
                </div>\
            </div>\
        </div>\
    </body>\
    </html>');


    });
})

app.post('/upload',function(req,res){
    upload(req,res,function(err) {
        if(err) {
            return res.end("Error subiendo TXT");
        }
        console.log("El archivo ha sido exitosamente subido");
        fs.readFile('uploads/archivo.txt', 'utf8', function(err, data) {
            if (err) throw err;
            const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
                modulusLength: 2048, //2048 bits
            })
            
            console.log(
                publicKey.export({
                    type: "pkcs1",
                    format: "pem",
                }),
            
                privateKey.export({
                    type: "pkcs1",
                    format: "pem",
                })
            )
            
            //Encriptacion
            
            const encryptedData = crypto.publicEncrypt(
                {
                    key: publicKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: "sha256",
                },
                Buffer.from(data)
            )
            
            // Esta en bytes, entonces la imprimimos en base64
            console.log("encypted data: ", encryptedData.toString("base64"))
            
            const decryptedData = crypto.privateDecrypt(
                {
                    key: privateKey,
                    // Indicamos el tipo de algoritmo
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: "sha256",
                },
                encryptedData
            )
            
            // Imprimimos la desencriptacion 
            console.log("decrypted data: ", decryptedData.toString())
            
            // data va a ser mi archivo
            const verifiableData = data
            
            // Generacion de firma
            const signature = crypto.sign("sha256", Buffer.from(verifiableData), {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            })
            
            console.log(signature.toString("base64"))
            
            // Verificacion de la firma
            const isVerified = crypto.verify(
                "sha256",
                Buffer.from(verifiableData),
                {
                    key: publicKey,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                },
                signature
            )
            
            console.log("El documento esta firmado? -> Verificacion ", isVerified)
        
        });
        
    });
});




server.listen(3001, () => {
    console.log('Running');
})

module.exports = app;