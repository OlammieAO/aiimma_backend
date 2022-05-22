require('dotenv').config({ debug: true, override: false })
const express = require('express');
const jwt = require("jsonwebtoken");
const logger = require('morgan');
const bodyParser = require('body-parser')
const http = require("http");
const https = require('https');
var fileUpload = require('express-fileupload');
const app = express();
const port = process.env.PORT || 80;
const session = require('express-session');
//const port_https = process.env.PORT_HTTPS || 443;
const routes = require('./routes');
const rfs = require("rotating-file-stream");
const path = require("path");
const md5 = require('md5');
const _ = require('lodash');
const fileWriter = rfs.createStream('errors.log', {
    interval: '1d', // rotate daily
    path: path.join(__dirname, 'log')
});
const {StatusCodes} = require('http-status-codes');
const fs = require("fs");

const connection = require("./database/connection");
const bcrypt = require('bcrypt');
const dbhelper = require("./models/db_helper.js");
const joi = require("joi");
const common_helper = require('./utils/common_helper');
const emailactivation = require('./notification/emailactivation');

const saltRound = 10;

const allowCrossDomain = function (req, res, next) {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'POST, GET, PUT,PATCH, DELETE, OPTIONS, ');
    res.header('Access-Control-Allow-Credentials', false);
    res.header('Access-Control-Max-Age', '86400');
    res.header('Access-Control-Allow-Headers', 'Authorization, X-Requested-With, X-HTTP-Method-Override, Content-Type, Accept');
    next();
};
app.use(allowCrossDomain);
// Error logger
app.use(logger('dev', {
    skip: function (req, res) { return res.statusCode < 400 },
    stream: fileWriter
}))
app.use(logger('dev'));
app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());
app.use(fileUpload());
app.use("/api/v1", routes);
app.use('/favicon.ico', (req, res) => {
    res.status(StatusCodes.OK).send();
});

app.use((req, res, next) => {
    const error = new Error("Not found");
    error.status = StatusCodes.NOT_FOUND;
    next(error);
});

// error handler middleware
app.use((error, req, res) => {
    if (process.env.NODE_ENV === "dev") {
        res.status(error.status || StatusCodes.INTERNAL_SERVER_ERROR).send({message: error.message || 'Internal Server Error',});
    } else {
        res.status(error.status || StatusCodes.INTERNAL_SERVER_ERROR).send({message: 'Internal Server Error',});
    }
});

/* const jwtExpirySeconds = "10h";

app.post("/onboarding", (req, res) => {
    const schema = joi.object({         
        fullname: joi.string().max(75).required("Full Name / Business Name is required"),
        email: joi.string().email().max(65).required("Email is required and must be reasonable"),
        phone: joi.number().min(11).max(11).required("Phone number is required and must be 11 digits"),
        password: joi.string().max(125).required("Password is required"),
        registeras: joi.string().max(10).required("Please choose how you want to be registered"),
    });

    const { error } = schema.validate(req.body);

    if (error) 
    {
      return res.status(400).send(error.details[0].message);      
    }
    
    const fullname = req.body.fullname;
    const email = req.body.email;
    const phone = req.body.phone;
    const password = req.body.password;
    const registeras = req.body.registeras;
    const userid = common_helper.userid();
    const emailActivation = common_helper.emailActivation(userid.replace(/[^a-zA-Z0-9]/g, ""));
    const phoneActivationCode = common_helper.getRandomNumberBetween(100000,900000);
    const loggedIP = req.header('x-forwarded-for') || req.message.connection.remoteAddress;
    
    bcrypt.hash(req.body.password, saltRound, (err, hash) => {
    if(err){
    console.log(err);
    }
    
    const values = [userid, fullname, phone, email, hash, registeras, emailActivation, phoneActivationCode, loggedIP];
   
    connection.query(OnboardingSP, [values], (err, result)=> {
        if(err){
            console.log(result);
       return res.status(500).json(
           {
               onboarded: false, 
               message: "Your registration cannot be completed at the moment",
        })
    }
        else{
            console.log(result);

           let subject = "Ai-Imma Global: Verify your email address";

            //send email activation code here
            emailactivation.sendConfirmationEmail(fullname, subject, emailActivation);

       return res.status(200).json(
           {
               onboarded: true, 
               message: "success",
            });
        }        
       });    
    })
    });

    app.post("/signin", (req, res, next) => {
      const username = req.body.username;
      const password = req.body.password;
      
       connection.query("SELECT * FROM aiimma_membersaccess WHERE username = ? AND LoginStatus='Enabled'", username, (err, result) => {
        
        if(err){
        //res.send({err: err});
        res.status(StatusCodes.NOT_FOUND).send({ message: "No such user found." });
      }
      
      else {
         if(result.length > 0) {             
         bcrypt.compare(password, result[0].pwd, (error, response) => {
          if(response) {
        
         const registeras = result[0].Login_Role;

         try{
         if(registeras == "AG")
         {             
             const userData = dbhelper.agentLoginVW(req.username);                        

             const token = jwt.sign({userData}, process.env.TOKEN_SECRET, {
                algorithm: 'HS256',
                expiresIn: jwtExpirySeconds
              });

              res.status(StatusCodes.OK).send({"expires_in":jwtExpirySeconds,"access_token":token,"token_type": "bearer","userData":userData});
         }

         if(registeras == "AS")
         {
             //it is AdmnStaff
         }

         if(registeras == "DRV")
         {
            const userData = dbhelper.driverLoginVW(req.username);

            const token = jwt.sign({userData}, process.env.TOKEN_SECRET, {
                algorithm: 'HS256',
                expiresIn: jwtExpirySeconds
              });

              res.status(StatusCodes.OK).send({"expires_in":jwtExpirySeconds,"access_token":token,"token_type": "bearer","userData":userData});
         }

         if(registeras == "HBBT")
         {
            const userData = dbhelper.hbbtLoginVW(req.username);

            const token = jwt.sign({userData}, process.env.TOKEN_SECRET, {
                algorithm: 'HS256',
                expiresIn: jwtExpirySeconds
              });

              res.status(StatusCodes.OK).send({"expires_in":jwtExpirySeconds,"access_token":token,"token_type": "bearer","userData":userData});
         }        

         if(registeras == "TRN")
         {
            const userData = dbhelper.transporterLoginVW(req.username);

            const token = jwt.sign({userData}, process.env.TOKEN_SECRET, {
                algorithm: 'HS256',
                expiresIn: jwtExpirySeconds
              });

              res.status(StatusCodes.OK).send({"expires_in":jwtExpirySeconds,"access_token":token,"token_type": "bearer","userData":userData});         
         }

         if(registeras == "SA" || registeras == "AS")
         {
            const userData = dbhelper.adminStaffLoginVW(req.username);

            const token = jwt.sign({userData}, process.env.TOKEN_SECRET, {
                algorithm: 'HS256',
                expiresIn: jwtExpirySeconds
              });

              res.status(StatusCodes.OK).send({"expires_in":jwtExpirySeconds,"access_token":token,"token_type": "bearer","userData":userData});

            
         } 
       // } //closes the if for bcrypt password checking    
        
        else {
            res.send("Wrong login credentials supplied.");
         } // closes this else
        }

        catch (e) {
            console.log(`Error in create`, e);
            next(e);
        } //closes catch
    }     //if for the response that open try

      });  //closes bcrypt                           
      } // closes the if before bcrypt
    }
              
      }); // closes db.query function      
      }); //closes app.post  

      //verify email verification      
    app.post("/emailconfirmation/verify/:hash", (req, res) => {
       
        const endpointParam = req.params;

        const verify = endpointParam.hash;

        if(dbhelper.updateEmailVerification(verify))
        {
            res.status(200).json({
                verified: true, 
                message: "Congratulation!!! Your email has been successfully verified",
            });
        }

        else{
            res.status(500).json({
                verified: false, 
                message: "Ooops!!! Sorry, we cannot verify your activation link.",
            });
        }

      })  */     

http.createServer(app).listen(() => {
    console.log('HTTP API server started on http://localhost/api/v1');
});

/* http.createServer(app).listen(port, () => {
    console.log('HTTP API server started on http://localhost:'+ port+'/api/v1');
});*/

// Create an HTTPS service identical to the HTTP service. Uncomment below line
// const options = {
//    key: fs.readFileSync('/domain.com.key'),
//    cert: fs.readFileSync('/certificate.crt')
// };
// https.createServer(options, app).listen(port_https, () => {
//     console.log('HTTPS API server started on https://localhost:'+ port_https+'/api/v1');
// });

process.on("unhandledRejection", (reason, p) => {
    console.error("Unhandled Rejection at:", p, "reason:", reason)
});
