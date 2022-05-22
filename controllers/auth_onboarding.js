//require('dotenv').config({ debug: true, override: false })
const express = require('express');
const jwt = require("jsonwebtoken");
const bodyParser = require('body-parser')
const http = require("http");
const https = require('https');
const _ = require('lodash');
const {StatusCodes} = require('http-status-codes');
const connection = require("../database/connection");
const bcrypt = require('bcrypt');
const dbhelper = require("../models/db_helper.js");
const joi = require("joi");
const common_helper = require('../utils/common_helper');
const emailactivation = require('../notification/emailactivation');

const saltRound = 10;

const jwtExpirySeconds = "2h";


//exports.onboarding = (req, res, next) => {
const onboarding = (req, res, next) => {
try{
    const userid = common_helper.userid();
    const emailActivation = common_helper.emailActivation(userid.replace(/[^a-zA-Z0-9]/g, ""));
    const phoneActivationCode = common_helper.getRandomNumberBetween(100000,900000);
    const loggedIP = req.header('x-forwarded-for');// || req.message.connection.remoteAddress;

    const schema = joi.object({         
        fullname: joi.string().max(75).required().label("Full Name / Business Name is required"),
        email: joi.string().email().max(65).required().label("Email is required and must be reasonable"),
        phone: joi.string().required().label("Phone number is required and must be 11 digits"),
        password: joi.string().max(125).required().label("Password is required"),
        registeras: joi.string().max(10).required().label("Please choose how you want to be registered"),
        userid: joi.string().required().label("User ID is required"),
        emailActivation: joi.string().required().label("Email Activation is required"),
        phoneActivationCode: joi.string().required().label("Phone Activation Code is required"),
        loggedIP: joi.string().required().label("Logged IP is required")
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
    
    bcrypt.hash(req.body.password, saltRound, (err, hash) => {
    if(err){
    console.log(err);
    }
    
    /* const values = [userid, fullname, phone, email, hash, registeras, emailActivation, phoneActivationCode, loggedIP]; */

    /* const values = [req.body.userid, req.body.fullname, req.body.phone, req.body.email, hash, req.body.registeras, req.body.emailActivation, req.body.phoneActivationCode, req.body.loggedIP]; */
    

    let sqlQuery = 'call OnboardingSP(?,?,?,?,?,?,?,?,?)';
    connection.query(sqlQuery, [req.body.userid, req.body.fullname, req.body.phone, req.body.email, hash, req.body.registeras, req.body.emailActivation, req.body.phoneActivationCode, req.body.loggedIP], (err, result)=> {

         console.log(req.body.userid, req.body.fullname, req.body.phone, req.body.email, hash, req.body.registeras, req.body.emailActivation, req.body.phoneActivationCode, req.body.loggedIP); 
        if(err){
            console.log(err);
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
            //emailactivation.sendConfirmationEmail(fullname, subject, emailActivation);

       return res.status(200).json(
           {
               onboarded: true, 
               message: "success",
            });
        }        
       });    
    })
}
catch (e) {
    console.log(`Error in create`, e);
    next(e);
}
}

//exports.signin = (req, res, next) => {
    const signin = (req, res, next) => {
    try{
        /* const username = req.body.username;
        const password = req.body.password; */

        const schema = joi.object({         
            username: joi.string().max(35).required().label("Username is required"),
            password: joi.string().max(125).required().label("Password is required"),            
        });
    
        const { error } = schema.validate(req.body);
    
        const loginQuery = "SELECT * FROM aiimma_membersaccess WHERE EmailID = ? OR PhoneNo= ? AND LoginStatus='Enabled' AND emailValidated='1'"

        connection.query(loginQuery, [req.body.username, req.body.username], (err, result) => {
        /* connection.query("SELECT * FROM aiimma_membersaccess WHERE EmailID = ? OR PhoneNo= ? AND LoginStatus='Enabled'", req.body.username, (err, result) => { */
          
          if(err){
          //res.send({err: err});
          return res.status(StatusCodes.NOT_FOUND).send({ message: "No such user found." });
          /* if(req.body.username =="" || req.body.password =="")
          {
              return res.status(StatusCodes.BAD_REQUEST).json({ message: "No such user found." })
          }
          return res.status(StatusCodes.NOT_FOUND).json({ message: "Good request but No such user found." }); */
        }

        else{
            if(result.length > 0) 
            {                   
                console.log(`Using result[0].pwd ==> ${result[0].Pwd}`);               
                console.log(`Using EmalID ==> ${result[0].EmailID}`);
                console.log(`Using PhoneNo ==> ${result[0].PhoneNo}`);


                bcrypt.compare(req.body.password, result[0].Pwd, (error, response) => {
                 if(response) 
                 {            

                const registeras = result[0].Login_Role;

                if(registeras == "AG")
         {             
             const userData = dbhelper.agentLoginVW(req.body.username);                        

             const token = jwt.sign({userData}, process.env.TOKEN_SECRET, {
                algorithm: 'HS256',
                expiresIn: jwtExpirySeconds
              });

              /* return res.status(StatusCodes.OK).send({"expires_in":jwtExpirySeconds,"access_token":token,"token_type": "bearer","userData":userData});  */

              return res.status(StatusCodes.OK).send({"expires_in":jwtExpirySeconds,"access_token":token,"token_type": "bearer","userData":userData}); 
              
              
         }

         if(registeras == "AS")
         {
             //it is AdmnStaff
         }

         if(registeras == "DRV")
         {
            const userData = dbhelper.driverLoginVW(req.body.username);

            const token = jwt.sign({userData}, process.env.TOKEN_SECRET, {
                algorithm: 'HS256',
                expiresIn: jwtExpirySeconds
              });

              return res.status(StatusCodes.OK).send({"expires_in":jwtExpirySeconds,"access_token":token,"token_type": "bearer","userData":userData});
         }

         if(registeras == "HBBT")
         {
            const userData = dbhelper.hbbtLoginVW(req.body.username);

            const token = jwt.sign({userData}, process.env.TOKEN_SECRET, {
                algorithm: 'HS256',
                expiresIn: jwtExpirySeconds
              });

              return res.status(StatusCodes.OK).send({"expires_in":jwtExpirySeconds,"access_token":token,"token_type": "bearer","userData":userData});
         }        

         if(registeras == "TRN")
         {
            const userData = dbhelper.transporterLoginVW(req.body.username);

             const token = jwt.sign({userData}, process.env.TOKEN_SECRET, {
                algorithm: 'HS256',
                expiresIn: jwtExpirySeconds
              });

              console.log("Authentication confirmed, you are authorized to performed activities.");

              return res.status(StatusCodes.OK).send({"expires_in":jwtExpirySeconds,"access_token":token,"token_type": "bearer","userData":userData}); 

              /* return res.status(StatusCodes.OK).json({"expires_in":jwtExpirySeconds,"access_token":token,"token_type": "bearer","userData":userData});  */

              // res.status(StatusCodes.OK).send({"expires_in":jwtExpirySeconds,"access_token":token,///"token_type": "bearer","userData":userData});  
              
              /* return res.status(StatusCodes.OK).json({LoggedIn: true, message: "You are logged in", userData: userData}); */
         }

         if(registeras == "SA" || registeras == "AS")
         {
            const userData = dbhelper.adminStaffLoginVW(req.body.username);

            const token = jwt.sign({userData}, process.env.TOKEN_SECRET, {
                algorithm: 'HS256',
                expiresIn: jwtExpirySeconds
              });

              return res.status(StatusCodes.OK).send({"expires_in":jwtExpirySeconds,"access_token":token,"token_type": "bearer","userData":userData});
         } 
        }//closes the if response for if bcrypt was correct

        else {
            return res.send("Wrong login credentials supplied.");
         } // closes this else
            
    }) //closes bcrypt
} //closes the if result.length               
        }//closes else
    }) //closes connection.query
    }// closes try

    catch (e) {
        console.log(`Error in create`, e);
        next(e);
    }
}

module.exports = { onboarding, signin }