const jwt = require("jsonwebtoken");
const {StatusCodes} = require('http-status-codes');
const {extractToken} = require('../utils/helper');
module.exports = function (req, res, next) {
    try {
        const token = extractToken(req);

        if (token == null) {
            return res.status(StatusCodes.UNAUTHORIZED).send("Unauthorized");
        }

        jwt.verify(token, process.env.TOKEN_SECRET, {}, (err, user) => {
            if (err) {
                console.log(err);
                return res.status(StatusCodes.FORBIDDEN).send("Invalid user");
            }
            req.user = user["userData"];
            next();
        });
    } catch (e) {
        next(e);
    }
};

