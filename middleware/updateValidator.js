const _ = require("lodash");
const {StatusCodes} = require('http-status-codes');

function updateValidator(model) {
    return (req, res, next) => {
        try {
            const bodyParams = req.body;
            if( _.isEmpty(model) || _.isEmpty(bodyParams)){
                return res.status(StatusCodes.BAD_REQUEST).send("Bad Request");
            }

            const newBody = {};
            for (const key in bodyParams) {
                const field = model[key];
                if (field && typeof bodyParams[key] === field.type) {
                    newBody[key] = bodyParams[key];
                }
            }
            req.body = newBody;
            next();
        } catch (e) {
            next(e);
        }
    };
}

module.exports = updateValidator;
