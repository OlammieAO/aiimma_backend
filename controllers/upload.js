const _ = require('lodash');
const { StatusCodes } = require('http-status-codes');
var uuid = require('uuid');
var path = require('path');
exports.uploadFile = async (req, res, next) => {
    try {
        if (!req.files || Object.keys(req.files).length === 0) {
            return res.status(StatusCodes.BAD_REQUEST).send('No files found');
        }

        let uploadedFile = req.files.file;
        if (uploadedFile && !uploadedFile.name && uploadedFile.name.match(/\.(jpg|jpeg|png|pdf|docx|xlsx)$/i)) {
            return res.status(StatusCodes.BAD_REQUEST).send({ message: 'File type not allowed' });
        }
        let newFileName = uuid.v1() + path.extname(uploadedFile.name);
        let uploadPath = "./uploads/" + newFileName;
        uploadedFile.mv(uploadPath, function (err) {
            if (err)
                next(err)
            else
                return res.status(StatusCodes.OK).send({ message: newFileName });
        });
    } catch (e) {
        console.log(`Error in upload file`, e);
        next(e);
    }
};
