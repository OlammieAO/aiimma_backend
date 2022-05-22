const express = require('express');
const checkAuth = require('../middleware/jwtVerify');
const controller = require('../controllers/aiimma_membersaccess');
const bodyValidator = require("../middleware/bodyValidator");
const createDto = require('../dto/aiimma_membersaccess.dto');
const router = express.Router();

router.get('/', checkAuth, controller.getAll);
router.post('/', bodyValidator(createDto), controller.create);
router.get('/:ID', checkAuth, controller.getById);
router.patch('/:ID', checkAuth, controller.update);
router.delete('/:ID', checkAuth, controller.remove);
router.get('/search/:searchKey', checkAuth, controller.search);

router.get('/getby/ID/:ID', checkAuth, controller.getByID);
router.get('/getby/Rolecode/:RoleCode', checkAuth, controller.getByRolecode);
module.exports = router;
