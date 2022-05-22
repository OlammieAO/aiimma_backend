const express = require('express');
const checkAuth = require('../middleware/jwtVerify');
const controller = require('../controllers/aiimma_staffs');
const bodyValidator = require("../middleware/bodyValidator");
const createDto = require('../dto/aiimma_staffs.dto');
const router = express.Router();

router.get('/', checkAuth, controller.getAll);
router.post('/', checkAuth, bodyValidator(createDto), controller.create);
router.get('/:id', checkAuth, controller.getById);
router.patch('/:id', checkAuth, controller.update);
router.delete('/:id', checkAuth, controller.remove);
router.get('/search/:searchKey', checkAuth, controller.search);

router.get('/getby/Rolecode/:RoleCode', checkAuth, controller.getByRolecode);
module.exports = router;
