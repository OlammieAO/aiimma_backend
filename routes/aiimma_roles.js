const express = require('express');
const checkAuth = require('../middleware/jwtVerify');
const controller = require('../controllers/aiimma_roles');
const bodyValidator = require("../middleware/bodyValidator");
const createDto = require('../dto/aiimma_roles.dto');
const router = express.Router();

router.get('/', checkAuth, controller.getAll);
router.post('/', checkAuth, bodyValidator(createDto), controller.create);
router.get('/:RoleCode', checkAuth, controller.getById);
router.patch('/:RoleCode', checkAuth, controller.update);
router.delete('/:RoleCode', checkAuth, controller.remove);
router.get('/search/:searchKey', checkAuth, controller.search);

module.exports = router;
