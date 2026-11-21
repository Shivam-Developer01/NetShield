const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const authenticate = require('../middleware/authenticate');
const authorize = require('../middleware/authorize');
const { validateUpdateUser } = require('../validators/userValidator');

// Protect all user management routes for ADMIN only
router.use(authenticate);
router.use(authorize('ADMIN'));

router.get('/', userController.getUsers);
router.get('/:id', userController.getUserById);
router.patch('/:id', validateUpdateUser, userController.updateUser);
router.delete('/:id', userController.deleteUser);

module.exports = router;
