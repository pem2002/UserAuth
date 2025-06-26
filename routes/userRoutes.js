const express = require ('express');
const router = express.Router();
const userController = require('../Controllers/userController');

router.get('/dashboard', userController.getDashboard);
router.get('/foods',userController.getAllFoods);

module.exports = router;
