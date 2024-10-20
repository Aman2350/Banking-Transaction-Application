const express = require("express");
const {
  getBalanceHandler,
  withdraw,
  transfer,
} = require("../controllers/transactionController");
const { verifyToken } = require("../controllers/authController");
const router = express.Router();

router.get("/balance", verifyToken, getBalanceHandler);
router.post("/withdraw", verifyToken, withdraw);
router.post("/transfer", verifyToken, transfer);

module.exports = router;
