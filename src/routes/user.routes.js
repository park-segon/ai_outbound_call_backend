import { Router } from "express";
import {
  logoutUser,
  login,
  createUser,
  listUsers,
} from "../controllers/user.controller.js";

import verifyToken from "../middlewares/verifyToken.js";

import multer from "multer";
import path from "path";

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const basename = path.basename(file.originalname, ext);
    // 파일명-날짜.확장자 형태로 깔끔하게 저장!
    cb(null, `${basename}-${Date.now()}${ext}`);
  },
});

const upload = multer({ storage: storage });

const router = Router();
router.get("/", verifyToken, listUsers); // GET    /api/users
router.post("/", verifyToken, createUser); // POST   /api/users
router.post("/login", login);
router.post("/logout", verifyToken, logoutUser);

export default router;
