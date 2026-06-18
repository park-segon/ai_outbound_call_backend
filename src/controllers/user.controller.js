import pool from "../db.js";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import fetch from "node-fetch";
import twilio from "twilio";
import jwt from "jsonwebtoken";

// 토큰 발급 함수 (헬퍼)
const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { id: user.id, email: user.email_id, role: user.role },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: "15m" }, // 억세스 토큰은 짧게!
  );

  const refreshToken = jwt.sign(
    { id: user.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" }, // 리프레쉬 토큰은 길게!
  );

  return { accessToken, refreshToken };
};

export const login = async (req, res) => {
  try {
    const { admin_id, password } = req.body;

    const [rows] = await pool.query(
      "SELECT * FROM admin_users WHERE adminId = ?",
      [admin_id],
    );

    const user = rows[0];
    if (!user) {
      return res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 틀렸습니다." });
    }

    // 비밀번호 체크
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 틀렸습니다." });
    }

    // 토큰 발급
    const { accessToken, refreshToken } = generateTokens({
      ...user,
      role: "admin",
    });

    res.status(200).json({
      message: "로그인 성공!",
      accessToken,
      refreshToken,
      user: { admin_id: user.adminId, adming_name: user.name },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

export const logoutUser = async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      message: "서버 로그아웃 처리 완료! 클라이언트 토큰을 삭제하세요. 웅..!",
    });
  } catch (err) {
    console.error("Logout Error:", err);
    res
      .status(500)
      .json({ message: "로그아웃 처리 중 서버 오류가 발생했어요." });
  }
};

export const createUser = async (req, res) => {
  try {
    const { name, admin_id, password, rank, phone_number } = req.body;

    const missingFields = [];
    if (!name) missingFields.push("name");
    if (!admin_id) missingFields.push("admin_id");

    if (!password) missingFields.push("password");
    if (!rank) missingFields.push("rank");
    if (!phone_number) missingFields.push("phone_number");

    if (missingFields.length > 0) {
      return res
        .status(400)
        .json({ message: `Missing fields: ${missingFields.join(", ")}` });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      "INSERT INTO admin_users (name, adminId, password, jik, phone_number) VALUES (?, ?, ?, ?, ?)",
      [name, admin_id, hashedPassword, rank, phone_number],
    );

    const [rows] = await pool.query(
      "SELECT id, name, adminId, jik, phone_number created_at FROM admin_users WHERE id = ?",
      [result.insertId],
    );

    if (!rows[0])
      return res.status(500).json({ message: "User not found after insert" });

    res.status(201).json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

function parsePaging(query) {
  const page = Math.max(1, parseInt(query.page ?? "1", 10));
  const limit = Math.min(100, Math.max(1, parseInt(query.limit ?? "20", 10)));
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}
export const listUsers = async (req, res) => {
  try {
    const limit = Number(req.query.limit || 10);
    const page = Number(req.query.page || 1);

    const offset =
      req.query.offset !== undefined
        ? Number(req.query.offset)
        : (page - 1) * limit;

    const name = (req.query.name || "").trim();
    const adminId = (req.query.adminId || "").trim();
    const jik = (req.query.jik || "").trim();

    const where = [];
    const params = [];

    if (name) {
      where.push("name LIKE ?");
      params.push(`%${name}%`);
    }

    if (adminId) {
      where.push("adminId LIKE ?");
      params.push(`%${adminId}%`);
    }

    if (jik) {
      where.push("jik LIKE ?");
      params.push(`%${jik}%`);
    }

    const whereSQL = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const [rows] = await pool.query(
      `SELECT id, name, adminId, jik, phone_number, created_at
       FROM admin_users
       ${whereSQL}
       ORDER BY id DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset],
    );

    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) AS total
       FROM admin_users
       ${whereSQL}`,
      params,
    );

    res.json({
      total,
      page,
      limit,
      offset,
      totalPages: Math.ceil(total / limit),
      items: rows,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "관리자 목록 조회에 실패하였습니다.",
    });
  }
};
