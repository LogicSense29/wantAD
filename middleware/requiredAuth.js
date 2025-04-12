// import db from "../dbModel/db.js";
import jwt from "jsonwebtoken";

export const requiredAuth = async (req, res, next) => {
  const { authorization } = req.headers;

  if (!authorization) {
    res.status(401).json({ error: "Authorization Token Required" });
  } else {
    const token = authorization.split(" ")[1];

    try {
      const { _id } = jwt.verify(token, process.env.SECRET);
      const { rows } = await db.query(
        "SELECT user_id FROM auth WHERE user_id = $1",
        [_id]
      );

      req.user = rows[0].user_id;

      next();
    } catch (err) {
      console.error(err);
      console.error(err.expiredAt);
      res.status(401).json({ error: "Request is not Authorized" });
    }
  }
};
