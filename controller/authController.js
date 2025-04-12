import validator from "validator";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import {
  sendResetPasswordEmail,
  sendVerificationEmail,
} from "../utilities/emails";

// Generate a JWT or session token Function
const createToken = (_id) => {
  return jwt.sign({ _id }, process.env.SECRET, { expiresIn: "3d" });
};

export const signup = async (req, res) => {
  const { username, mobile, email, password } = req.body;

  if (!username || !mobile || !email || !password) {
    return res.status(400).json({ error: "fields can not be empty" });
  }

  // Check if username is empty or too short/long
  if (!validator.isLength(username, { min: 3, max: 20 })) {
    return { valid: false, error: "Username must be 3-20 characters long" };
  }

  // Check allowed characters (letters, numbers, underscore)
  const usernameRegex = /^[a-zA-Z0-9_]+$/;
  if (!usernameRegex.test(username)) {
    return res.json({
      valid: false,
      error: "Username can only contain letters, numbers, and underscores",
    });
  }

  if (validator.isMobilePhone(mobile)) {
    return res.status(400).json({ error: "Invalid Phone number" });
  }

  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: "Invalid Email" });
  }

  if (!validator.isStrongPassword(password)) {
    return res.status(400).json({ error: "Password is not Strong Enough" });
  }

  try {
    const { rows } = await db.query(
      "SELECT id FROM users WHERE email = $1 OR mobile = $2",
      [email, mobile]
    );
    if (rows.length > 0) {
      res.status(401).json({ message: "User Already Exist" });
    } else {
      //hash password
      const salt = bcrypt.genSalt(10);
      const hashed = bcrypt.hash(password, salt);

      //Add User to Database
      const { rows } = await db.query(
        "INSERT INTO users(username, mobile, email, password) VALUES($1,$2,$3) RETURNING id, email, username",
        [username, mobile, email, hashed]
      );

      const user = rows[0];
      const user_email = user.email;
      const user_username = user.username;
      const user_id = user.id;

      //OTP
      await sendOTP(user_id, user_email, user_username, res);
    }
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Something went wrong" });
  }
};

//Login
export const login = async (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier) {
    return res.status(400).json({ error: `${identifier} is required` });
  }

  if (!password) {
    return res.status(400).json({ error: "password is required" });
  }

  // check if identifier is an email
  const isEmail = validator.isEmail(identifier);
  const field = isEmail ? "email" : "username";

  try {
    const { rows } = await db.query(`SELECT * FROM users WHERE ${field} = $1`, [
      identifier,
    ]);

    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid Password" });
    }

    if (!user.email_verified) {
      return res
        .status(403)
        .json({ error: "Please verify your email before logging in" });
    }

    // Generate a JWT or session token
    // const token = jwt.sign({ user_id: user.user_id }, process.env.JWT_SECRET, {
    //   expiresIn: "2d",
    // });
    const id = user.user_id;
    const token = createToken(id);

    return res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user.user_id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Something went wrong" });
  }
};

export const sendOTP = async (id, email, username, res) => {
  try {
    //Generate OTP
    const otp = `${Math.floor(100000 + Math.random() * 900000)}`;

    //Hash using Crypto
    const cryptoHashed = crypto.createHash("sha256").update(otp).digest("hex");

    // Expiry time 5 minutes from now
    const otpExpire = new Date(Date.now() + 5 * 60 * 1000);

    // Store OTP in DB
    const { rows } = await db.query(
      "INSERT INTO otp_verifications(user_id, otp, otp_expires_at) VALUES($1,$2,$3,$4) RETURNING *",
      [id, cryptoHashed, otpExpire]
    );
    if (rows.length > 0) {
      return res.status(404).json({ error: "Error" });
    }

    sendVerificationEmail(username, email, otp, res);
  } catch (err) {
    console.error("Error generating OTP:", err);
    return res.status(500).json({ error: "failed to Generate OTP" });
  }
};

export const userVerification = async (req, res) => {
  const { email, otp } = req.body;

  if (!otp || !email) {
    return res.status(400).json({ error: "Empty OTP Not Allowed" });
  }

  try {
    const { rows } = await db.query(
      "SELECT otp, otp_expires_at, user_id FROM otp_verifications WHERE email = $1",
      [email]
    );

    // Check if OTP record exists
    if (rows.length === 0) {
      return res.status(404).json({ error: "No OTP found for this user" });
    }

    const hashedOTP = rows[0].otp;
    const expiringDate = new Date(rows[0].otp_expires_at);
    const currentDate = new Date();

    // First, check if the OTP is correct
    const cryptoHashed = crypto.createHash("sha256").update(otp).digest("hex");
    if (cryptoHashed !== hashedOTP) {
      return res.status(401).json({ error: "Invalid OTP" });
    }

    // Then, check if the OTP is expired
    const id = rows[0].user_id;
    if (currentDate > expiringDate) {
      await db.query("DELETE FROM otp_verifications WHERE user_id = $1", [id]);
      return res.status(401).json({ error: "Expired OTP" });
    }

    // Update email
    await db.query("UPDATE users SET email_verified = TRUE WHERE id = $1", [
      id,
    ]);
    // Delete OTP after successful verification
    await db.query("DELETE FROM otp_verifications WHERE user_id = $1", [id]);

    //Get User Info
    const { rows: userInfo } = await db.query(
      "SELECT email, username FROM users WHERE user_id = $1",
      [id]
    );

    const user = userInfo[0];

    //Token
    const token = createToken(id);

    // OTP is correct and verified
    return res.status(200).json({
      message: "Verification successful",
      token,
      user: {
        id: id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("Error verifying OTP:", err);
    return res.status(500).json({ error: "Server Error" });
  }
};

export const resendOTP = async (req, res) => {
  const { id } = req.body;

  try {
    const { rows } = await db.query(
      "SELECT id, email, username FROM users WHERE id = $1",
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "No User Found" });
    }

    const { id: user_id, email: user_email, username: user_username } = rows[0];

    // Send OTP and return the OTP value
    const otp = await sendOTP(user_id, user_email, user_username, res);

    // Send email
    await sendVerificationEmail(user_id, user_email, otp);

    return res.status(200).json({ message: "OTP Resent Successfully" });
  } catch (err) {
    console.error("Error resending OTP:", err);
    return res.status(500).json({ error: "Failed to resend OTP" });
  }
};

//Request Password Reset
export const forgetPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const { rows } = await db.query(
      "SELECT email FROM users WHERE email = $1",
      [email]
    );

    if (rows.length == 0) {
      return res.status(401).json({ error: "User does not exist" });
    }
    const isVerified = rows[0].email_verified;

    if (!isVerified) {
      return res.status(401).json({ error: "User is not verified" });
    }

    try {
      //User id from Database
      const user_id = rows[0].user_id;

      //set Token
      const setToken = crypto.randomBytes(32).toString("hex");

      //Hash Token
      const hashed = crypto.createHash("sha256").update(setToken).digest("hex");

      //Set Expiring Date
      let expiringTime = Math.floor((Date.now() + 10 * 60 * 1000) / 1000);

      //Reset URL
      const resetURL = `${req.protocol}://${req.get(
        "host"
      )}/user/reset_password/${setToken}`;

      await db.query(
        "INSERT INTO password_resets (user_id, reset_token, expires_at) VALUES($1,$2,to_timestamp($3))",
        [user_id, hashed, expiringTime]
      );

      await sendResetPasswordEmail(email, resetURL);
    } catch (err) {
      return res
        .status(500)
        .json({ error: "Failed to create password reset token" });
    }
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};

//ResetPassword

export const resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    // Hash the token for comparison
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    // Query to check if token exists
    const { rows } = await db.query(
      "SELECT * FROM reset_password WHERE token = $1",
      [hashedToken]
    );

    // Check if Token Exists
    if (rows.length === 0) {
      return res.status(404).json({ error: "Token does not exist" });
    }

    // Get token details from the database
    const storedToken = rows[0].token;
    const currentDate = new Date();
    const expiringDate = rows[0].expires_at;
    const id = rows[0].user_id;

    // First, check if the Token is correct
    if (storedToken !== hashedToken) {
      return res.status(401).json({ error: "Invalid Token" });
    }

    // Then, check if the Token is expired
    if (currentDate > expiringDate) {
      // Delete expired token from DB
      await db.query("DELETE FROM reset_password WHERE user_id = $1", [id]);
      return res.status(400).json({ error: "Expired Token" });
    }

    // Proceed to reset the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Update password in the users table
    const { rows: updatedRows } = await db.query(
      "UPDATE users SET password = $1 WHERE user_id = $2 RETURNING user_id",
      [hashedPassword, id]
    );

    if (updatedRows.length > 0) {
      // Delete the used reset token
      await db.query("DELETE FROM reset_password WHERE user_id = $1", [id]);

      // Return success response
      return res.status(200).json({ message: "Password Updated" });
    } else {
      return res.status(400).json({ error: "Failed to update password" });
    }
  } catch (err) {
    //logging for better error traceability in production
    console.error("Error during password reset:", err);
    return res.status(500).json({ error: err.message });
  }
};
