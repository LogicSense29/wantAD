import nodemailer from "nodemailer";

export const transporter = nodemailer.createTransport({
  host: "umera.ng",
  port: 587,
  secure: false, // true for port 465, false for other ports
  auth: {
    user: process.env.EMAIL,
    pass: process.env.NEWPASS,
    tls: {
      rejectUnauthorized: false,
    },
  },
});

export const sendVerificationEmail = async (username, email, otp, res) => {
  const mailOptions = {
    from: process.env.EMAIL,
    to: email,
    subject: "Test",
    html: `
    <p>Username : ${username}</p>
    <strong>${otp}</strong>
    <p>Expires in 5 mins</p>
    `,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
      res.status(400).json({ error: "Message Failed" });
    } else {
      console.log("Message sent:", info.messageId);
      console.log("Preview URL:", nodemailer.getTestMessageUrl(info)); // Useful for testing with Ethereal
      console.log("Accepted:", info.accepted); // Array of recipients that accepted the email
      console.log("Rejected:", info.rejected); // Array of recipients that rejected the email
      console.log("Pending:", info.pending); // Array of recipients where delivery is pending
    }
  });
};

export const sendResetPasswordEmail = async (email, url) => {
  const mailOptions = {
    from: process.env.EMAIL,
    to: email,
    subject: "Test",
    html: `
        <p>Username : ${username}</p>
        <a href=${url}>Reset Password</a>
        <p>Expires in 10 mins</p>
        `,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
      res.status(400).json({ error: "Message Failed" });
    } else {
      console.log("Message sent:", info.messageId);
      console.log("Preview URL:", nodemailer.getTestMessageUrl(info)); // Useful for testing with Ethereal
      console.log("Accepted:", info.accepted); // Array of recipients that accepted the email
      console.log("Rejected:", info.rejected); // Array of recipients that rejected the email
      console.log("Pending:", info.pending); // Array of recipients where delivery is pending
    }
  });
};
