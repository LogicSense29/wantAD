import express from "express";
import cors from "cors";
import { authRoute } from "./route/auth";

const app = express();
const port = process.env.PORT;

//MiddeleWare
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://ip-address:5173",
      "https://nameofapp.vercel.app",
    ],
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE"],
    credentials: true,
  })
);

app.use(cors());
app.use(express.json());

db.connect();

//Routes
app.use("/api/auth", authRoute);

app.listen(port, () => {
  console.log("Port is Listening on ", port);
});
