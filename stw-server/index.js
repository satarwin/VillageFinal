const express = require("express");
const app = express();
const cors = require("cors");
const multer = require("multer");
const path = require("path");

app.use(cors());
app.use(express.json());

var bodyParser = require("body-parser");
var jsonParser = bodyParser.json();

// ประกาศการเข้ารหัส
const bcrypt = require("bcrypt");
const saltRounds = 10;

var jwt = require("jsonwebtoken");
const secret = "Fullstack-login";

const mysql = require("mysql2");
// const Connection = require("mysql2/typings/mysql/lib/Connection");
const db = mysql.createConnection({
  user: "root",
  host: "localhost",
  password: "",
  database: "stwvillage",
});

// สร้างการบันทึกประวัติ
app.post("/registerowner", jsonParser, function (req, res, next) {
  bcrypt.hash(req.body.password.trim(""), saltRounds, function (err, hash) {
    db.execute(
      "INSERT INTO owner(fullname,emailOwner,phone,password,home_num) VALUES (?,?,?,?,?)",
      [
        req.body.fullname.trim(""),
        req.body.emailOwner.trim(),
        req.body.phone.trim(""),
        hash,
        req.body.home_num.trim(""),
      ],
      function (err, results, fields) {
        if (err) {
          res.json({ status: "error", message: err });
          alert({ message: err });
          console.log(err);
          return;
        }
        res.json({ status: "ok" });
      }
    );
  });
});

// API LOGIN OWNER
app.post("/loginowner", jsonParser, function (req, res, next) {
  db.execute(
    "SELECT * FROM owner WHERE emailOwner=?",
    [req.body.emailOwner],
    function (err, owner, fields) {
      if (err) {
        res.json({ status: "error", message: err });
        return;
      }
      if (owner.length == 0) {
        res.json({ status: "error", message: "ON OWner" });
        return;
      }
      bcrypt.compare(
        req.body.password,
        owner[0].password,
        function (err, isLogin) {
          if (isLogin) {
            var token = jwt.sign({ emailOwner: owner[0].emailOwner }, secret, {
              expiresIn: "24h",});res.json({ status: "ok", message: "login success", token });
          } else {res.json({ status: "error", message: "login fsiled" });
          }
        }
      );
    }
  );
});

app.get("/authen/users", jsonParser, function (req, res, next) {
  db.query("SELECT `id_owner`, `fullname`, `emailOwner`, `phone`, `password`, `home_num` FROM `owner` WHERE `emailOwner` ", (err, data) => {
    if (err) {
      console.log(err);
      res.json({ status: "error", message: err.message });
    } else {
      const token = req.headers.authorization;
      var decoded = jwt.verify(token, secret);
      res.json({ status: "ok", secret,data });
     
    }
  });
});
//ter

// ตรวจสอบ token -------------------------------------------->
// app.post("/authen", jsonParser, function (req, res, next) {
//   try {
//     const token = req.headers.authorization.split(" ")[1]
//     var decoded = jwt.verify(token, secret)
//     res.json({ status:'ok', decoded })
//   } catch (err) {
//     res.json({status: 'error',message: err.message});
//   }
// });

//---------------------------------> for ADMIN <--------------------------------

//LOGIN ADMIN
app.post("/signinadmin", jsonParser, function (req, res, next) {
  db.execute(
    "SELECT * FROM admin_table WHERE User_Admin=?",
    [req.body.User_Admin],
    function (err, admin_table, fields) {
      if (err) {
        res.json({ status: "error", message: err });
        return;
      }
      if (admin_table.length == 0) {
        res.json({ status: "error", message: "NOT A D M I N" });
        return;
      }
      bcrypt.compare(
        req.body.Pass_Admin,
        admin_table[0].Pass_Admin,
        function (err, isLogin) {
          if (isLogin) {
            var token = jwt.sign(
              { User_Admin: admin_table[0].User_Admin },
              secret,
              { expiresIn: "1h" }
            );
            res.json({ status: "ok", message: "ADMIN LOGIN SUCCESS", token });
          } else {
            res.json({ status: "error", message: "ADMIN LOGIN Failed" });
          }
        }
      );
    }
  );
});
app.get("/authen/admin", jsonParser, function (req, res, next) {
  db.query("SELECT * FROM admin_table", (err, data) => {
    if (err) {
      console.log(err);
      res.json({ status: "error", message: err.message });
    } else {
      const token = req.headers.authorization.split(" ")[1];
      var decoded = jwt.verify(token, secret);
      res.json({ status: "ok", data });
    }
  });
});

app.post("/create", jsonParser, function (req, res, next) {
  bcrypt.hash(req.body.Pass_Admin, saltRounds, function (err, hash) {
    db.execute(
      "INSERT INTO admin_table(Name_Admin,User_Admin,Pass_Admin,Phone_Admin,Email_Admin) VALUES (?,?,?,?,?)",
      [
        req.body.Name_Admin,
        req.body.User_Admin,
        hash,
        req.body.Phone_Admin,
        req.body.Email_Admin,
      ],
      function (err, results, fields) {
        if (err) {
          res.json({ status: "error", message: err });
          return;
        }
        res.json({ status: "ok" });
      }
    );
  });
});

//---------------------------------> for GUARD <--------------------------------
app.post("/createguard", jsonParser, function (req, res, next) {
  bcrypt.hash(req.body.passG, saltRounds, function (err, hash) {
    db.execute(
      "INSERT INTO guard_table(userG,nameG,phoneG,emailG,passG) VALUES (?,?,?,?,?)",
      [req.body.userG, req.body.nameG, req.body.phoneG, req.body.emailG, hash],
      function (err, results, fields) {
        if (err) {
          res.json({ status: "error", message: err });
          return;
        }
        res.json({ status: "ok" });
      }
    );
  });
});

//-----------------------------------------img up load
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, "public/images/outsider/");
//   },
//   filename: (req, file, cb) => {
//     cb(
//       null,
//       "file-" +
//         Date.now() +
//         "." +
//         file.originalname.split(".")[file.originalname.split(".").length - 1]
//     );
//   },
// });
// const upload = multer({ storage: storage });

//---------------------------------> for OUTSIDER <-----------------------------------

app.post("/createoutsider", jsonParser, function (req, res, next) {
  db.execute(
    "INSERT INTO outsider_table(Name_Outsider,Phone_Outsider,Carregistration,Reason_Outsider,Img_Outsider,Date_Outsider) VALUES (?,?,?,?,?,?)",
    [
      req.body.Name_Outsider,
      req.body.Phone_Outsider,
      req.body.Carregistration,
      req.body.Reason_Outsider,
      req.body.Img_Outsider,
      req.body.Date_Outsider,
    ],
    function (err, results, fields) {
      if (err) {
        res.json({ status: "error", message: err });

        return;
      }
      res.json({ status: "ok" });

      // res.render("show", req.file);
      //   res.json({ message: "Successfully uploaded files" });
      //   console.log("file uploaded")
    }
  );
});

app.put("/updateoutsider", (req, res) => {
  const id = req.body.id;
  const name = req.body.name;
  db.query(
    "UPDATE  outsider_table set Name_Outsider=?,Carregistration=?,Reason_Outsider=?,Date_Outsider=? WHERE ID_Outsider = ?",
    [
      Name_Outsider,
      Carregistration,
      Reason_Outsider,
      Date_Outsider,
      ID_Outsider,
    ],
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.send(result);
      }
    }
  );
});

app.get("/getoutsider", (req, res, next) => {
  const page = parseInt(req.query.page);
  const per_page = parseInt(req.query.per_page);
  const s_column = req.query.s_column;
  const s_direction = req.query.s_direction;
  const search = req.query.search;

  // const start_idx = (page - 1) * per_page;
  var params = [];
  var sql = "SELECT * FROM outsider_table";
  if (search) {
    sql += " WHERE Phone_Outsider LIKE ?";

    params.push("%" + search + "%");
  }
  // if (s_column) {
  //   sql += 'ORDER BY' + s_column + ' ' + s_direction;
  // }
  // sql += 'LIMIT ?, ?';
  // params.push(start_idx);
  // params.push(per_page);

  db.execute(sql, function (err, result, field) {
    console.log(result);
    res.json({ result: result });
    console.log(field);
    console.log(result);
    console.log(search);
    console.log(sql);
  });
});

app.listen("3001", function () {
  console.log("Server is runing on port 3001");
});
