// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const bcrypt = require("bcrypt");

//NEED TO ADD IN MIDDLEWARES

const router = require("express").Router();

const User = require("../users/users-model.js");

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post("/register", (req, res, next) => {
  const { username, password } = req.body;

  const passHash = bcrypt.hashSync(password, 6);

  User.add({ username, password: passHash }).then(({ username }) => {
    res.status(201).json({ message: `Welcome to the party, ${username}!` });
  });
});

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

router.post("/login", (req, res, next) => {
  const { username, password } = req.body;

  User.findBy({ username })
    .first()
    .then((user) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user;

        res.json({ message: `Welcome ${username}!` });
      } else {
        res.status(401).json({ message: "Invalid credentials" });
      }
    });
});

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

router.get("/logout", (req, res) => {
  if (req.session.user) {
    const { username } = req.session.user;

    req.session.destroy((err) => {
      if (err) {
        res.json({ message: " You are unable to logout at this time" });
      } else {
        res.status(200).json({
          message: `logged out`,
        });
      }
    });
  } else {
    res.status(200).json({ message: "no session" });
  }
});

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
