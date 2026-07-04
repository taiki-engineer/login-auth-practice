const router = require("express").Router();
const { body, validationResult } = require("express-validator");
const { User } = require("../db/user");
const bcrypt = require("bcrypt");
const JWT = require("jsonwebtoken");

router.get("/", (req, res) => {
    res.send("Hello AuthJs");
})

// １，ユーザー新規登録用のAPI
router.post("/register",
    // ２，バリデーションチェック
    body("email").isEmail(),
    body("password").isLength({min: 6}),
    async (req, res) => {

        const email = req.body.email;
        const password = req.body.password;

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({errors: errors.array()});
        }

        // ３，DBにユーザーが存在しているか確認
        const user = User.find((user) => user.email === email);
        if (user) {
            return res.status(400).json([
                {
                    message: "すでにそのユーザーは存在しています",
                },
            ]);
        }

        // ４，パスワードの暗号化
        let hashedPassword = await bcrypt.hash(password, 10)
        // console.log(hashedPassword);

        // ５，DBへ保存
        User.push({
            email,
            password: hashedPassword,
        });

        // ６，クライアントへJWTの発行
        const token = await JWT.sign({
            email,
        },
        "SECRET_KEY",
        {
            expiresIn: "24h",
        }
        );

        return res.json({
            token: token,
        });
    }
);

// ログイン用のAPI
router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const user = User.find((user) => user.email === email);
    if (!user) {
        return res.status(400).json([
            {
                message: "すでにそのユーザーは存在ません",
            },
        ]);
    }

    // パスワードの複合、照合
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        return res.status(400).json([
            {
                message: "パスワードが異なります",
            },
        ]);
    }

    const token = await JWT.sign({
        email,
    },
    "SECRET_KEY",
    {
        expiresIn: "24h",
    }
    );

    return res.json({
        token: token,
    });

})

// DBのユーザー確認するAPI
router.get("/allUser", (req, res) => {
    return res.json(User);
});

module.exports = router;
