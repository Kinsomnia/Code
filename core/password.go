package core

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"time"
)

func Password() {
	var passwd string
	// 连接数据库
	db, err := sql.Open("mysql", "root:123456@tcp(127.0.0.1:3306)/test?parseTime=true")
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	// 查询用户信息
	var username string
	var password string
	var attempts int
	var lastAttempt time.Time
	err = db.QueryRow("SELECT username, password, attempts, last_attempt FROM user WHERE username=?", "admin").Scan(&username, &password, &attempts, &lastAttempt)
	if err != nil {
		panic(err.Error())
	}

	// 检查密码和密码次数
	fmt.Println("Please input password:")
	fmt.Scan(&passwd)
	if password == passwd && attempts < 3 && time.Now().Sub(lastAttempt) > time.Minute*5 {
		fmt.Println("登录成功！")
		// 在这里可以进行其他操作，如获取用户信息等

		// 重置密码次数和最后一次尝试时间
		_, err = db.Exec("UPDATE user SET attempts=0, last_attempt=NOW() WHERE username=?", username)
		if err != nil {
			panic(err.Error())
		}
	} else if password != passwd && attempts < 3 {
		fmt.Println("密码错误！还剩", 2-attempts, "次机会。")
		// 更新密码次数和最后一次尝试时间
		_, err = db.Exec("UPDATE user SET attempts=?, last_attempt=NOW() WHERE username=?", attempts+1, username)
		if err != nil {
			panic(err.Error())
		}
	} else {
		fmt.Println("密码错误次数过多，请稍后再试。")
	}
}
