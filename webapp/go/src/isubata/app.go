package main

import (
	crand "crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/middleware"
)

const (
	avatarMaxBytes = 1 * 1024 * 1024
)

var (
	db            *sqlx.DB
	ErrBadReqeust = echo.NewHTTPError(http.StatusBadRequest)
	ErrNotFound   = echo.ErrNotFound
	ErrDuplicate  = errors.New("duplicate")
)

type Renderer struct {
	templates *template.Template
}

func (r *Renderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return r.templates.ExecuteTemplate(w, name, data)
}

func init() {
	seedBuf := make([]byte, 8)
	crand.Read(seedBuf)
	rand.Seed(int64(binary.LittleEndian.Uint64(seedBuf)))

	db_host := os.Getenv("ISUBATA_DB_HOST")
	if db_host == "" {
		db_host = "127.0.0.1"
	}
	db_port := os.Getenv("ISUBATA_DB_PORT")
	if db_port == "" {
		db_port = "3306"
	}
	db_user := os.Getenv("ISUBATA_DB_USER")
	if db_user == "" {
		db_user = "root"
	}
	db_password := os.Getenv("ISUBATA_DB_PASSWORD")
	if db_password != "" {
		db_password = ":" + db_password
	}

	dsn := fmt.Sprintf("%s%s@tcp(%s:%s)/isubata?parseTime=true&loc=Local&charset=utf8mb4",
		db_user, db_password, db_host, db_port)

	log.Printf("Connecting to db: %q", dsn)
	db, _ = sqlx.Connect("mysql", dsn)
	for {
		err := db.Ping()
		if err == nil {
			break
		}
		log.Println(err)
		time.Sleep(time.Second * 3)
	}

	db.SetMaxIdleConns(1024) // デフォルトだと2
	db.SetConnMaxLifetime(0) // 一応セット
	// db.SetConnMaxIdleTime(0)
	db.SetMaxOpenConns(64)
	// db.SetConnMaxLifetime(5 * time.Minute)
	log.Printf("Succeeded to connect db.")
}

type User struct {
	ID          int64     `json:"-" db:"id"`
	Name        string    `json:"name" db:"name"`
	Salt        string    `json:"-" db:"salt"`
	Password    string    `json:"-" db:"password"`
	DisplayName string    `json:"display_name" db:"display_name"`
	AvatarIcon  string    `json:"avatar_icon" db:"avatar_icon"`
	CreatedAt   time.Time `json:"-" db:"created_at"`
}

func getUser(userID int64) (*User, error) {
	return userMap[userID], nil
	// u := User{}
	// if err := db.Get(&u, "SELECT * FROM user WHERE id = ?", userID); err != nil {
	// 	if err == sql.ErrNoRows {
	// 		return nil, nil
	// 	}
	// 	return nil, err
	// }
	// return &u, nil
}

func addMessage(channelID, userID int64, content string) (int64, error) {
	res, err := db.Exec(
		"INSERT INTO message (channel_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())",
		channelID, userID, content)
	if err != nil {
		return 0, err
	}
	channelMap[int(channelID)].MessageCount++
	return res.LastInsertId()
}

type Message struct {
	ID        int64     `db:"id"`
	ChannelID int64     `db:"channel_id"`
	UserID    int64     `db:"user_id"`
	Content   string    `db:"content"`
	CreatedAt time.Time `db:"created_at"`
}

func queryMessages(chanID, lastID int64) ([]Message, error) {
	msgs := []Message{}
	err := db.Select(&msgs, "SELECT id, channel_id, user_id, content, created_at FROM message WHERE channel_id = ? AND id > ? ORDER BY id DESC LIMIT 100",
		chanID, lastID)
	return msgs, err
}

func sessUserID(c echo.Context) int64 {
	r := c.Request()
	sessionData, ok := getSession(r)
	if !ok {
		return 0
	}
	return sessionData.UserID
	// sess, _ := session.Get("session", c)
	// var userID int64
	// if x, ok := sess.Values["user_id"]; ok {
	// 	userID, _ = x.(int64)
	// }
	// return userID
}

func sessSetUserID(c echo.Context, id int64) {
	w := c.Response().Writer
	setSession(w, SessionData{id, randomString(20)})
	// sess, _ := session.Get("session", c)
	// sess.Options = &sessions.Options{
	// 	HttpOnly: true,
	// 	MaxAge:   0,
	// }
	// sess.Values["user_id"] = id
	// sess.Save(c.Request(), c.Response())
}

func ensureLogin(c echo.Context) (*User, error) {
	var user *User
	var err error
	r := c.Request()
	w := c.Response().Writer
	userID := sessUserID(c)
	if userID == 0 {
		goto redirect
	}

	user, err = getUser(userID)
	if err != nil {
		goto redirect
		return nil, err
	}

	if user == nil {
		deleteSession(r, w)
		goto redirect
	}
	// 	if user == nil {
	// 		sess, _ := session.Get("session", c)
	// 		delete(sess.Values, "user_id")
	// 		sess.Save(c.Request(), c.Response())
	// 		goto redirect
	// 	}
	return user, nil

redirect:
	c.Redirect(http.StatusSeeOther, "/login")
	return nil, nil
}

const LettersAndDigits = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(n int) string {
	b := make([]byte, n)
	z := len(LettersAndDigits)

	for i := 0; i < n; i++ {
		b[i] = LettersAndDigits[rand.Intn(z)]
	}
	return string(b)
}

func register(name, password string) (int64, error) {
	salt := randomString(20)
	digest := fmt.Sprintf("%x", sha1.Sum([]byte(salt+password)))

	res, err := db.Exec(
		"INSERT INTO user (name, salt, password, display_name, avatar_icon, created_at)"+
			" VALUES (?, ?, ?, ?, ?, NOW())",
		name, salt, digest, name, "default.png")
	if err != nil {
		return 0, err
	}
	userID, err := res.LastInsertId()
	fmt.Println(userID)
	if err != nil {
		return 0, err
	}
	userList = append(userList, User{userID, name, salt, digest, name, "default.png", time.Now()})
	userMap[userID] = &userList[len(userList)-1]
	userNameMap[name] = &userList[len(userList)-1]
	return userID, nil
}

// request handlers

type Image struct {
	Name string `db:"name"`
	Data []byte `db:"data"`
}

type ChannelInfo struct {
	ID           int       `db:"id"`
	Name         string    `db:"name"`
	Description  string    `db:"description"`
	UpdatedAt    time.Time `db:"updated_at"`
	CreatedAt    time.Time `db:"created_at"`
	MessageCount int
}

var (
	channelList []ChannelInfo
	channelMap  map[int]*ChannelInfo
	userList    []User
	userMap     map[int64]*User
	userNameMap map[string]*User
)

func getInitialize(c echo.Context) error {
	db.MustExec("DELETE FROM user WHERE id > 1000")
	db.MustExec("DELETE FROM image WHERE id > 1001")
	db.MustExec("DELETE FROM channel WHERE id > 10")
	db.MustExec("DELETE FROM message WHERE id > 10000")
	// db.MustExec("DELETE FROM haveread")
	db.MustExec("DELETE FROM haveread_count")

	var images []Image
	err := db.Select(&images, "SELECT name, data FROM image")
	if err != nil {
		fmt.Println(err)
		return ErrBadReqeust
	}
	for i := 0; i < len(images); i++ {
		file, err := os.Create(images[i].Name)
		if err != nil {
			fmt.Println(err)
			return err
		}
		defer file.Close()
		_, err = file.Write(images[i].Data)
		if err != nil {
			fmt.Println(err)
			return err
		}
	}

	channelList = make([]ChannelInfo, 0, 1000)
	err = db.Select(&channelList, "SELECT * FROM channel ORDER BY id")
	if err != nil {
		fmt.Println(err)
		return ErrBadReqeust
	}

	channelMap = make(map[int]*ChannelInfo, 1000)
	for i := len(channelList) - 1; i >= 0; i-- {
		var cnt int
		err = db.Get(&cnt,
			"SELECT COUNT(*) as cnt FROM message WHERE channel_id = ?", channelList[i].ID)
		if err != nil {
			fmt.Println(err)
			return err
		}
		channelList[i].MessageCount = cnt
		channelMap[channelList[i].ID] = &channelList[i]
	}

	userList = make([]User, 0, 5000)
	err = db.Select(&userList, "SELECT * FROM user ORDER BY id")
	if err != nil {
		fmt.Println(err)
		return ErrBadReqeust
	}

	userMap = make(map[int64]*User, 5000)
	userNameMap = make(map[string]*User, 5000)
	for i := 0; i < len(userList); i++ {
		userMap[userList[i].ID] = &userList[i]
		userNameMap[userList[i].Name] = &userList[i]
	}

	return c.String(204, "")
}

func getIndex(c echo.Context) error {
	userID := sessUserID(c)
	if userID != 0 {
		return c.Redirect(http.StatusSeeOther, "/channel/1")
	}

	return c.Render(http.StatusOK, "index", map[string]interface{}{
		"ChannelID": nil,
	})
}

func getChannel(c echo.Context) error {
	user, err := ensureLogin(c)
	if user == nil {
		return err
	}
	cID, err := strconv.Atoi(c.Param("channel_id"))
	if err != nil {
		return err
	}

	var desc string
	for _, ch := range channelList {
		if ch.ID == cID {
			desc = ch.Description
			break
		}
	}
	return c.Render(http.StatusOK, "channel", map[string]interface{}{
		"ChannelID":   cID,
		"Channels":    channelList,
		"User":        user,
		"Description": desc,
	})
}

func getRegister(c echo.Context) error {
	return c.Render(http.StatusOK, "register", map[string]interface{}{
		"ChannelID": 0,
		"Channels":  []ChannelInfo{},
		"User":      nil,
	})
}

func postRegister(c echo.Context) error {
	name := c.FormValue("name")
	pw := c.FormValue("password")
	if name == "" || pw == "" {
		return ErrBadReqeust
	}
	userID, err := register(name, pw)
	if err != nil {
		if err == ErrDuplicate {
			return c.NoContent(http.StatusConflict)
		}
		if merr, ok := err.(*mysql.MySQLError); ok {
			if merr.Number == 1062 { // Duplicate entry xxxx for key zzzz
				return c.NoContent(http.StatusConflict)
			}
		}
		return err
	}
	sessSetUserID(c, userID)
	return c.Redirect(http.StatusSeeOther, "/")
}

func getLogin(c echo.Context) error {
	return c.Render(http.StatusOK, "login", map[string]interface{}{
		"ChannelID": 0,
		"Channels":  []ChannelInfo{},
		"User":      nil,
	})
}

func postLogin(c echo.Context) error {
	name := c.FormValue("name")
	pw := c.FormValue("password")
	if name == "" || pw == "" {
		return ErrBadReqeust
	}

	// var user User
	// err := db.Get(&user, "SELECT id, salt, password FROM user WHERE name = ?", name)
	// fmt.Println("SELECT * FROM user WHERE name = %s", name)
	user := userNameMap[name]
	// if err == sql.ErrNoRows {
	// 	return echo.ErrForbidden
	// } else if err != nil {
	// 	return err
	// }
	if user == nil {
		return echo.ErrForbidden
	}

	digest := fmt.Sprintf("%x", sha1.Sum([]byte(user.Salt+pw)))
	if digest != user.Password {
		return echo.ErrForbidden
	}
	sessSetUserID(c, user.ID)
	return c.Redirect(http.StatusSeeOther, "/")
}

func getLogout(c echo.Context) error {
	r := c.Request()
	w := c.Response().Writer
	deleteSession(r, w)
	// sess, _ := session.Get("session", c)
	// delete(sess.Values, "user_id")
	// sess.Save(c.Request(), c.Response())
	return c.Redirect(http.StatusSeeOther, "/")
}

func postMessage(c echo.Context) error {
	user, err := ensureLogin(c)
	if user == nil {
		return err
	}

	message := c.FormValue("message")
	if message == "" {
		return echo.ErrForbidden
	}

	var chanID int64
	if x, err := strconv.Atoi(c.FormValue("channel_id")); err != nil {
		return echo.ErrForbidden
	} else {
		chanID = int64(x)
	}

	if _, err := addMessage(chanID, user.ID, message); err != nil {
		return err
	}

	return c.NoContent(204)
}

// メッセージ（複数形）をJSONにする
func jsonifyMessage(m []Message) ([]map[string]interface{}, error) {
	if len(m) == 0 {
		return make([]map[string]interface{}, 0, 0), nil
	}

	messages := map[int64]Message{}
	for i := range m {
		messages[m[i].UserID] = m[i]
	}

	// メッセージの投稿者を抽出してその情報をmapにする
	userIDs := make([]int64, 0, len(m))
	for id := range messages {
		userIDs = append(userIDs, id)
	}
	// query, args, err := sqlx.In("SELECT id, name, display_name, avatar_icon FROM user WHERE id IN (?) ORDER BY id DESC", userIDs)
	// if err != nil {
	// 	return nil, err
	// }
	// users := []User{}
	// err = db.Select(&users, query, args...)
	// if err != nil {
	// 	return nil, err
	// }
	// usersMap := map[int64]User{}
	// for i := range users {
	// 	usersMap[users[i].ID] = users[i]
	// }

	// JSON生成
	rs := make([]map[string]interface{}, 0, len(userList))
	for i := len(m) - 1; i >= 0; i-- {
		r := make(map[string]interface{})
		r["id"] = m[i].ID
		r["user"] = userMap[m[i].UserID]
		r["date"] = m[i].CreatedAt.Format("2006/01/02 15:04:05")
		r["content"] = m[i].Content
		rs = append(rs, r)
	}
	return rs, nil
}

func getMessage(c echo.Context) error {
	userID := sessUserID(c)
	if userID == 0 {
		return c.NoContent(http.StatusForbidden)
	}

	chanID, err := strconv.ParseInt(c.QueryParam("channel_id"), 10, 64)
	if err != nil {
		return err
	}
	lastID, err := strconv.ParseInt(c.QueryParam("last_message_id"), 10, 64)
	if err != nil {
		return err
	}

	messages, err := queryMessages(chanID, lastID)
	if err != nil {
		return err
	}

	response, err := jsonifyMessage(messages)
	if err != nil {
		return err
	}

	if len(messages) > 0 {
		// _, err = db.Exec("INSERT haveread_count (user_id, channel_id, num) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE num = ?", userID, chanID, len(messages), len(messages))
		_, err = db.Exec("UPDATE haveread_count SET num = ? WHERE user_id = ? AND channel_id = ?", len(messages), userID, chanID)
		if err != nil {
			return err
		}
	}

	return c.JSON(http.StatusOK, response)
}

type havereadInfo struct {
	Channel int64 `db:"channel_id"`
	Num     int   `db:"num"`
}

func queryHaveRead(userID int64) ([]havereadInfo, error) {
	IDs := []havereadInfo{}

	err := db.Select(&IDs, "SELECT channel_id, num FROM haveread_count WHERE user_id = ?", userID)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return IDs, nil
}

// あるユーザーについて全てのチャンネルで未読のカウントを返す
func fetchUnread(c echo.Context) error {
	fmt.Println("fetch")
	userID := sessUserID(c)
	if userID == 0 {
		return c.NoContent(http.StatusForbidden)
	}

	fmt.Println("userID kan")
	// TODO 非同期かなにかするかもしれない
	time.Sleep(500 * time.Millisecond)

	fmt.Println("sleep kan")
	IDs, err := queryHaveRead(userID)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("query Have read kan", IDs)

	resp := []map[string]interface{}{}
	for i := range IDs {
		fmt.Println(IDs[i].Channel)
		c := channelMap[int(IDs[i].Channel)]
		fmt.Println(c)
		_, err = db.Exec("UPDATE haveread_count SET num = ? WHERE user_id = ? AND channel_id = ?", c.MessageCount, userID, IDs[i].Channel)
		if err != nil {
			fmt.Println(err)
			return err
		}
		fmt.Println("loop", userID)
		r := map[string]interface{}{
			"channel_id": IDs[i].Channel,
			"unread":     c.MessageCount - IDs[i].Num}
		resp = append(resp, r)
	}

	return c.JSON(http.StatusOK, resp)
}

func getHistory(c echo.Context) error {
	chID, err := strconv.ParseInt(c.Param("channel_id"), 10, 64)
	if err != nil || chID <= 0 {
		return ErrBadReqeust
	}

	user, err := ensureLogin(c)
	if user == nil {
		return err
	}

	var page int64
	pageStr := c.QueryParam("page")
	if pageStr == "" {
		page = 1
	} else {
		page, err = strconv.ParseInt(pageStr, 10, 64)
		if err != nil || page < 1 {
			return ErrBadReqeust
		}
	}

	const N = 20
	cnt := channelMap[int(chID)].MessageCount
	//err = db.Get(&cnt, "SELECT COUNT(*) as cnt FROM message WHERE channel_id = ?", chID)
	// if err != nil {
	// 	return err
	// }
	maxPage := int64(cnt+N-1) / N
	if maxPage == 0 {
		maxPage = 1
	}
	if page > maxPage {
		return ErrBadReqeust
	}

	messages := []Message{}
	err = db.Select(&messages,
		"SELECT * FROM message WHERE channel_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
		chID, N, (page-1)*N)
	if err != nil {
		return err
	}

	mjson, err := jsonifyMessage(messages)
	if err != nil {
		return err
	}

	return c.Render(http.StatusOK, "history", map[string]interface{}{
		"ChannelID": chID,
		"Channels":  channelList,
		"Messages":  mjson,
		"MaxPage":   maxPage,
		"Page":      page,
		"User":      user,
	})
}

func getProfile(c echo.Context) error {
	self, err := ensureLogin(c)
	if self == nil {
		return err
	}

	userName := c.Param("user_name")
	// var other User
	// err = db.Get(&other, "SELECT * FROM user WHERE name = ?", userName)
	// if err == sql.ErrNoRows {
	// 	return echo.ErrNotFound
	// }
	// if err != nil {
	// 	return err
	// }
	other := userNameMap[userName]
	if other == nil {
		return ErrNotFound
	}

	return c.Render(http.StatusOK, "profile", map[string]interface{}{
		"ChannelID":   0,
		"Channels":    channelList,
		"User":        self,
		"Other":       other,
		"SelfProfile": self.ID == other.ID,
	})
}

func getAddChannel(c echo.Context) error {
	self, err := ensureLogin(c)
	if self == nil {
		return err
	}

	return c.Render(http.StatusOK, "add_channel", map[string]interface{}{
		"ChannelID": 0,
		"Channels":  channelList,
		"User":      self,
	})
}

func postAddChannel(c echo.Context) error {
	self, err := ensureLogin(c)
	if self == nil {
		return err
	}

	name := c.FormValue("name")
	desc := c.FormValue("description")
	if name == "" || desc == "" {
		return ErrBadReqeust
	}

	channelList = append(channelList, ChannelInfo{len(channelList) + 1, name, desc, time.Now(), time.Now(), 0})
	channelMap[len(channelList)] = &channelList[len(channelList)-1]
	return c.Redirect(http.StatusSeeOther,
		fmt.Sprintf("/channel/%v", len(channelList)))
}

func postProfile(c echo.Context) error {
	self, err := ensureLogin(c)
	if self == nil {
		return err
	}

	avatarName := ""
	var avatarData []byte

	if fh, err := c.FormFile("avatar_icon"); err == http.ErrMissingFile {
		// no file upload
	} else if err != nil {
		return err
	} else {
		dotPos := strings.LastIndexByte(fh.Filename, '.')
		if dotPos < 0 {
			return ErrBadReqeust
		}
		ext := fh.Filename[dotPos:]
		switch ext {
		case ".jpg", ".jpeg", ".png", ".gif":
			break
		default:
			return ErrBadReqeust
		}

		file, err := fh.Open()
		if err != nil {
			return err
		}
		avatarData, _ = ioutil.ReadAll(file)
		file.Close()

		if len(avatarData) > avatarMaxBytes {
			return ErrBadReqeust
		}

		avatarName = fmt.Sprintf("%x%s", sha1.Sum(avatarData), ext)
	}

	if avatarName != "" && len(avatarData) > 0 {
		file, err := os.Create(avatarName)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = file.Write(avatarData)
		if err != nil {
			return err
		}

		// _, err := db.Exec("INSERT INTO image (name, data) VALUES (?, ?)", avatarName, avatarData)
		// if err != nil {
		// 	return err
		// }
		// _, err = db.Exec("UPDATE user SET avatar_icon = ? WHERE id = ?", avatarName, self.ID)
		userMap[self.ID].AvatarIcon = avatarName
		if err != nil {
			return err
		}
	}

	if name := c.FormValue("display_name"); name != "" {
		// _, err := db.Exec("UPDATE user SET display_name = ? WHERE id = ?", name, self.ID)
		userMap[self.ID].DisplayName = name
		if err != nil {
			return err
		}
	}

	return c.Redirect(http.StatusSeeOther, "/")
}

func getIcon(c echo.Context) error {
	name := c.Param("file_name")
	var data []byte

	f, err := os.Open(name)
	if err != nil {
		return echo.ErrNotFound
	}
	defer f.Close()
	data, err = ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	mime := ""
	switch true {
	case strings.HasSuffix(name, ".jpg"), strings.HasSuffix(name, ".jpeg"):
		mime = "image/jpeg"
	case strings.HasSuffix(name, ".png"):
		mime = "image/png"
	case strings.HasSuffix(name, ".gif"):
		mime = "image/gif"
	default:
		return echo.ErrNotFound
	}
	return c.Blob(http.StatusOK, mime, data)
}

func tAdd(a, b int64) int64 {
	return a + b
}

func tRange(a, b int64) []int64 {
	r := make([]int64, b-a+1)
	for i := int64(0); i <= (b - a); i++ {
		r[i] = a + i
	}
	return r
}

func main() {
	e := echo.New()
	funcs := template.FuncMap{
		"add":    tAdd,
		"xrange": tRange,
	}
	e.Renderer = &Renderer{
		templates: template.Must(template.New("").Funcs(funcs).ParseGlob("views/*.html")),
	}
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secretonymoris"))))
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "request:\"${method} ${uri}\" status:${status} latency:${latency} (${latency_human}) bytes:${bytes_out}\n",
	}))
	e.Use(middleware.Static("../public"))

	e.GET("/initialize", getInitialize)
	e.GET("/", getIndex)
	e.GET("/register", getRegister)
	e.POST("/register", postRegister)
	e.GET("/login", getLogin)
	e.POST("/login", postLogin)
	e.GET("/logout", getLogout)

	e.GET("/channel/:channel_id", getChannel)
	e.GET("/message", getMessage)
	e.POST("/message", postMessage)
	e.GET("/fetch", fetchUnread)
	e.GET("/history/:channel_id", getHistory)

	e.GET("/profile/:user_name", getProfile)
	e.POST("/profile", postProfile)

	e.GET("add_channel", getAddChannel)
	e.POST("add_channel", postAddChannel)
	e.GET("/icons/:file_name", getIcon)

	e.Start(":5000")
}
