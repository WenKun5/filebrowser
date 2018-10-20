package http

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	fb "github.com/WenKun5/filebrowser/lib"
)

const reCaptchaAPI = "/recaptcha/api/siteverify"

type cred struct {
	Password  string `json:"password"`
	Username  string `json:"username"`
	ReCaptcha string `json:"recaptcha"`
}

// reCaptcha checks the reCaptcha code.
func reCaptcha(host, secret, response string) (bool, error) {
	body := url.Values{}
	body.Set("secret", secret)
	body.Add("response", response)

	client := &http.Client{}

	resp, err := client.Post(host+reCaptchaAPI, "application/x-www-form-urlencoded", strings.NewReader(body.Encode()))
	if err != nil {
		return false, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var data struct {
		Success bool `json:"success"`
	}

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return false, err
	}

	return data.Success, nil
}

// authHandler processes the authentication for the user.
func authHandler(c *fb.Context, w http.ResponseWriter, r *http.Request) (int, error) {
	if c.Auth.Method == "none" {
		// NoAuth instances shouldn't call this method.
		return 0, nil
	}

	if c.Auth.Method == "proxy" {
		// Receive the Username from the Header and check if it exists.
		u, err := c.Store.Users.GetByUsername(r.Header.Get(c.Auth.Header), c.NewFS)
		if err != nil {
			return http.StatusForbidden, nil
		}

		c.User = u
		return printToken(c, w)
	}

	// Receive the credentials from the request and unmarshal them.
	var cred cred

	if r.Body == nil {
		return http.StatusForbidden, nil
	}

	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		return http.StatusForbidden, err
	}

	// Wenkun, Validate the token of user from cloud server and return JWT token.
	if c.Auth.Method != "none" {
		ok, u := validateAuthByUserId(c, cred.Username)
		if !ok {
			return http.StatusForbidden, nil
		}

		c.User = u
		return printToken(c, w)
	}

	// If ReCaptcha is enabled, check the code.
	if len(c.ReCaptcha.Secret) > 0 {
		ok, err := reCaptcha(c.ReCaptcha.Host, c.ReCaptcha.Secret, cred.ReCaptcha)
		if err != nil {
			return http.StatusForbidden, err
		}

		if !ok {
			return http.StatusForbidden, nil
		}
	}

	// Checks if the user exists.
	u, err := c.Store.Users.GetByUsername(cred.Username, c.NewFS)
	if err != nil {
		return http.StatusForbidden, nil
	}

	// Checks if the password is correct.
	if !fb.CheckPasswordHash(cred.Password, u.Password) {
		return http.StatusForbidden, nil
	}

	c.User = u
	return printToken(c, w)
}

// renewAuthHandler is used when the front-end already has a JWT token
// and is checking if it is up to date. If so, updates its info.
func renewAuthHandler(c *fb.Context, w http.ResponseWriter, r *http.Request) (int, error) {
	ok, u := validateAuth(c, r)
	if !ok {
		return http.StatusForbidden, nil
	}

	c.User = u
	return printToken(c, w)
}

// claims is the JWT claims.
type claims struct {
	fb.User
	jwt.StandardClaims
}

// printToken prints the final JWT token to the user.
func printToken(c *fb.Context, w http.ResponseWriter) (int, error) {
	// Creates a copy of the user and removes it password
	// hash so it never arrives to the user.
	u := fb.User{}
	u = *c.User
	u.Password = ""

	// Builds the claims.
	claims := claims{
		u,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
			Issuer:    "File Browser",
		},
	}

	// Creates the token and signs it.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(c.Key)

	if err != nil {
		return http.StatusInternalServerError, err
	}

	// Writes the token.
	w.Header().Set("Content-Type", "cty")
	w.Write([]byte(signed))
	return 0, nil
}

type extractor []string

func (e extractor) ExtractToken(r *http.Request) (string, error) {
	token, _ := request.AuthorizationHeaderExtractor.ExtractToken(r)

	// Checks if the token isn't empty and if it contains two dots.
	// The former prevents incompatibility with URLs that previously
	// used basic auth.
	if token != "" && strings.Count(token, ".") == 2 {
		return token, nil
	}

	cookie, err := r.Cookie("auth")
	if err != nil {
		return "", request.ErrNoTokenInRequest
	}

	return cookie.Value, nil
}

type imdosReq struct {
	ReqId  string `json:"req_id"`
	Time   string `json:"time_mills"`
	Nonce  string `json:"nonce"`
	MchId  string `json:"mch_id"`
	Token  string `json:"token"`
	Method string `json:"method"`
	Data   string `json:"data"`
	Sign   string `json:"sign"`
}

type UserId struct {
	UserId string `json:"UserId"`
}

type imdosRsp struct {
	Code string `json:"return_codes"`
	Msg  string `json:"return_msg"`
}

func MD5(text string) string {
	ctx := md5.New()
	ctx.Write([]byte(text))
	return hex.EncodeToString(ctx.Sum(nil))
}

func checkUserId(UserId string) bool {
	cmdstr := "uci get bindInfo.bind.UserId"
	cmd := exec.Command("/bin/sh", "-c", cmdstr)
	userId, err := cmd.Output()
	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	userIdStr := strings.Replace(string(userId), "\n", "", -1)
	if userIdStr != UserId {
		fmt.Printf("userId does not match, %s, %s", userIdStr, UserId)
		return false
	}
	return true
}

func validateAuthByUserId(c *fb.Context, UserId string) (bool, *fb.User) {
	ok := checkUserId(UserId)
	if !ok {
		return false, nil
	}

	// Check UserId
	user, err := c.Store.Users.GetByUsername(UserId, c.NewFS)
	if err == nil {
		return true, user
	}

	// Can not find userId in database, Create an DefaultUser in database
	var u fb.User
	u = fb.DefaultUser
	u.Username = UserId

	// Hashes the password.
	u.Password, err = fb.HashPassword(UserId)
	if err != nil {
		fmt.Println(err.Error())
		return false, nil
	}

	// The first user must be an administrator.
	u.Admin = true
	u.AllowCommands = true
	u.AllowNew = true
	u.AllowEdit = true
	u.AllowPublish = true

	// Saves the user to the database.
	if err := c.Store.Users.Save(&u); err != nil {
		fmt.Println(err.Error())
		return false, nil
	}

	return true, &u
}

// validateAuthFromCloud is use to validate the user authentication
func validateAuthFromCloud(token string) (bool, string) {
	var userId UserId
	var reqData imdosReq
	var strslice []string

	reqId := "NQE1PiLi"
	timeStamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	fmt.Println(timeStamp)
	nonce := "H7SG5XW6"
	mchId := "1"
	method := "CheckToken"

	imdosUrl := "http://app.ccipfs.cn/dake/interface.aspx"

	userId.UserId = "wenkun"
	data, errs := json.Marshal(userId)
	if errs != nil {
		fmt.Println(errs.Error())
	}
	strslice = append(strslice, "/dake/Interface.aspx", token)
	strslice = append(strslice, reqId, timeStamp, nonce, mchId, method)
	strslice = append(strslice, string(data))
	sort.Strings(strslice)

	netStr := strings.Join(strslice, ",")
	fmt.Println(netStr)
	reqData.Data = string(data)
	reqData.Method = method
	reqData.Time = timeStamp
	reqData.ReqId = reqId
	reqData.Nonce = nonce
	reqData.MchId = mchId
	reqData.Token = token
	reqData.Sign = MD5(netStr)

	fmt.Println(reqData)
	request_info, errs := json.Marshal(reqData)
	if errs != nil {
		fmt.Println(errs.Error())
	}

	fmt.Println(string(request_info))
	reqBody := bytes.NewBuffer(request_info)
	resp, err := http.Post(imdosUrl, "json", reqBody)
	if err != nil {
		fmt.Println(err.Error())
	}
	var ret imdosRsp
	err = json.NewDecoder(resp.Body).Decode(&ret)
	if err != nil {
		fmt.Println(err.Error())
	}

	if ret.Code != "200" {

	}
	fmt.Println(ret.Code, ret.Msg)
	return true, "OK"
}

// validateAuth is used to validate the authentication and returns the
// User if it is valid.
func validateAuth(c *fb.Context, r *http.Request) (bool, *fb.User) {
	if c.Auth.Method == "none" {
		c.User = c.DefaultUser
		return true, c.User
	}

	// If proxy auth is used do not verify the JWT token if the header is provided.
	if c.Auth.Method == "proxy" {
		u, err := c.Store.Users.GetByUsername(r.Header.Get(c.Auth.Header), c.NewFS)
		if err != nil {
			return false, nil
		}
		c.User = u
		return true, c.User
	}

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return c.Key, nil
	}

	var claims claims
	token, err := request.ParseFromRequestWithClaims(r,
		extractor{},
		&claims,
		keyFunc,
	)

	if err != nil || !token.Valid {
		return false, nil
	}

	u, err := c.Store.Users.Get(claims.User.ID, c.NewFS)
	if err != nil {
		return false, nil
	}

	c.User = u
	return true, u
}
