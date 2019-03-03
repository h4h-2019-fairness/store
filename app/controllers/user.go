package controllers

import (
	"encoding/base64"
	"encoding/pem"
	"github.com/google/uuid"
	"github.com/h4h-2019-fairness/store/app"
	"github.com/revel/revel"
)

type User struct {
	*revel.Controller
}

type CreateUserReq struct {
	Pubkey string `json:"pubkey"`
	Fullname string `json:"fullname"`
}

type UserRow struct {
	Id string `json:"id"`
	Pubkey string `json:"pubkey"`
	Fullname string `json:"fullname"`
}

func (u User) Abort() []*revel.ValidationError {
	u.Validation.Keep()
	u.FlashParams()
	u.Response.Status = 500
	return u.Validation.Errors
}

func (u User) Create() revel.Result {
	var req CreateUserReq
	err := u.Params.BindJSON(&req)
	u.Validation.Required(req.Pubkey).Message("pubkey is required")
	u.Validation.Required(req.Fullname).Message("fullname is required")

	if err != nil {
		u.Validation.Error("invalid json body")
		errors := u.Abort()
		return u.Render(errors)
	}

	pubkey, err := base64.StdEncoding.DecodeString(req.Pubkey)
	if err != nil {
		u.Validation.Error("public key is not in base64 format: %s", err)
		errors := u.Abort()
		return u.Render(errors)
	}

	block, _ := pem.Decode(pubkey)
	if block == nil {
		u.Validation.Error("invalid pubkey provided, must be pem encoded rsa")
		errors := u.Abort()
		return u.Render(errors)
	}
	if block.Type != "PUBLIC KEY" {
		u.Validation.Error("provided pubkey is not a public key")
		errors := u.Abort()
		return u.Render(errors)
	}

	if u.Validation.HasErrors() {
		errors := u.Abort()
		return u.Render(errors)
	}

	id := uuid.New()

	user := UserRow{
		Id: id.String(),
		Pubkey: req.Pubkey,
		Fullname: req.Fullname,
	}

	stmt, err := app.DB.Prepare("INSERT INTO users(id, public_key, fullname) values(?,?,?)")
	if err != nil {
		u.Validation.Error("error in insert user statement: %s", err)
		errors := u.Abort()
		return u.Render(errors)
	}

	_, err = stmt.Exec(user.Id, user.Pubkey, user.Fullname)
	if err != nil {
		u.Validation.Error("error inserting user: %s", err)
		errors := u.Abort()
		return u.Render(errors)
	}

	return u.RenderJSON(user)
}
