package controllers

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"github.com/h4h-2019-fairness/store/app"
	"github.com/revel/revel"
)

type Content struct {
	*revel.Controller
}

func (c Content) Abort() []*revel.ValidationError {
	c.Validation.Keep()
	c.FlashParams()
	c.Response.Status = 500
	return c.Validation.Errors
}

type GetContentUsersResp struct {
	Id string `json:"id"`
	Fullname string `json:"fullname"`
}

func (c Content) Get() revel.Result {
	hash := c.Params.Route.Get("hash")
	c.Validation.Required(hash).Message("hash is required")

	if c.Validation.HasErrors() {
		c.Validation.Error("invalid query parameter")
		errors := c.Abort()
		return c.Render(errors)
	}

	stmt, err := app.DB.Prepare("SELECT id, fullname from (select u.id as id, u.fullname as fullname, c.content_hash as content_hash from users as u join content as c where u.id = c.user_id ) where content_hash = ?")
	if err != nil {
		c.Validation.Error("error in query content statement: %s", err)
		errors := c.Abort()
		return c.Render(errors)
	}

	res, err := stmt.Query(hash)
	if err != nil {
		c.Validation.Error("error querying content: %s", err)
		errors := c.Abort()
		return c.Render(errors)
	}

	results := make([]GetContentUsersResp, 0)

	for res.Next() {
		var id string
		var fullname string
		err := res.Scan(&id, &fullname)
		if err != nil {
			c.Validation.Error("error getting user data: %s", err)
			errors := c.Abort()
			return c.Render(errors)
		}
		results = append(results, GetContentUsersResp{Id: id, Fullname: fullname})
	}

	return c.RenderJSON(results)
}

type CreateContentReq struct {
	UserId string `json:"user_id"`
	ContentHash string `json:"content_hash"`
	Signature string `json:"signature"`
}

func (c Content) Create() revel.Result {
	var req CreateContentReq
	err := c.Params.BindJSON(&req)
	c.Validation.Required(req.UserId).Message("user_id is required")
	c.Validation.Required(req.ContentHash).Message("content_hash is required")
	c.Validation.Required(req.Signature).Message("signature is required")

	if err != nil || c.Validation.HasErrors() {
		c.Validation.Error("invalid json body")
		errors := c.Abort()
		return c.Render(errors)
	}

	stmt, err := app.DB.Prepare("SELECT public_key from users where id = ?")
	if err != nil {
		c.Validation.Error("error in query user statement: %s", err)
		errors := c.Abort()
		return c.Render(errors)
	}

	res, err := stmt.Query(req.UserId)
	if err != nil {
		c.Validation.Error("error querying user: %s", err)
		errors := c.Abort()
		return c.Render(errors)
	}

	if !res.Next() {
		c.Validation.Error("no user with id %s: %s", req.UserId, err)
		errors := c.Abort()
		return c.Render(errors)
	}

	var pubkey_string string
	err = res.Scan(&pubkey_string)
	if err != nil {
		c.Validation.Error("error scanning public key: %s", err)
		errors := c.Abort()
		return c.Render(errors)
	}

	err = res.Close()
	if err != nil {
		c.Validation.Error("error closing db connection: %s", err)
		errors := c.Abort()
		return c.Render(errors)
	}

	pubkey_dec, err := base64.StdEncoding.DecodeString(pubkey_string)
	if err != nil {
		c.Validation.Error("public key is not stored in base64 format: %s", err)
		errors := c.Abort()
		return c.Render(errors)
	}

	block, _ := pem.Decode(pubkey_dec)
	if block == nil {
		c.Validation.Error("invalid pubkey stored, must be pem encoded rsa")
		errors := c.Abort()
		return c.Render(errors)
	}
	if block.Type != "PUBLIC KEY" {
		c.Validation.Error("stored pubkey is not a public key")
		errors := c.Abort()
		return c.Render(errors)
	}

	genericPubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		c.Validation.Error("stored pubkey is not a valid public key")
		errors := c.Abort()
		return c.Render(errors)
	}

	pubkey, ok := genericPubKey.(*rsa.PublicKey)
	if !ok {
		c.Validation.Error("stored pubkey is not an RSA key")
		errors := c.Abort()
		return c.Render(errors)
	}

	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		c.Validation.Error("signature is not in base64 format: %s", err)
		errors := c.Abort()
		return c.Render(errors)
	}

	hash := make([]byte, hex.DecodedLen(len([]byte(req.ContentHash))))
	_, err = hex.Decode(hash, []byte(req.ContentHash))
	if err != nil {
		c.Validation.Error("hash is not in hex format: %s", err)
		errors := c.Abort()
		return c.Render(errors)
	}

	err = rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, hash, sig)
	if err != nil {
		c.Validation.Error("signature is not valid for user: %s", err)
		errors := c.Abort()
		return c.Render(errors)
	}

	stmt, err = app.DB.Prepare("INSERT INTO content(user_id, content_hash, signature) VALUES(?, ?, ?)")
	if err != nil {
		c.Validation.Error("error in insert content statement: %s", err)
		errors := c.Abort()
		return c.Render(errors)
	}

	_, err = stmt.Exec(req.UserId, req.ContentHash, req.Signature)
	if err != nil {
		c.Validation.Error("error inserting content: %s", err)
		errors := c.Abort()
		return c.Render(errors)
	}

	return c.Render()
}
