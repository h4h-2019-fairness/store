package controllers

import (
	"github.com/h4h-2019-fairness/store/app"
	"github.com/revel/revel"
	"time"
)

type App struct {
	*revel.Controller
}

func (a App) Abort() []*revel.ValidationError {
	a.Validation.Keep()
	a.FlashParams()
	a.Response.Status = 500
	return a.Validation.Errors
}

type ContentData struct {
	UserId string
	UserName string
	Hash string
	CreatedAt time.Time
}

func (a App) Index() revel.Result {
	stmt, err := app.DB.Prepare("SELECT u.id as user_id, u.fullname as user_name, c.content_hash as hash, c.created_at as created_at from users as u join content as c where u.id = c.user_id ORDER BY c.created_at DESC LIMIT 30")
	if err != nil {
		a.Validation.Error("error in query content statement: %s", err)
		errors := a.Abort()
		return a.Render(errors)
	}

	res, err := stmt.Query()
	if err != nil {
		a.Validation.Error("error querying content: %s", err)
		errors := a.Abort()
		return a.Render(errors)
	}

	var results []ContentData

	for res.Next() {
		var user_id string
		var user_name string
		var hash string
		var created_at time.Time
		err := res.Scan(&user_id, &user_name, &hash, &created_at)
		if err != nil {
			a.Validation.Error("error getting user data: %s", err)
			errors := a.Abort()
			return a.Render(errors)
		}
		results = append(results, ContentData{UserId: user_id, UserName: user_name, Hash: hash, CreatedAt: created_at})
	}
	return a.Render(results)
}
