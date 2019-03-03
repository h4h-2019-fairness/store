package controllers

import (
	"github.com/revel/revel"
)

type App struct {
	*revel.Controller
}

func (c App) Index() revel.Result {
	greeting := "Store Homepage"
	subtitle := "Probably a demo here or something"
	return c.Render(greeting, subtitle)
}
