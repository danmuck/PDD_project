package main

import (
	"github.com/danmuck/the_cookie_jar/api"
)

func main() {
	router := api.BaseRouter()
	router.Run(":6669")
}
