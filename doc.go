// Copyright 2017 Bo-Yi Wu.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

/*
Support Let's Encrypt for a Go server application.

example for 1-line LetsEncrypt HTTPS servers.

	package main

	import (
		"log"

		"github.com/gin-gonic/autotls"
		"github.com/gin-gonic/gin"
	)

	func main() {
		r := gin.Default()

		// Ping handler
		r.GET("/ping", func(c *gin.Context) {
			c.String(200, "pong")
		})

		log.Fatal(autotls.Run(r, "example1.com", "example2.com"))
	}

*/

package autotls
