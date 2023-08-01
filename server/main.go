package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// gin.SetMode(gin.ReleaseMode)

	// read ca's cert
	caCert, err := ioutil.ReadFile("../cert/ca-cert.pem")
	if err != nil {
		log.Fatal(err)
	}

	// create cert pool and append ca's cert
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.Fatal(err)
	}

	cert, err := tls.LoadX509KeyPair("../cert/server-cert.pem", "../cert/server-key.pem")
	if err != nil {
		log.Fatal(err)
	}
	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
	}
	// tlsConfig.BuildNameToCertificate()

	srv := &http.Server{
		Addr:      ":8080",
		Handler:   setupRouter(),
		TLSConfig: tlsConfig,
	}

	go func() {
		// service connections
		// if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		// 	log.Fatalf("listen: %s\n", err)
		// }
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal)
	// kill (no param) default send syscanll.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall. SIGKILL but can"t be catch, so don't need add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	} else {
		cancel()
	}

	// catching ctx.Done(). timeout of 5 seconds.

	<-ctx.Done()

	log.Println("Server exiting")
}

func setupRouter() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery(), gin.Logger(), cors.Default())
	r.GET("/status", Status)
	return r
}

type Response struct {
	Code    uint   `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func Status(c *gin.Context) {
	// Response
	c.JSON(200, &Response{
		Code:    200,
		Message: "ok",
	})

}
