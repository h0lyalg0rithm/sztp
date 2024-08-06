/*
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2022-2023 Intel Corporation
Copyright (c) 2022 Dell Inc, or its subsidiaries.
Copyright (C) 2022 Red Hat.
*/

// Package secureagent implements the secure agent
package secureagent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func (a *Agent) doTLSRequest(input string, url string, empty bool) (*BootstrapServerPostOutput, error) {
	var postResponse BootstrapServerPostOutput
	var errorResponse BootstrapServerErrorOutput

	log.Println("[DEBUG] Sending to: " + url)
	log.Println("[DEBUG] Sending input: " + input)

	body := strings.NewReader(input)
	r, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}

	r.SetBasicAuth(a.GetSerialNumber(), a.GetDevicePassword())
	r.Header.Add("Content-Type", a.GetContentTypeReq())

	caCert, _ := os.ReadFile(a.GetBootstrapTrustAnchorCert())
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	cert, _ := tls.LoadX509KeyPair(a.GetDeviceEndEntityCert(), a.GetDevicePrivateKey())

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ //nolint:gosec
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}
	res, err := client.Do(r)
	if err != nil {
		log.Println("Error doing the request", err.Error())
		return nil, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			log.Println("Error when closing:", err)
		}
	}()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Println("Error reading the request", err.Error())
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
	decoder.DisallowUnknownFields()
	if !empty {
		derr := decoder.Decode(&postResponse)
		if derr != nil {
			errdecoder := json.NewDecoder(bytes.NewReader(bodyBytes))
			errdecoder.DisallowUnknownFields()
			eerr := errdecoder.Decode(&errorResponse)
			if eerr != nil {
				log.Println("Received unknown response", string(bodyBytes))
				return nil, derr
			}
			return nil, errors.New("[ERROR] Expected conveyed-information" +
				", received error type=" + errorResponse.IetfRestconfErrors.Error[0].ErrorType +
				", tag=" + errorResponse.IetfRestconfErrors.Error[0].ErrorTag +
				", message=" + errorResponse.IetfRestconfErrors.Error[0].ErrorMessage)
		}
		log.Println(postResponse)
	}
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("[ERROR] Status code received: " + strconv.Itoa(res.StatusCode) + " ...but status code expected: " + strconv.Itoa(http.StatusOK))
	}
	return &postResponse, nil
}

func (a *Agent) downloadImage(uri string, file *os.File) error {
	caCert, _ := os.ReadFile(a.GetBootstrapTrustAnchorCert())
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	cert, _ := tls.LoadX509KeyPair(a.GetDeviceEndEntityCert(), a.GetDevicePrivateKey())

	check := http.Client{
		CheckRedirect: func(r *http.Request, _ []*http.Request) error {
			r.URL.Opaque = r.URL.Path
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				//nolint:gosec
				InsecureSkipVerify: true, // TODO: remove skip verify
				RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{cert},
			},
		},
	}

	response, err := check.Get(uri)
	if err != nil {
		return err
	}

	sizeorigin, _ := strconv.Atoi(response.Header.Get("Content-Length"))
	downloadSize := int64(sizeorigin)
	log.Printf("[INFO] Downloading the image with size: %v", downloadSize)

	if response.StatusCode != 200 {
		return errors.New("received non 200 response code")
	}
	_, err = io.Copy(file, response.Body)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Println("[ERROR] Error when closing:", err)
		}
	}()
	defer func() {
		if err := response.Body.Close(); err != nil {
			log.Println("[ERROR] Error when closing:", err)
		}
	}()
	return nil
}
