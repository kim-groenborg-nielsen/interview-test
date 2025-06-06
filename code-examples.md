# Identify code language
## 1st code snippet
```yaml
---

- name: Ensure nginx is installed
  become: yes
  apt:
    name: nginx
    state: latest
  tags: nginx

- name: Ensure that {{ nginx_ssl_dhparam | dirname }} exists
  become: yes
  file:
    state: directory
    path: "{{ nginx_ssl_dhparam | dirname }}"
    owner: root
    group: root
    mode: "0640"
  tags: nginx

- name: Check if dhparam exists
  become: yes
  stat:
    path: "{{ nginx_ssl_dhparam }}"
  register: ssl_dhparam

- name: Generate {{ nginx_ssl_dhparam }}
  become: yes
  command: "openssl dhparam -out {{ nginx_ssl_dhparam }} 4096"
  when: "ssl_dhparam.stat.exists == false"
  tags: nginx
  notify: Restart nginx

- name: Install log conf files
  become: yes
  template:
    src: "log.conf.j2"
    dest: "{{ nginx_conf_base }}/conf.d/log.conf"
    owner: root
    group: root
    mode: "0644"
    backup: yes
  notify: Restart nginx

- name: Install ssl conf files
  become: yes
  template:
    src: "ssl.conf.j2"
    dest: "{{ nginx_conf_base }}/conf.d/ssl.conf"
    owner: root
    group: root
    mode: "0644"
    backup: yes
  notify: Restart nginx

- name: Install max-body conf files
  become: yes
  template:
    src: "max-body.conf.j2"
    dest: "{{ nginx_conf_base }}/conf.d/max-body.conf"
    owner: root
    group: root
    mode: "0644"
    backup: yes
  notify: Restart nginx

- name: Install content-security-policy conf files
  become: yes
  template:
    src: "content-security-policy.conf.j2"
    dest: "{{ nginx_conf_base }}/conf.d/content-security-policy.conf"
    owner: root
    group: root
    mode: "0644"
    backup: yes
  notify: Restart nginx
```
Can above be optimized further?

## 2nd code snippet
```go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"strings"
)

type CertToken struct {
	Domain     string `json:"domain"`
	Token      string `json:"token"`
	Validation string `json:"validation"`
}

var version string = ""
var commit string = ""
var date string = ""

// Make map of certificate tokens where the key is the domain
var certTokens = make(map[string]CertToken)

var tokenPostPath = os.Getenv("TOKEN_POST_PATH")
var uploadPath = os.Getenv("UPLOAD_PATH")

const acmeChallengePath = "/.well-known/acme-challenge/"
const MaxTokens = 10000

const MaxUploadFileSize = 1024 * 1014

func main() {
	var showVersion bool

	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.Parse()

	if showVersion {
		fmt.Printf("Version: %s\nCommit:  %s\nDate:    %s\n", version, commit, date)
		os.Exit(0)
	}

	if tokenPostPath == "" {
		tokenPostPath = "/token_poster/"
	}
	if uploadPath == "" {
		ex, err := os.Executable()
		if err != nil {
			log.Fatal(err)
		}
		uploadPath = path.Dir(ex) + "/upload"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "4080"
		log.Printf("Defaulting to port %s", port)
	}

	//http.HandleFunc("/", indexHandler)
	http.HandleFunc(acmeChallengePath, acmeChallengeHandler)
	http.HandleFunc(tokenPostPath, acmeTokenHandler)
	http.HandleFunc(tokenPostPath+"upload", fileUploadHandler)

	log.Printf("Upload file path %s", uploadPath)
	log.Printf("Token post path %s", tokenPostPath)
	log.Printf("Listening on port %s", port)
	log.Printf("Open http://localhost:%s in the browser", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("localhost:%s", port), nil))
}

func getIp(r *http.Request) string {
	fwd := r.Header.Get("X-FORWARDED-FOR")
	if fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}

func acmeChallengeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		ip := getIp(r)
		log.Printf("Request token for %s from %s", r.Host, ip)
		if token, ok := certTokens[r.Host]; ok {
			if r.URL.Path == acmeChallengePath+token.Token {
				log.Printf("Return token for %s to %s", r.Host, ip)
				_, err := fmt.Fprintf(w, token.Validation)
				if err != nil {
					http.Error(w, "Internal error", http.StatusInternalServerError)
				}
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func acmeTokenHandler(w http.ResponseWriter, r *http.Request) {
	token := &CertToken{}
	if r.Body == nil {
		http.Error(w, "Bad json request", http.StatusBadRequest)
		return
	}
	if err := json.NewDecoder(r.Body).Decode(token); err != nil {
		http.Error(w, "Bad json request", http.StatusBadRequest)
		return
	}
	ip := getIp(r)
	switch r.Method {
	case http.MethodPost:
		if token.Domain == "" || token.Validation == "" || token.Token == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(certTokens) >= MaxTokens {
			log.Printf("Hits token limitation of %d, someone is proberly doing DoS, maybe from %s", MaxTokens, ip)
			w.WriteHeader(http.StatusInsufficientStorage)
		}
		log.Printf("Set token for %s from %s", token.Domain, ip)
		certTokens[token.Domain] = *token
		return
	case http.MethodDelete:
		log.Printf("Delete token for %s from %s", token.Domain, ip)
		delete(certTokens, token.Domain)
		return
	}
	log.Printf("%s method not allowed from %s", r.Method, ip)
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func writeUploadFile(fileHeader *multipart.FileHeader, domain string) (int, error) {
	if fileHeader.Size > MaxUploadFileSize {
		return http.StatusBadRequest, fmt.Errorf("size of %s is larger than %d", fileHeader.Filename, MaxUploadFileSize)
	}

	file, err := fileHeader.Open()
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("upload: Error opening upload file %s: %v", fileHeader.Filename, err)
	}
	defer func(file multipart.File) {
		err := file.Close()
		if err != nil {
			log.Printf("upload: Error closing %s: %v", fileHeader.Filename, err)
		}
	}(file)

	buffer := make([]byte, 512)
	if _, err := file.Read(buffer); err != nil {
		return http.StatusInternalServerError, err
	}

	fileType := http.DetectContentType(buffer)
	log.Printf("Upload file %s with type %s", fileHeader.Filename, fileType)

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("upload: Cannot seek to start of %s: %v", fileHeader.Filename, err)
	}

	domainUpload := path.Join(uploadPath, domain)
	if err := os.MkdirAll(domainUpload, os.ModePerm); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("upload: Unable to create %s: %v", domainUpload, err)
	}

	fullUploadPath := path.Join(domainUpload, fileHeader.Filename)
	if strings.Contains(fullUploadPath, "..") {
		return http.StatusBadRequest, fmt.Errorf("upload: Invalid upload fullpath: %s", fullUploadPath)
	}

	f, err := os.Create(fullUploadPath)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("upload: Cannot create %s", fullUploadPath)
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			log.Printf("upload: Error closing %s: %v", fullUploadPath, err)
		}
	}(f)

	if _, err := io.Copy(f, file); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("upload: Error writing %s: %v", fullUploadPath, err)
	}
	log.Printf("%s uploaded", fullUploadPath)
	return http.StatusOK, nil
}

func fileUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			http.Error(w, "File upload to big", http.StatusBadRequest)
			return
		}

		domains := r.MultipartForm.Value["domain"]
		if len(domains) != 1 {
			log.Print("Upload: Domain should be given once, and only once")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		domain := domains[0]
		if domain == "" {
			log.Printf("Upload: No domain found in data")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if strings.Contains(domain, "..") || !strings.Contains(domain, ".") || strings.Contains(domain, " ") {
			log.Printf("Upload: Invalid domain: '%s'", domain)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		files := r.MultipartForm.File["file"]
		for _, fileHeader := range files {
			if status, err := writeUploadFile(fileHeader, domain); err != nil {
				log.Printf("%v", err)
				w.WriteHeader(status)
				return
			}
		}
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}
```

## 3rd code snippet
```python
import logging
import os
from datetime import timedelta
from typing import List

from fastapi import FastAPI, HTTPException, Depends, status, Request

from . import __version__
from .auth import Token, authenticate_terminal, create_access_token, get_current_client
from .config import Client
from .navision import Navision
from .oauth2_workaround import OAuth2PasswordRequestFormGrantTypeWorkaround
from .request_writer import RequestWriter
from .schemas import Order, OrderV2, StockItem, StockItemV2

ORDER_NOT_FOUND = 'Order not found'

description = '''
ScannerApp API is a data broker between Navision and the handheld scanners

It translate Code Page 850 encoding used by Navision and UTF-8 used by the JSON API.
'''

tags_metadata = [
    dict(name='orders'),
    dict(name='stock'),
    dict(name='authentication')
]

app = FastAPI(title='ScannerApp', description=description, version=__version__,
              contact=dict(name='Kim G. Nielsen', email='kgn@network-it.dk'))

logger = logging.getLogger(__name__)
navi = Navision()
request_writer = RequestWriter()


@app.get('/orders/', response_model=List[Order], tags=['orders', 'v1'])
async def list_orders(request: Request, current_client: Client = Depends(get_current_client)):
    """
    Collect and read order files and return the data to the client
    :param request:
    :param current_client:
    :return:
    """

    orders = await navi.async_read_pick_lists()
    logger.info('%s:%d - Return orders=%s to client=%s', request.client.host, request.client.port,
                ','.join([str(x) for x in sorted(orders)]),
                current_client.id)
    return [v for _, v in sorted(orders.items())]


@app.get('/v2/orders/', response_model=List[OrderV2], tags=['orders', 'v2'])
async def list_orders_v2(request: Request, current_client: Client = Depends(get_current_client)):
    """
    Collect and read order files and return the data to the client
    :param request:
    :param current_client:
    :return:
    """

    orders, _ = await navi.async_read_pick_lists_v2()
    logger.info('%s:%d - Return orders=%s to client=%s', request.client.host, request.client.port,
                ','.join([str(x) for x in sorted(orders)]),
                current_client.id)
    return [v for _, v in sorted(orders.items())]


@app.get('/orders/{order_no}', response_model=Order, tags=['orders', 'v1'])
async def get_order(order_no: int, request: Request, current_client: Client = Depends(get_current_client)):
    """
    Read order file and return data to the client
    :param order_no:
    :param request:
    :param current_client:
    :return:
    """
    orders = await navi.async_read_pick_lists()
    if order_no not in orders:
        raise HTTPException(status_code=404, detail=ORDER_NOT_FOUND)
    logger.info('%s:%d - Return order=%d to client=%s', request.client.host, request.client.port,
                order_no, current_client.id)
    return orders[order_no]


@app.get('/v2/orders/{order_no}', response_model=OrderV2, tags=['orders', 'v2'])
async def get_order_v2(order_no: int, request: Request, current_client: Client = Depends(get_current_client)):
    """
    Read order file and return data to the client
    :param order_no:
    :param request:
    :param current_client:
    :return:
    """
    orders, _ = await navi.async_read_pick_lists_v2()
    if order_no not in orders:
        raise HTTPException(status_code=404, detail=ORDER_NOT_FOUND)
    logger.info('%s:%d - Return order=%d to client=%s', request.client.host, request.client.port,
                order_no, current_client.id)
    return orders[order_no]


@app.put('/orders/{order_no}', response_model=Order, tags=['orders', 'v1'])
async def put_order(order_no: int, order: Order, request: Request,
                    current_client: Client = Depends(get_current_client)):
    """
    Put order data from client into a file if the original order file exists
    :param order_no:
    :param order:
    :param request:
    :param current_client:
    :return:
    """
    orders = await navi.async_read_pick_lists()
    if order_no not in orders:
        raise HTTPException(status_code=404, detail=ORDER_NOT_FOUND)
    logger.info('%s:%d - Write order=%d from client=%s', request.client.host, request.client.port,
                order_no, current_client.id)
    orders[order_no] = order
    await navi.async_write_order_file(order)
    await request_writer.write_json(request, 'order-{order_no}_from_scanner', order_no=order_no)
    return order


@app.put('/v2/orders/{order_no}', response_model=OrderV2, tags=['orders', 'v2'])
async def put_order_v2(order_no: int, order: OrderV2, request: Request,
                       current_client: Client = Depends(get_current_client)):
    """
    Put order data from client into a file if the original order file exists
    :param order_no:
    :param order:
    :param request:
    :param current_client:
    :return:
    """
    orders, order_files = await navi.async_read_pick_lists_v2()
    if order_no not in orders:
        raise HTTPException(status_code=404, detail=ORDER_NOT_FOUND)
    logger.info('%s:%d - Write order=%d from client=%s', request.client.host, request.client.port,
                order_no, current_client.id)
    orders[order_no] = order
    await navi.async_write_order_file_v2(order)
    await request_writer.write_json(request, 'v2_order-{order_no}_from_scanner', order_no=order_no)
    try:
        os.remove(order_files[order_no])
    except FileNotFoundError:
        pass
    return order


@app.post('/stockitems/', response_model=List[StockItem], tags=['stock', 'v1'])
async def post_stock_items(stock_items: List[StockItem], request: Request,
                           current_client: Client = Depends(get_current_client)):
    """
    Put stock item data from client into a file
    :param stock_items:
    :param request:
    :param current_client:
    :return:
    """
    logger.info('%s:%d - Write stock items from client=%s', request.client.host, request.client.port,
                current_client.id)
    if len(stock_items) > 0:
        await navi.async_write_stock_file(stock_items)
        await request_writer.write_json(request, 'stock_items_from_scanner')
    return stock_items


@app.post('/v2/stockitems/', response_model=List[StockItemV2], tags=['stock', 'v2'])
async def post_stock_items_v2(stock_items: List[StockItemV2], request: Request,
                              current_client: Client = Depends(get_current_client)):
    """
    Put stock item data from client into a file
    :param stock_items:
    :param request:
    :param current_client:
    :return:
    """
    logger.info('%s:%d - Write stock items from client=%s', request.client.host, request.client.port,
                current_client.id)
    if len(stock_items) > 0:
        await navi.async_write_stock_file_v2(stock_items)
        await request_writer.write_json(request, 'v2_stock_items_from_scanner')
    return stock_items


@app.post('/token', response_model=Token, tags=['authentication'])
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestFormGrantTypeWorkaround = Depends()):
    """
    Authenticate client and return token
    :param request:
    :param form_data:
    :return:
    """
    terminal = authenticate_terminal(navi.config.clients, form_data.username, form_data.password)
    if not terminal:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Invalid username or password',
                            headers={"WWW-Authenticate": "Bearer"})
    logger.info('%s:%d - Valid token to client=%s', request.client.host, request.client.port,
                terminal.id)
    token_expires = timedelta(minutes=navi.config.env.token_expire_minutes)
    access_token = create_access_token(data=dict(sub=terminal.id), expires_delta=token_expires)
    return Token(access_token=access_token, token_type='bearer')


@app.get('/me', response_model=Client, tags=['authentication'])
async def read_client_me(current_client: Client = Depends(get_current_client)):
    """
    Return client info from authentication token
    :param current_client:
    :return:
    """
    return current_client
```

## 4th code snippet
```terraform
terraform {
  required_providers {
    aws = {
      source            = "hashicorp/aws"
      version           = "~> 5.97.0"
    }
  }
  backend "s3" {
        bucket          = "example-state-bucket"
        encrypt         = true
        use_lockfile    = true
  }
}

provider "aws" {
    region      = var.region
}

data "aws_vpc" "default" {
  tags                =   {
      "ManagedBy"         = "example_team"
      "DeploymentMethod"  = "Terraform"
  }
}

variable "region" {
  type                  = string
  description           = "(required) The AWS region to use"
}

variable "environment" {
  type                  = string
  description           = "(required) The environment to use"
}

variable "tags" {
  type                  = map(string)
  description           = "(optional) A map containing tags to assign to all resources"
}

resource "aws_security_group" "example_security_group" {
  name                  = format("%s-security-group", "example_app")
  description           = "Example security group"
  vpc_id                = data.aws_vpc.default.id
  tags                  = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "allow_ssh_communication" {
  count                 = var.environment != "PROD" ? 1 : 0
  from_port             = 22
  to_port               = 22
  ip_protocol           = "tcp"
  cidr_ipv4             = data.aws_vpc.default.cidr_block
  description           = "Allow SSH access to example nodes"

  security_group_id     = aws_security_group.example_security_group.id
}
```

### 5th code snippet
```html
<body class="bg-gray-100 p-6 min-h-screen flex flex-col">
<div id="main-container" class="w-full max-w-6xl mx-auto bg-white p-6 rounded-lg shadow-md flex flex-col">
    <h1 class="text-2xl font-bold mb-4">GitLab to GitHub migration</h1>
    <div class="mb-4">
        <label for="token" class="block text-gray-700">GitLab Private Token:</label>
        <input type="password" id="token" class="w-full p-2 border border-gray-300 rounded mt-1">
    </div>
    <div class="mb-4">
        <label for="url" class="block text-gray-700">GitLab Project URL:</label>
        <input type="text" id="url" class="w-full p-2 border border-gray-300 rounded mt-1">
    </div>
    <div class="mb-4">
        <label for="lock_source" class="inline-flex items-center">
            <input type="checkbox" id="lock_source" class="form-checkbox">
            <span class="ml-2 text-gray-700">Lock Source</span>
        </label>
    </div>
    <button onclick="submitJob()" class="w-full bg-blue-500 text-white p-2 rounded">Submit</button>
    <div class="text-gray-700 mt-4">
        <div class="flex justify-between items-center">
            <span>Status:</span>
            <span id="spinner-container" class="flex items-center gap-2 hidden">
                <span class="heart flex items-center justify-center w-4 h-4" id="heart">
                    <svg viewBox="0 0 32 29.6" class="w-4 h-4">
                        <path d="M23.6,0c-2.7,0-5.1,1.3-6.6,3.3C15.5,1.3,13.1,0,10.4,0C4.7,0,0,4.7,0,10.4
                    c0,6.1,5.4,11.1,13.6,18.3l2.4,2.1l2.4-2.1C26.6,21.5,32,16.5,32,10.4C32,4.7,27.3,0,23.6,0z"
                      fill="#e25555"/>
                    </svg>
                </span>
                <span class="align-middle">Receiving logs...</span>
            </span>
        </div>
    </div>
    <div id="status" class="overflow-y-auto border border-gray-300 p-2 mt-2 rounded bg-gray-50 font-mono h-[calc(100vh-445px)]">
    </div>
</div>
```