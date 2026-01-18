package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"
)

type IAMEvent struct {
	Source    string                 `json:"source"`
	Category  string                 `json:"category"`
	Action    string                 `json:"action"`
	Actor     string                 `json:"actor"`
	Target    string                 `json:"target"`
	Severity  string                 `json:"severity"`
	Timestamp string                 `json:"timestamp"`
	Raw       map[string]interface{} `json:"raw"`
}

type HECEvent struct {
	Time       int64     `json:"time"`
	Index      string    `json:"index"`
	SourceType string    `json:"sourcetype"`
	Event      IAMEvent  `json:"event"`
}

func getEnvOrFail(key string) string {
	val := os.Getenv(key)
	if val == "" {
		fmt.Printf("Environment variable %s is not set\n", key)
		os.Exit(1)
	}
	return val
}

func buildClient() *http.Client {
	// Skip TLS verification for the lab (self-signed Splunk cert)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // lab-only!
	}
	return &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}
}

func generateFakeIAMEvent() IAMEvent {
	actions := []string{
		"CreateUser",
		"DeleteUser",
		"AttachUserPolicy",
		"DetachUserPolicy",
		"CreateAccessKey",
		"DeleteAccessKey",
		"UpdateLoginProfile",
	}
	actors := []string{
		"admin_user",
		"automation_role",
		"security_engineer",
		"dev_user1",
		"dev_user2",
		"unknown_user",
	}
	targets := []string{
		"new_user123",
		"temporary_contractor",
		"service_account_api",
		"prod_admin",
		"test_user",
	}
	severities := []string{"low", "medium", "high"}

	action := actions[rand.Intn(len(actions))]
	actor := actors[rand.Intn(len(actors))]
	target := targets[rand.Intn(len(targets))]

	// Biased severity similar to the Python script
	sevIndex := rand.Intn(len(severities))
	severity := severities[sevIndex]

	if actor == "unknown_user" || action == "DeleteUser" || action == "CreateAccessKey" {
		severity = "high"
	}

	return IAMEvent{
		Source:    "aws_cloudtrail",
		Category:  "iam",
		Action:    action,
		Actor:     actor,
		Target:    target,
		Severity:  severity,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Raw: map[string]interface{}{
			"example":  "fake_iam_event_go",
			"event_id": rand.Intn(900000) + 100000,
		},
	}
}

func sendEvent(client *http.Client, hecURL, hecToken, index, sourcetype string, event IAMEvent) error {
	payload := HECEvent{
		Time:       time.Now().Unix(),
		Index:      index,
		SourceType: sourcetype,
		Event:      event,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", hecURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Splunk "+hecToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("non-200 from Splunk: %s", resp.Status)
	}

	fmt.Println("Status:", resp.Status)
	return nil
}

func main() {
	rand.Seed(time.Now().UnixNano())

	hecURL := getEnvOrFail("SPLUNK_HEC_URL")
	hecToken := getEnvOrFail("SPLUNK_HEC_TOKEN")

	// For now we hardcode these just like the Python script.
	index := "cloud_security"
	sourcetype := "json"

	client := buildClient()

	numEvents := 20
	fmt.Printf("Sending %d fake IAM events from Go to Splunk...\n", numEvents)

	for i := 0; i < numEvents; i++ {
		ev := generateFakeIAMEvent()
		fmt.Printf("[%d/%d] %s by %s -> %s (sev=%s)\n",
			i+1, numEvents, ev.Action, ev.Actor, ev.Target, ev.Severity)

		if err := sendEvent(client, hecURL, hecToken, index, sourcetype, ev); err != nil {
			fmt.Println("Error sending event:", err)
		}

		time.Sleep(200 * time.Millisecond)
	}
}
