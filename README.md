# Social Growth Automation (n8n Workflows)

This repository is dedicated to **growing on social media with automation** — practical n8n workflows you can import and run in minutes.

## What you’ll find here
A collection of **ready-to-use n8n workflows** focused on:
- content distribution & scheduling
- repurposing posts across platforms
- engagement & community ops
- tracking performance and iterating faster

## First drop: “Post on X”
The first workflow shared here is **Post on X** — a simple automation to publish content on X (Twitter) from n8n.
- Google sheet will come soon

### Notes
- **Credentials are not included.** You’ll need to create your own credentials inside n8n.
- Check the workflow nodes for any required **environment variables / placeholders** (API keys, tokens, webhooks, etc.).
- Releases are versioned (v1.0.0, v1.1.0…) so you can always download the latest stable file.

## How to import
- Download the workflow JSON from **GitHub Releases**
- In n8n: **Workflows → Import**
- Open the imported workflow and configure your credentials

## Download the workflows JSON

### Post on X
[⬇️ Download "Post on X" workflow JSON](https://raw.githubusercontent.com/Rufus94us/Growth-in-Public/refs/heads/main/N8N/Post%20on%20X/Post%20on%20X.json)
[⬇️ Download Google Sheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vQFBYuR88v2Rf3s0ivdGau1QZo0nWT41ZdyfCoqKSTSafLcCZXN6ywUT-Kj4ty-H2pF9jqEfN5YSsgg/pub?output=xlsx)

---

### Get content from X - Free X API
Retrieve tweets from any X user using the **free tier X API** (100 requests/month). Includes support for images and videos extraction.

**Features:**
- 🔍 Get user ID from username
- 📝 Retrieve user's original tweets (excludes retweets & replies)
- 🖼️ Extract images and videos from tweets
- 📊 Save to Google Sheets automatically

[⬇️ Download "Get content from X - Free X API" workflow JSON](https://raw.githubusercontent.com/Rufus94us/Growth-in-Public/refs/heads/main/N8N/Get%20content%20from%20X/Get%20content%20from%20X%20-%20Free%20X%20API.json)
[⬇️ Download Google Sheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vQFBYuR88v2Rf3s0ivdGau1QZo0nWT41ZdyfCoqKSTSafLcCZXN6ywUT-Kj4ty-H2pF9jqEfN5YSsgg/pub?output=xlsx)

### Get content from X - APIFY
Retrieve tweets from any X user using **APIFY** (Twitter Scraper). Ideal if you need more volume than the free X API tier.

**Features:**
- 🕵️‍♂️ Scrape tweets via Apify (bypass standard API limits)
- 📝 Retrieve user's original tweets (excludes retweets & replies)
- 🖼️ Extract images, videos, and detailed metadata
- 📊 Save to Google Sheets automatically

[⬇️ Download "Get content from X - APIFY" workflow JSON](https://raw.githubusercontent.com/Rufus94us/Growth-in-Public/refs/heads/main/N8N/Get%20content%20from%20X/Get%20content%20from%20X%20-%20APIFY.json)
[⬇️ Download Google Sheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vQFBYuR88v2Rf3s0ivdGau1QZo0nWT41ZdyfCoqKSTSafLcCZXN6ywUT-Kj4ty-H2pF9jqEfN5YSsgg/pub?output=xlsx)

### Post on X - Threads from Reddit Post
Turn viral Reddit posts into engaging Twitter threads automatically using AI.

**Features:**
- 🤖 Generate engaging threads using AI (LLMs)
- 🎯 Auto-select best posts (upvotes & comments)
- 🔄 Prevent duplicates with Google Sheets check
- 🧵 Publish threads directly to X
- 📊 Update in google sheet the post as used

[⬇️ Download "Post on X - Threads from Reddit Post" workflow JSON](https://raw.githubusercontent.com/Rufus94us/Growth-in-Public/refs/heads/main/N8N/Thread%20on%20X/Post%20on%20X%20-%20Threads%20from%20reddit%20post.json)
[⬇️ Download Google Sheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vQFBYuR88v2Rf3s0ivdGau1QZo0nWT41ZdyfCoqKSTSafLcCZXN6ywUT-Kj4ty-H2pF9jqEfN5YSsgg/pub?output=xlsx)

---

Like and follow on X @RugSlay3r, DMs if you need any help, See u
