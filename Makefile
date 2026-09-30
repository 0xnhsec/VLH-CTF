# =============================================================================
# VLH-CTF — Makefile
# Base image must be built before any DSLTV profile:  make base
# Compose file is generated (never hand-edited):       make compose
# =============================================================================
BASE_IMAGE := vlh-dsltv-base:1.0.0
VERSION    := 1.0.0

.PHONY: base tui compose up-full up-m1 up-m2 up-m3 up-m4 up-m5 down qa clean zip help

help:
	@echo "VLH-CTF targets:"
	@echo "  base        build the shared DSLTV base image ($(BASE_IMAGE))"
	@echo "  tui         build bin/vlh-tui (go mod tidy + go build)"
	@echo "  compose     regenerate docker-compose.yml from the manifests"
	@echo "  up-full     ASLV full-chain mode   (profile full, :18024)"
	@echo "  up-m1..m5   ASLV standalone modes  (:18021 :18022 :18023 :18025 :18026)"
	@echo "  up-<other>  any other profile, e.g. up-dsltv-jwt-none-alg (:8119)"
	@echo "  down        stop everything (keep volumes)"
	@echo "  clean       stop everything AND remove volumes (flags regenerate)"
	@echo "  qa          run the solver suite (node qa/run-all.mjs)"
	@echo "  zip         package dist/vlh-ctf-$(VERSION).zip"

# --- shared DSLTV base image (required before any dsltv-* profile) -----------
base:
	docker build -t $(BASE_IMAGE) ./dsltv/base

# --- TUI ----------------------------------------------------------------------
tui:
	cd tui && go mod tidy && go build -o ../bin/vlh-tui .

# --- compose regeneration ------------------------------------------------------
compose:
	cd tools && npm install && node gen-compose.mjs

# --- ASLV modes ----------------------------------------------------------------
up-full:
	docker compose --profile full up -d --build

up-m1:
	docker compose --profile m1 up -d --build

up-m2:
	docker compose --profile m2 up -d --build

up-m3:
	docker compose --profile m3 up -d --build

up-m4:
	docker compose --profile m4 up -d --build

up-m5:
	docker compose --profile m5 up -d --build

# --- generic profile selector (e.g. up-dsltv-jwt-none-alg, up-dsltv-csrf-missing-token)
#     explicit targets above win over this pattern rule. Remember `make base`
#     first for any dsltv-* profile.
up-%:
	docker compose --profile $* up -d --build

# --- teardown --------------------------------------------------------------------
down:
	docker compose down

clean:
	docker compose down -v

# --- QA + packaging -----------------------------------------------------------------
qa:
	node qa/run-all.mjs

zip:
	mkdir -p dist
	zip -r dist/vlh-ctf-$(VERSION).zip . -x ".git/*" "node_modules/*" "**/node_modules/*" "dist/*"
