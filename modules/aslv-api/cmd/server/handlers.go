// VLH-CTF — ASLV M4 aslv-api: HTTP handlers (BOLA/BFLA/BOPLA + mass
// assignment + shadow version + stage-gated flags). See main.go for the map.
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

/* ------------------------------------------------------------------ identity */

type identity struct {
	Authed     bool
	ViaSession bool
	ViaJWT     bool
	Username   string // session: username; jwt: sub claim
	UUID       string
	Role       string // session: users.role; jwt: role claim (trusted blindly — the trust edge)
	Local      *userRow
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// resolveIdentity: session cookie OR Bearer JWT (signature-only validation,
// any sub/role claims trusted — deliberately loose, arch §5.2 M5→M4).
func resolveIdentity(r *http.Request) identity {
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(authz, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
		if claims, err := verifyJWT(token); err == nil {
			id := identity{Authed: true, ViaJWT: true}
			if s, ok := claims["sub"].(string); ok {
				id.Username = s
				id.UUID = s
			}
			if s, ok := claims["role"].(string); ok {
				id.Role = s
			}
			if id.Username != "" {
				if u := userByRef(id.Username); u != nil {
					id.Local = u
				}
			}
			return id
		}
	}
	if sid := cookieValue(r, "sid"); sid != "" {
		if u := sessionUser(sid); u != nil {
			return identity{
				Authed:     true,
				ViaSession: true,
				Username:   u.Username,
				UUID:       u.UUID,
				Role:       u.Role,
				Local:      u,
			}
		}
	}
	return identity{}
}

func requireAuth(w http.ResponseWriter, r *http.Request) (identity, bool) {
	id := resolveIdentity(r)
	if !id.Authed {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required (session cookie or Bearer JWT)"})
		return id, false
	}
	return id, true
}

func ownerOf(id identity, target *userRow) bool {
	if target == nil {
		return false
	}
	if id.ViaSession {
		return id.Local != nil && id.Local.ID == target.ID
	}
	if id.ViaJWT {
		return id.Username == target.UUID || id.Username == target.Username
	}
	return false
}

/* --------------------------------------------------------------- basic routes */

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "aslv-api"})
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "aslv-api",
		"scheme":  "aslv.lab/user/v1/{user}/… (arch §7.2)",
		"see":     []string{"/user/v1/login", "/user/v1/list", "/user/v1/{user}/profile", "/user/v1/{user}/orders/{id}", "/admin/v1/restart", "/admin/v1/panel", "/v1/user/{user}/profile?export=full"},
	})
}

func readJSONBody(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

/* ---------------------------------------------------------------------- login */

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body {username,password}"})
		return
	}
	u := userByRef(in.Username)
	if u == nil || u.Password != sha256Hex(in.Password) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	sid, err := createSession(u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "session create failed"})
		return
	}
	// SameSite=None keeps the M2↔M4 CORS edge genuinely exploitable cross-site.
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": u.Username, "uuid": u.UUID, "role": u.Role})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if sid := cookieValue(r, "sid"); sid != "" {
		_, _ = db.Exec("DELETE FROM sessions WHERE sid = ?", sid)
	}
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

/* ------------------------------------------------------ directory (mild enumeration) */

func handleList(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAuth(w, r); !ok {
		return
	}
	rows, err := db.Query("SELECT username, uuid, role, tenant FROM users ORDER BY id")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var username, uuid, role, tenant string
		if err := rows.Scan(&username, &uuid, &role, &tenant); err != nil {
			continue
		}
		out = append(out, map[string]any{"username": username, "uuid": uuid, "role": role, "tenant": tenant})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out, "count": len(out)})
}

/* ---------------------------------------------------- profile (excessive data exposure / BOPLA) */

func profileJSON(target *userRow, owner bool) map[string]any {
	out := map[string]any{
		"username":   target.Username,
		"uuid":       target.UUID,
		"email":      target.Email,
		"tenant":     target.Tenant,
		"role":       target.Role,
		"created_at": target.CreatedAt,
	}
	var full, bio, phone string
	_ = db.QueryRow("SELECT full_name, bio, phone FROM profiles WHERE user_id = ?", target.ID).Scan(&full, &bio, &phone)
	out["full_name"] = full
	out["bio"] = bio
	out["phone"] = phone
	if owner {
		// Full data (incl. the session-bound api_key) is only for the owner —
		// the intended exposure is uuid+email+tenant for EVERYONE else.
		out["api_key"] = target.APIKey
		out["original_role"] = target.OriginalRole
		if target.Role == "admin" && target.OriginalRole != "admin" {
			// Stage 1 gate: own profile shows flag1 only AFTER self-escalation
			// via mass assignment (role changed from the seeded original).
			earnFlag("stage1", flagStage1)
			out["flag1"] = flagStage1
		}
	}
	return out
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := requireAuth(w, r)
	if !ok {
		return
	}
	target := userByRef(r.PathValue("user"))
	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such user"})
		return
	}
	writeJSON(w, http.StatusOK, profileJSON(target, ownerOf(id, target)))
}

/* --------------------------------------------------------------- orders (BOLA) */

func handleOrders(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAuth(w, r); !ok {
		return
	}
	target := userByRef(r.PathValue("user"))
	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such user"})
		return
	}
	rows, err := db.Query("SELECT id, note, total_cents, created_at FROM orders WHERE user_id = ? ORDER BY id", target.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var note string
		var cents int64
		var created string
		if err := rows.Scan(&id, &note, &cents, &created); err != nil {
			continue
		}
		out = append(out, map[string]any{"id": id, "note": note, "total_cents": cents, "created_at": created})
	}
	writeJSON(w, http.StatusOK, map[string]any{"orders": out, "user": target.Username})
}

func handleOrder(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAuth(w, r); !ok {
		return
	}
	// BOLA: the order is resolved purely by {id}; NO ownership check ties it
	// to the {user} segment of the path (or to the caller).
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "order id must be numeric"})
		return
	}
	var userID int64
	var note, secret, created string
	var cents int64
	err = db.QueryRow("SELECT user_id, note, secret_note, total_cents, created_at FROM orders WHERE id = ?", id).
		Scan(&userID, &note, &secret, &cents, &created)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such order"})
		return
	}
	owner := userByID(userID)
	ownerName := ""
	if owner != nil {
		ownerName = owner.Username
	}
	out := map[string]any{
		"id":         id,
		"user":       ownerName,
		"note":       note,
		"total_cents": cents,
		"created_at": created,
	}
	if secret != "" {
		out["secret_note"] = secret
	}
	writeJSON(w, http.StatusOK, out)
}

/* ------------------------------------------------- admin restart (BFLA: no role check) */

func handleRestart(w http.ResponseWriter, r *http.Request) {
	id, ok := requireAuth(w, r)
	if !ok {
		return
	}
	// BFLA: ANY authenticated user may invoke the privileged function —
	// the endpoint never checks id.Role == "admin".
	writeJSON(w, http.StatusOK, map[string]any{
		"restarted": true,
		"called_by": id.Username,
		"hint":      "admin functions are not role-checked here. The /admin/v1/panel endpoint DOES verify the server-side role claim — see what PATCH /user/v1/{user} accepts.",
	})
}

/* ------------------------------------- PATCH /user/v1/{user} (mass assignment) */

func handlePatch(w http.ResponseWriter, r *http.Request) {
	id, ok := requireAuth(w, r)
	if !ok {
		return
	}
	if !id.ViaSession {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "PATCH requires a session (JWT identities cannot modify profiles)"})
		return
	}
	target := userByRef(r.PathValue("user"))
	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such user"})
		return
	}
	// Ownership IS checked for PATCH (self-service profile update) — the bug
	// is not BOLA here, it is the bindable `role` field below.
	if id.Local == nil || id.Local.ID != target.ID {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "you may only PATCH your own profile"})
		return
	}
	var in map[string]any
	if err := readJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return
	}
	// Mass assignment: the update whitelist includes `role`…
	if role, ok := in["role"].(string); ok && role != "" {
		if _, err := db.Exec("UPDATE users SET role = ? WHERE id = ?", role, target.ID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "update failed"})
			return
		}
	}
	if email, ok := in["email"].(string); ok && email != "" {
		_, _ = db.Exec("UPDATE users SET email = ? WHERE id = ?", email, target.ID)
	}
	if v, ok := in["full_name"].(string); ok {
		_, _ = db.Exec("UPDATE profiles SET full_name = ? WHERE user_id = ?", v, target.ID)
	}
	if v, ok := in["bio"].(string); ok {
		_, _ = db.Exec("UPDATE profiles SET bio = ? WHERE user_id = ?", v, target.ID)
	}
	if v, ok := in["phone"].(string); ok {
		_, _ = db.Exec("UPDATE profiles SET phone = ? WHERE user_id = ?", v, target.ID)
	}
	updated := userByID(target.ID)
	writeJSON(w, http.StatusOK, profileJSON(updated, true))
}

/* ------------------------------------------- admin panel (stage 2: role claim check) */

func handlePanel(w http.ResponseWriter, r *http.Request) {
	id, ok := requireAuth(w, r)
	if !ok {
		return
	}
	// Stage 2: the panel DOES verify the role — but "server-side role" for a
	// JWT identity is the (blindly trusted) role claim, and for a session it
	// is users.role (writable via the mass-assignment PATCH above).
	if id.Role != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "admin role required", "your_role": id.Role})
		return
	}
	earnFlag("stage2", flagStage2)
	var users, orders int
	_ = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&users)
	_ = db.QueryRow("SELECT COUNT(*) FROM orders").Scan(&orders)
	writeJSON(w, http.StatusOK, map[string]any{
		"flag2":     flagStage2,
		"flag":      flagStage2,
		"panel":     "organization control panel",
		"stats":     map[string]int{"users": users, "orders": orders},
		"note":      "stage 2 verified: server-side role claim == admin",
		"called_by": id.Username,
	})
}

/* ------------------------- shadow version: old route (forgotten export=full) */

func handleShadowProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := requireAuth(w, r)
	if !ok {
		return
	}
	target := userByRef(r.PathValue("user"))
	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such user"})
		return
	}
	out := profileJSON(target, ownerOf(id, target))
	out["legacy_route"] = true
	out["api_version"] = "v1-legacy"
	if r.URL.Query().Get("export") == "full" {
		// The old route's "full export" still returns the api_key for the
		// innocent account — the field the new route restricted to self.
		out["export"] = "full"
		if target.Role == "innocent" || ownerOf(id, target) {
			out["api_key"] = target.APIKey
		}
	}
	writeJSON(w, http.StatusOK, out)
}

/* --------------------------------------------------------- activity export */

func handleInternalActivity(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT ts, identifier, is_authenticated, data, latency_ms FROM activity ORDER BY id DESC LIMIT 5000")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	for rows.Next() {
		var ts, identifier, data string
		var authed int
		var latency float64
		if err := rows.Scan(&ts, &identifier, &authed, &data, &latency); err != nil {
			continue
		}
		_ = enc.Encode(map[string]any{
			"ts":              ts,
			"identifier":      identifier,
			"is_authenticated": authed == 1,
			"data":            data,
			"latency_ms":      latency,
		})
	}
}
