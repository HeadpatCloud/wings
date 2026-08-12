package router

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/pterodactyl/wings/config"
	"github.com/pterodactyl/wings/router/tokens"
	wserver "github.com/pterodactyl/wings/server"
)

func newDownloadBackupRequest(t *testing.T, token string, rangeHeader string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/download/backup?token="+token, nil)
	if rangeHeader != "" {
		c.Request.Header.Set("Range", rangeHeader)
	}
	return c, w
}

// Downloads are deliberately not one-time: a resumed or segmented transfer
// re-sends the same token, and rejecting the second request is what made
// multi-GB archives impossible to pull down.
func TestGetDownloadBackupAcceptsRepeatedAndRangedRequests(t *testing.T) {
	backupDir := t.TempDir()
	config.Set(&config.Configuration{
		AuthenticationToken: "test-token",
		System:              config.SystemConfiguration{BackupDirectory: backupDir},
	})

	backupID := uuid.New().String()
	body := strings.Repeat("headpat", 1000)
	if err := os.WriteFile(filepath.Join(backupDir, backupID+".tar.gz"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	client := backupTestRemoteClient{}
	s, err := wserver.New(client)
	if err != nil {
		t.Fatal(err)
	}
	s.Config().Uuid = "server"
	manager := wserver.NewEmptyManager(client)
	manager.Add(s)

	// iat and user_uuid are both mandatory: isDenylisted treats a token missing
	// either as revoked, which surfaces as a bare 404. iat is nudged forward
	// because it serialises truncated to the second and would otherwise land
	// before this process booted.
	payload := tokens.BackupPayload{
		Payload: jwt.Payload{
			IssuedAt:       jwt.NumericDate(time.Now().Add(2 * time.Second)),
			ExpirationTime: jwt.NumericDate(time.Now().Add(time.Hour)),
		},
		Scoped:     tokens.Scoped{Scope: string(tokens.BackupDownload)},
		ServerUuid: "server",
		UserUuid:   uuid.New().String(),
		BackupUuid: backupID,
		UniqueId:   uuid.New().String(),
	}
	signed, err := jwt.Sign(payload, config.GetJwtAlgorithm())
	if err != nil {
		t.Fatal(err)
	}
	token := string(signed)

	for attempt := 1; attempt <= 2; attempt++ {
		c, w := newDownloadBackupRequest(t, token, "")
		c.Set("manager", manager)
		c.Set("api_client", client)

		getDownloadBackup(c)

		if w.Code != http.StatusOK {
			t.Fatalf("attempt %d: got status %d, want 200 - the one-time token check is back", attempt, w.Code)
		}
		if w.Body.Len() != len(body) {
			t.Fatalf("attempt %d: got %d bytes, want %d", attempt, w.Body.Len(), len(body))
		}
		if got := w.Header().Get("Accept-Ranges"); got != "bytes" {
			t.Fatalf("attempt %d: Accept-Ranges is %q, want bytes", attempt, got)
		}
	}

	c, w := newDownloadBackupRequest(t, token, "bytes=100-199")
	c.Set("manager", manager)
	c.Set("api_client", client)

	getDownloadBackup(c)

	if w.Code != http.StatusPartialContent {
		t.Fatalf("ranged request got status %d, want 206 - downloads cannot resume", w.Code)
	}
	if w.Body.Len() != 100 {
		t.Fatalf("ranged request returned %d bytes, want 100", w.Body.Len())
	}
	if got := w.Header().Get("Content-Range"); got != "bytes 100-199/7000" {
		t.Fatalf("Content-Range is %q", got)
	}
}
