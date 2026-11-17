package olm

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"testing"
)

func encodeForTest(t *testing.T, plain string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(plain)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestDecodeDNSBlocklist(t *testing.T) {
	bl, err := decodeDNSBlocklist(encodeForTest(t, "ads.example.com\ntracker.net\n"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bl.Len() != 2 || !bl.Blocked("x.ads.example.com") || !bl.Blocked("tracker.net") {
		t.Errorf("unexpected blocklist (len %d)", bl.Len())
	}

	bl, err = decodeDNSBlocklist("")
	if err != nil || bl != nil {
		t.Errorf("empty payload must clear the list, got %v, %v", bl, err)
	}

	if _, err := decodeDNSBlocklist("not base64 !!"); err == nil {
		t.Error("expected an error for a corrupt payload")
	}
}
