package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RFC 6238's test vector (SHA-1, the ASCII secret "12345678901234567890").
func TestTOTPCode(t *testing.T) {
	key := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		if got := totpCode(key, unix/30); got != want {
			t.Errorf("%d: %s, want %s", unix, got, want)
		}
	}
}

func codeAt(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	key, err := b32.DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return totpCode(key, now.Unix()/totpStep)
}

func TestTwoFactor(t *testing.T) {
	s, dir, token := newOwner(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }

	if _, _, err := s.StartTwoFactor(ctx, "ip", token, "wrong password", "Blockheads"); err == nil {
		t.Error("started without the password")
	}
	secret, link, err := s.StartTwoFactor(ctx, "ip", token, "long enough pw", "Blockheads")
	if err != nil || len(secret) != 32 || !strings.HasPrefix(link, "otpauth://totp/Blockheads:Scott?") || !strings.Contains(link, "secret="+secret) {
		t.Fatalf("start: %q %q %v", secret, link, err)
	}
	if on, _ := s.TwoFactorStatus("Scott"); on {
		t.Error("on before it was confirmed")
	}
	if _, err := s.ConfirmTwoFactor("ip", token, "000000"); !errors.Is(err, ErrBadTwoCode) {
		t.Errorf("wrong first code: %v", err)
	}
	codes, err := s.ConfirmTwoFactor("ip", token, codeAt(t, secret, now))
	if err != nil || len(codes) != 10 || len(codes[0]) != 11 {
		t.Fatalf("confirm: %v %v", codes, err)
	}
	if on, left := s.TwoFactorStatus("Scott"); !on || left != 10 {
		t.Errorf("status: %v %d", on, left)
	}
	// It can't be moved to another phone without turning it off first.
	if _, _, err := s.StartTwoFactor(ctx, "ip", token, "long enough pw", "Blockheads"); err == nil {
		t.Error("started again while on")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "accounts.json"))
	if strings.Contains(string(b), codes[0]) {
		t.Error("recovery codes are saved as they are")
	}

	// The password alone isn't enough now.
	_, err = s.Login(ctx, "ip", "Scott", "long enough pw")
	var need *NeedCodeError
	if !errors.As(err, &need) || need.Challenge == "" {
		t.Fatalf("login: %v", err)
	}
	// The code used to turn it on can't be used again.
	if _, err := s.LoginCode(ctx, "ip", need.Challenge, codeAt(t, secret, now)); !errors.Is(err, ErrUsedCode) {
		t.Errorf("same code twice: %v", err)
	}
	if n := len(s.twoFails["scott"]); n != 0 {
		t.Errorf("a used code counted as a wrong guess (%d)", n)
	}
	now = now.Add(30 * time.Second)
	tok, err := s.LoginCode(ctx, "ip", need.Challenge, codeAt(t, secret, now))
	if err != nil || s.Check(tok) != "Scott" {
		t.Fatalf("code: %v", err)
	}
	// A challenge works once, and not for long.
	if _, err := s.LoginCode(ctx, "ip", need.Challenge, codeAt(t, secret, now.Add(30*time.Second))); err == nil {
		t.Error("challenge used twice")
	}
	_, err = s.Login(ctx, "ip", "Scott", "long enough pw")
	errors.As(err, &need)
	now = now.Add(6 * time.Minute)
	if _, err := s.LoginCode(ctx, "ip", need.Challenge, codeAt(t, secret, now)); err == nil {
		t.Error("an old challenge worked")
	}
	// A clock a step off is fine.
	_, err = s.Login(ctx, "ip", "Scott", "long enough pw")
	errors.As(err, &need)
	if _, err := s.LoginCode(ctx, "ip", need.Challenge, codeAt(t, secret, now.Add(-30*time.Second))); err != nil {
		t.Errorf("a step behind: %v", err)
	}

	// A recovery code works once.
	now = now.Add(time.Minute)
	_, err = s.Login(ctx, "ip", "Scott", "long enough pw")
	errors.As(err, &need)
	if _, err := s.LoginCode(ctx, "ip", need.Challenge, " "+strings.ToUpper(codes[3])+" "); err != nil {
		t.Errorf("recovery: %v", err)
	}
	if _, left := s.TwoFactorStatus("Scott"); left != 9 {
		t.Errorf("left %d", left)
	}
	_, err = s.Login(ctx, "ip", "Scott", "long enough pw")
	errors.As(err, &need)
	if _, err := s.LoginCode(ctx, "ip", need.Challenge, codes[3]); err == nil {
		t.Error("recovery code used twice")
	}

	// New recovery codes and turning it off need the password.
	tok2, _ := s.LoginCode(ctx, "ip2", need.Challenge, codes[4])
	if _, err := s.NewRecoveryCodes(ctx, "ip2", tok2, "wrong password"); err == nil {
		t.Error("new codes without the password")
	}
	fresh, err := s.NewRecoveryCodes(ctx, "ip2", tok2, "long enough pw")
	if err != nil || len(fresh) != 10 || fresh[0] == codes[0] {
		t.Fatalf("new codes: %v", err)
	}
	if err := s.DisableTwoFactor(ctx, "ip2", tok2, "nope nope nope"); err == nil {
		t.Error("turned off without the password")
	}
	if err := s.DisableTwoFactor(ctx, "ip2", tok2, "long enough pw"); err != nil {
		t.Fatal(err)
	}
	if tok, err := s.Login(ctx, "ip3", "Scott", "long enough pw"); err != nil || tok == "" {
		t.Errorf("login after turning it off: %v", err)
	}
	// Loaded again from the file.
	s2, _ := Open(dir, "")
	if on, _ := s2.TwoFactorStatus("Scott"); on {
		t.Error("still on after reload")
	}
}

// Guessing codes is limited per account, even with the right password from
// many addresses, and a password reset (which needs the server) turns it
// off.
func TestTwoFactorGuessingAndReset(t *testing.T) {
	s, dir, token := newOwner(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	secret, _, _ := s.StartTwoFactor(ctx, "ip", token, "long enough pw", "Blockheads")
	if _, err := s.ConfirmTwoFactor("ip", token, codeAt(t, secret, now)); err != nil {
		t.Fatal(err)
	}
	wrong := "123456"
	if wrong == codeAt(t, secret, now) {
		wrong = "654321"
	}
	for i := 0; i < twoFailLimit; i++ {
		ip := "10.0.0." + string(rune('a'+i))
		_, err := s.Login(ctx, ip, "Scott", "long enough pw")
		var need *NeedCodeError
		if !errors.As(err, &need) {
			t.Fatalf("try %d: %v", i, err)
		}
		if _, err := s.LoginCode(ctx, ip, need.Challenge, wrong); err == nil {
			t.Fatal("a wrong code worked")
		}
	}
	var locked *LockedError
	if _, err := s.Login(ctx, "10.9.9.9", "Scott", "long enough pw"); !errors.As(err, &locked) {
		t.Errorf("not locked after %d wrong codes: %v", twoFailLimit, err)
	}
	now = now.Add(twoFailWindow + time.Second)
	var need *NeedCodeError
	if _, err := s.Login(ctx, "10.9.9.9", "Scott", "long enough pw"); !errors.As(err, &need) {
		t.Errorf("still locked later: %v", err)
	}

	// A reset code turns it off.
	s.mu.Lock()
	s.now = time.Now // the code's age is checked against the clock
	s.mu.Unlock()
	code, err := WriteResetCode(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reset(ctx, "ip", code, "a new long password"); err != nil {
		t.Fatal(err)
	}
	if on, _ := s.TwoFactorStatus("Scott"); on {
		t.Error("still on after a reset")
	}
}

func TestResetUserTwoFactor(t *testing.T) {
	s, _, _ := newOwner(t)
	ctx := context.Background()
	if err := s.CreateUser(ctx, "Ava", "ava password 1", false); err != nil {
		t.Fatal(err)
	}
	tok, err := s.Login(ctx, "ip", "Ava", "ava password 1")
	if err != nil {
		t.Fatal(err)
	}
	secret, _, _ := s.StartTwoFactor(ctx, "ip", tok, "ava password 1", "Blockheads")
	if _, err := s.ConfirmTwoFactor("ip", tok, codeAt(t, secret, time.Now())); err != nil {
		t.Fatal(err)
	}
	if u := s.Users(); len(u) != 1 || !u[0].TwoFactor {
		t.Errorf("users: %+v", u)
	}
	if err := s.ResetUserTwoFactor("ava"); err != nil {
		t.Fatal(err)
	}
	if s.Check(tok) != "" {
		t.Error("still signed in after the reset")
	}
	if tok, err := s.Login(ctx, "ip", "Ava", "ava password 1"); err != nil || tok == "" {
		t.Errorf("login: %v", err)
	}
	if err := s.ResetUserTwoFactor("Scott"); err == nil {
		t.Error("the owner's two-factor reset from the People page")
	}
}
