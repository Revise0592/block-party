package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Two-factor sign-in: after the password, a 6-digit code from an
// authenticator app (TOTP, RFC 6238: SHA-1, 30-second steps), or one of ten
// one-time recovery codes. Any account can turn it on for itself; the owner
// can turn it off for someone who lost their phone, and the owner's own is
// turned off by a password reset (which needs access to the server).

// TwoFactor is an account's authenticator app setup.
type TwoFactor struct {
	Secret   string    `json:"secret"`   // base32
	LastStep int64     `json:"lastStep"` // the newest code used, so it can't be used twice
	Recovery []string  `json:"recovery"` // SHA-256 of each unused recovery code
	Since    time.Time `json:"since"`
}

const (
	totpStep       = 30
	totpDigits     = 6
	recoveryCodes  = 10
	challengeLife  = 5 * time.Minute
	challengeTries = 5
	pendingLife    = 15 * time.Minute
)

var (
	// ErrNeedCode is wrapped by NeedCodeError.
	ErrNeedCode   = errors.New("enter the code from your authenticator app")
	ErrBadTwoCode = errors.New("that code isn't right; check your phone's clock if it keeps happening")
	// ErrUsedCode is a right code that was already used (codes work once).
	ErrUsedCode  = errors.New("that code was just used; wait for the app to show the next one")
	errTwoIsOn   = errors.New("two-factor sign-in is already on; turn it off first to move it to a new phone")
	errNoPending = errors.New("start again: the setup ran out or wasn't started")
	errChallenge = errors.New("that sign-in ran out; enter your password again")
)

// NeedCodeError is returned by Login for accounts with two-factor sign-in:
// finish with LoginCode and Challenge.
type NeedCodeError struct{ Challenge string }

func (e *NeedCodeError) Error() string { return ErrNeedCode.Error() }
func (e *NeedCodeError) Unwrap() error { return ErrNeedCode }

type challenge struct {
	username string
	hash     string // the password hash it was made for
	expires  time.Time
	tries    int
}

type pendingTwo struct {
	secret  string
	expires time.Time
}

func (a *Account) cloneTwo() *TwoFactor {
	if a.Two == nil {
		return nil
	}
	t := *a.Two
	t.Recovery = append([]string(nil), a.Two.Recovery...)
	return &t
}

// totpCode is the code for a time step.
func totpCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	h := hmac.New(sha1.New, secret)
	h.Write(msg[:])
	sum := h.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, n%1000000)
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// totpMatch finds the step a code belongs to (now, or one step either side
// for clocks a little off). It returns 0 if none matches, and -1 if it
// matches a step at or before after (already used: a code works once).
func totpMatch(secret string, code string, now time.Time, after int64) int64 {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0
	}
	step := now.Unix() / totpStep
	found := int64(0)
	for _, s := range []int64{step, step - 1, step + 1} {
		if subtle.ConstantTimeCompare([]byte(totpCode(key, s)), []byte(code)) == 1 && found <= 0 {
			if s <= after {
				found = -1
			} else {
				found = s
			}
		}
	}
	return found
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// newRecoveryCodes makes recovery codes (shown once) and their hashes.
func newRecoveryCodes() ([]string, []string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no look-alikes
	var codes, hashes []string
	for i := 0; i < recoveryCodes; i++ {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		var sb strings.Builder
		for j, x := range b {
			if j == 5 {
				sb.WriteByte('-')
			}
			sb.WriteByte(alphabet[int(x)%len(alphabet)])
		}
		code := sb.String()
		codes = append(codes, code)
		hashes = append(hashes, recoveryHash(code))
	}
	return codes, hashes, nil
}

func normRecovery(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	code = strings.ReplaceAll(code, " ", "")
	code = strings.ReplaceAll(code, "-", "")
	return code
}

func recoveryHash(code string) string {
	h := sha256.Sum256([]byte(normRecovery(code)))
	return hex.EncodeToString(h[:])
}

func normDigits(code string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), " ", ""), "-", "")
}

// newChallengeLocked starts the code step of a sign-in. Caller holds s.mu.
func (s *Store) newChallengeLocked(acct *Account) (string, error) {
	tok, err := randomToken(24)
	if err != nil {
		return "", err
	}
	now := s.now()
	for k, c := range s.challenges {
		if now.After(c.expires) {
			delete(s.challenges, k)
		}
	}
	s.challenges[tokenHash(tok)] = &challenge{username: acct.Username, hash: acct.Hash, expires: now.Add(challengeLife)}
	return tok, nil
}

// LoginCode finishes a sign-in with a code from the authenticator app or a
// recovery code, and returns a session token.
func (s *Store) LoginCode(ctx context.Context, ip, challengeToken, code string) (string, error) {
	done, err := s.begin(ip)
	if err != nil {
		return "", err
	}
	outcome := tryNeutral
	defer func() { done(outcome) }() // after the unlock below: done takes s.mu
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tokenHash(challengeToken)
	c := s.challenges[key]
	if c == nil || s.now().After(c.expires) {
		delete(s.challenges, key)
		return "", errChallenge
	}
	acct := s.accountLocked(c.username)
	if acct == nil || acct.Hash != c.hash || acct.Two == nil {
		delete(s.challenges, key)
		return "", ErrChanged
	}
	if wait := s.twoLockedLocked(acct.Username); wait > 0 {
		delete(s.challenges, key)
		return "", &LockedError{Wait: wait}
	}
	changed := acct.clone()
	ok := false
	if d := normDigits(code); len(d) == totpDigits && strings.Trim(d, "0123456789") == "" {
		step := totpMatch(acct.Two.Secret, d, s.now(), acct.Two.LastStep)
		if step == -1 {
			// Signing in twice within one code's time isn't a wrong guess.
			return "", ErrUsedCode
		}
		if step > 0 {
			changed.Two.LastStep, ok = step, true
		}
	} else if h := recoveryHash(code); normRecovery(code) != "" {
		kept := changed.Two.Recovery[:0]
		for _, r := range changed.Two.Recovery {
			if !ok && subtle.ConstantTimeCompare([]byte(r), []byte(h)) == 1 {
				ok = true // used up
				continue
			}
			kept = append(kept, r)
		}
		changed.Two.Recovery = kept
	}
	if !ok {
		outcome = tryWrong
		s.noteTwoFailLocked(acct.Username)
		c.tries++
		if c.tries >= challengeTries {
			delete(s.challenges, key)
			return "", errChallenge
		}
		return "", ErrBadTwoCode
	}
	outcome = tryRight
	delete(s.challenges, key)
	delete(s.twoFails, strings.ToLower(acct.Username))
	if err := s.replaceLocked(acct, changed); err != nil {
		return "", err
	}
	return s.newSessionLocked(acct.Username)
}

// TwoFactorStatus says whether an account has two-factor sign-in, and how
// many recovery codes it has left.
func (s *Store) TwoFactorStatus(username string) (on bool, recoveryLeft int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.accountLocked(username)
	if a == nil || a.Two == nil {
		return false, 0
	}
	return true, len(a.Two.Recovery)
}

// StartTwoFactor makes a new secret for the account signed in with token
// (its password is checked again, so a browser left signed in can't tie
// the account to someone else's phone) and returns it, with the otpauth://
// link authenticator apps scan. It isn't used until ConfirmTwoFactor.
func (s *Store) StartTwoFactor(ctx context.Context, ip, token, password, issuer string) (secret, link string, err error) {
	acct, err := s.checkOwnPassword(ctx, ip, token, password)
	if err != nil {
		return "", "", err
	}
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	secret = b32.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.samePasswordLocked(acct) {
		return "", "", ErrChanged
	}
	acct = s.accountLocked(acct.Username)
	if acct.Two != nil {
		return "", "", errTwoIsOn
	}
	s.pending[strings.ToLower(acct.Username)] = &pendingTwo{secret: secret, expires: s.now().Add(pendingLife)}
	label := url.PathEscape(issuer + ":" + acct.Username)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return secret, "otpauth://totp/" + label + "?" + q.Encode(), nil
}

// ConfirmTwoFactor turns two-factor sign-in on once a code from the app
// matches the new secret. It returns the recovery codes (shown once).
// The account's other browsers are signed out.
func (s *Store) ConfirmTwoFactor(ip, token, code string) ([]string, error) {
	done, err := s.begin(ip)
	if err != nil {
		return nil, err
	}
	outcome := tryNeutral
	defer func() { done(outcome) }() // after the unlock below: done takes s.mu
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	acct := s.sessionAccountLocked(token)
	if acct == nil {
		return nil, errors.New("sign in again")
	}
	if acct.Two != nil {
		return nil, errTwoIsOn
	}
	k := strings.ToLower(acct.Username)
	p := s.pending[k]
	if p == nil || s.now().After(p.expires) {
		delete(s.pending, k)
		return nil, errNoPending
	}
	step := totpMatch(p.secret, normDigits(code), s.now(), 0)
	if step == 0 {
		outcome = tryWrong
		return nil, ErrBadTwoCode
	}
	outcome = tryRight
	changed := acct.clone()
	changed.Two = &TwoFactor{Secret: p.secret, LastStep: step, Recovery: hashes, Since: s.now().UTC()}
	if err := s.replaceLocked(acct, changed); err != nil {
		return nil, err
	}
	delete(s.pending, k)
	s.keepOnlySessionLocked(acct.Username, token)
	// It's on now, so the codes must be shown even if this save fails (the
	// other browsers would then only be signed out until a restart).
	_ = s.saveSessionsLocked()
	return codes, nil
}

// checkOwnPassword checks the password of the account signed in with token
// (for turning two-factor off or making new recovery codes).
func (s *Store) checkOwnPassword(ctx context.Context, ip, token, password string) (*Account, error) {
	done, err := s.begin(ip)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	acct := s.sessionAccountLocked(token)
	s.mu.Unlock()
	if acct == nil {
		done(tryNeutral)
		return nil, errors.New("sign in again")
	}
	ok, err := s.verify(ctx, acct.Hash, password)
	if err != nil {
		done(tryNeutral)
		return nil, err
	}
	done(result(ok))
	if !ok {
		return nil, errors.New("your password isn't right")
	}
	return acct, nil
}

// DisableTwoFactor turns two-factor sign-in off for the account signed in
// with token (its password is checked again).
func (s *Store) DisableTwoFactor(ctx context.Context, ip, token, password string) error {
	acct, err := s.checkOwnPassword(ctx, ip, token, password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.samePasswordLocked(acct) {
		return ErrChanged
	}
	acct = s.accountLocked(acct.Username)
	changed := acct.clone()
	changed.Two = nil
	return s.replaceLocked(acct, changed)
}

// NewRecoveryCodes replaces the recovery codes of the account signed in with
// token (its password is checked again).
func (s *Store) NewRecoveryCodes(ctx context.Context, ip, token, password string) ([]string, error) {
	acct, err := s.checkOwnPassword(ctx, ip, token, password)
	if err != nil {
		return nil, err
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.samePasswordLocked(acct) {
		return nil, ErrChanged
	}
	acct = s.accountLocked(acct.Username)
	if acct.Two == nil {
		return nil, errors.New("two-factor sign-in isn't on")
	}
	changed := acct.clone()
	changed.Two.Recovery = hashes
	if err := s.replaceLocked(acct, changed); err != nil {
		return nil, err
	}
	return codes, nil
}

// ResetUserTwoFactor turns two-factor sign-in off for someone else's account
// (the owner does this when they've lost their phone). They're signed out.
func (s *Store) ResetUserTwoFactor(username string) error {
	return s.changeUser(username, func(a *Account) { a.Two = nil }, true)
}

// Wrong codes are also counted per account, wherever they come from: the
// password alone (which resets the per-address count) mustn't allow
// guessing codes forever.
const (
	twoFailLimit  = 10
	twoFailWindow = 15 * time.Minute
)

func (s *Store) noteTwoFailLocked(username string) {
	k := strings.ToLower(username)
	now := s.now()
	kept := s.twoFails[k][:0]
	for _, t := range s.twoFails[k] {
		if now.Sub(t) < twoFailWindow {
			kept = append(kept, t)
		}
	}
	s.twoFails[k] = append(kept, now)
}

// twoLockedLocked returns how long an account must wait before trying
// codes again (0 if it needn't).
func (s *Store) twoLockedLocked(username string) time.Duration {
	list := s.twoFails[strings.ToLower(username)]
	now := s.now()
	recent := 0
	var newest time.Time
	for _, t := range list {
		if now.Sub(t) < twoFailWindow {
			recent++
			if t.After(newest) {
				newest = t
			}
		}
	}
	if recent < twoFailLimit {
		return 0
	}
	return twoFailWindow - now.Sub(newest)
}

// keepOnlySessionLocked signs an account out everywhere but token.
func (s *Store) keepOnlySessionLocked(username, token string) {
	keep := tokenHash(token)
	for h, x := range s.sessions {
		if h != keep && strings.EqualFold(x.Username, username) {
			delete(s.sessions, h)
		}
	}
}
