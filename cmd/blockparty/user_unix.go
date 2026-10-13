//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// dropRoot runs the panel as an ordinary user. The image starts as root
// only so it can fix the owner of a brand-new data folder: Docker creates a
// missing host folder owned by root, which the panel's user (Unraid's
// nobody:users, 99:100, or PUID and PGID) couldn't write to. Then it
// switches to that user and starts itself again, so the binary's file
// capability (binding port 53) applies to the ordinary user. The same
// happens for "docker exec ... reset-password", so the files it writes
// belong to the panel's user too.
//
// It does nothing when the container already runs as another user (docker
// run --user), or with RUN_AS_ROOT=true.
func dropRoot() {
	if os.Getuid() != 0 || envBool("RUN_AS_ROOT", false) {
		return
	}
	uid, err := envInt("PUID", 99)
	if err != nil {
		fail(err)
	}
	gid, err := envInt("PGID", 100)
	if err != nil {
		fail(err)
	}
	dirs := []string{envOr("DATA_DIR", "/data"), filepath.Dir(envOr("SERVERS_FILE", "/config/servers.json"))}
	for _, d := range dirs {
		// Lstat, and only real folders: a link is never followed as root.
		st, err := os.Lstat(d)
		if err != nil || !st.IsDir() {
			continue
		}
		// Only a folder owned by root is taken over: one that already
		// belongs to someone else is left as it is.
		if s, ok := st.Sys().(*syscall.Stat_t); ok && s.Uid == 0 {
			if err := os.Lchown(d, uid, gid); err != nil {
				fmt.Fprintf(os.Stderr, "couldn't give %s to user %d:%d: %v\n", d, uid, gid, err)
			}
		}
		warnRootOwned(d, uid, gid)
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		fail(fmt.Errorf("setgroups: %w", err))
	}
	if err := syscall.Setgid(gid); err != nil {
		fail(fmt.Errorf("setgid %d: %w", gid, err))
	}
	if err := syscall.Setuid(uid); err != nil {
		fail(fmt.Errorf("setuid %d: %w", uid, err))
	}
	exe, err := os.Executable()
	if err != nil {
		fail(err)
	}
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		fail(fmt.Errorf("starting %s as user %d:%d: %w", exe, uid, gid, err))
	}
}

// warnRootOwned says so when files at the top of a folder belong to root
// (copied in as root, say): the panel's user can't change them.
func warnRootOwned(dir string, uid, gid int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if s, ok := info.Sys().(*syscall.Stat_t); ok && s.Uid == 0 {
			fmt.Fprintf(os.Stderr, "warning: %s belongs to root, so the panel (user %d:%d) may not be able to change it; fix it with: chown -R %d:%d <that folder on the host>\n",
				filepath.Join(dir, e.Name()), uid, gid, uid, gid)
			return
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "setup problem:", err)
	os.Exit(2)
}
