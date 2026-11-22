package app

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"protectedauth/internal/auth"
	"protectedauth/internal/password"
	"protectedauth/internal/storage/sqlite"
)

func TestUnsupportedArgumentsDoNotOpenDatabase(t *testing.T) {
	t.Chdir(t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, args := range [][]string{
		{"-port", "8081"},
		{"-data", "other.sqlite3"},
		{"serve"},
		{"init"},
		{"unlock", "-username", "admin"},
	} {
		if err := Run(ctx, args, io.Discard); err == nil {
			t.Fatalf("unsupported arguments accepted: %v", args)
		}

		entries, err := os.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}

		if len(entries) != 0 {
			t.Fatalf("unsupported arguments created files: %v", args)
		}
	}
}

func TestDefaultAccountUses1234AndIgnoresEnvironment(t *testing.T) {
	t.Setenv("AUTH_PASSWORD", "different-password")
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "auth.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	service := auth.NewService(store, store, password.Argon2id{})
	if err := ensureDefaultUser(context.Background(), service); err != nil {
		t.Fatal(err)
	}

	result, err := service.Authenticate(context.Background(), "admin", "1234")
	if err != nil || result != auth.Success {
		t.Fatal("hardcoded credentials do not work", result, err)
	}
}

func TestRepeatedStartupDoesNotResetLockout(t *testing.T) {
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "auth.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	service := auth.NewService(store, store, password.Argon2id{})
	if err := ensureDefaultUser(context.Background(), service); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		if _, err := service.Authenticate(context.Background(), "admin", "wrong"); err != nil {
			t.Fatal(err)
		}
	}

	if err := ensureDefaultUser(context.Background(), service); err != nil {
		t.Fatal(err)
	}

	result, err := service.Authenticate(context.Background(), "admin", "1234")
	if err != nil || result != auth.AccountLocked {
		t.Fatal("startup removed account lockout", result, err)
	}

}

func TestUnlockCommandStillWorks(t *testing.T) {
	t.Chdir(t.TempDir())
	path := "data/auth.sqlite3"
	store, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	service := auth.NewService(store, store, password.Argon2id{})
	if err := ensureDefaultUser(context.Background(), service); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		if _, err := service.Authenticate(context.Background(), "admin", "wrong"); err != nil {
			t.Fatal(err)
		}
	}

	if err := Run(context.Background(), []string{"unlock"}, io.Discard); err != nil {
		t.Fatal(err)
	}

	result, err := service.Authenticate(context.Background(), "admin", "1234")
	if err != nil || result != auth.Success {
		t.Fatal(result, err)
	}
}
