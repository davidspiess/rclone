//go:build !plan9 && !solaris

package iclouddrive_test

import (
	"context"
	"testing"

	"github.com/rclone/rclone/backend/iclouddrive"
	"github.com/rclone/rclone/backend/iclouddrive/api"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configfile"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fstest/fstests"
)

// TestIntegration runs integration tests against the remote
func TestIntegration(t *testing.T) {
	fstests.Run(t, &fstests.Opt{
		RemoteName: "TestICloudDrive:",
		NilObject:  (*iclouddrive.Object)(nil),
	})
}

func TestConfigSignIn(t *testing.T) {
	const remoteName = "TestICloudDrive"

	configfile.Install()

	appleID := config.GetValue(remoteName, "apple_id")
	password := config.GetValue(remoteName, "password")
	if revealedPassword, err := obscure.Reveal(password); err == nil {
		password = revealedPassword
	}

	ctx := context.Background()
	icloud, err := api.New(appleID, password, "", "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d", nil, nil)
	if err != nil {
		t.Fatalf("failed to create icloud client: %v", err)
	}
	if err := icloud.SignIn(ctx); err != nil {
		t.Fatalf("failed to sign in: %v", err)
	}
}
